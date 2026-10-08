"""hal_trace: inspect an event log written by ``halucinator --event-log``."""
import argparse
import shutil
import subprocess
import sys
import time
from typing import List, Optional

from halucinator.trace import analyze


def _load(args: argparse.Namespace) -> List[dict]:
    return [e for e in analyze.load_events(args.events)
            if (args.from_t is None or e["t"] >= args.from_t) and (args.to_t is None or e["t"] <= args.to_t)]


def _map(args: argparse.Namespace) -> int:
    events = _load(args)
    if args.hide_stubs:
        events = [e for e in events if not (e["kind"] == "intercept" and analyze.category(e) == "stub")]
    dot = analyze.to_dot(*analyze.build_graph(events, analyze.load_symbols(args.config)))
    if args.output is None or args.output.endswith(".dot"):
        with open(args.output or "/dev/stdout", "w", encoding="utf-8") as out:
            out.write(dot)
        return 0
    if shutil.which("dot") is None:
        print("graphviz 'dot' not found; write a .dot file instead", file=sys.stderr)
        return 2
    subprocess.run(["dot", f"-T{args.output.rsplit('.', 1)[-1]}", "-o", args.output],
                   input=dot.encode(), check=True)
    return 0


def _timeline(args: argparse.Namespace) -> int:
    symbols, prev = analyze.load_symbols(args.config), None
    for ev in _load(args):
        if ev["kind"] == "intercept":
            if any(s in (ev["sym"] or "") for s in args.skip):
                continue
            what = (f"[{analyze.category(ev)}] {analyze.symbol_at(symbols, ev['lr'])} -> {ev['sym']} "
                    f"({ev['cls']}.{ev['fn']}) ret={ev['ret']}")
        elif ev["kind"] in ("model_tx", "model_rx"):
            what = f"[zmq {ev['kind']}] {analyze.topic(ev)[0]} {ev['payload']}"
        else:
            what = f"[{ev['kind']}] " + " ".join(f"{k}={v}" for k, v in ev.items()
                                                  if k not in ("seq", "t", "kind"))
        if args.speed and prev is not None:
            time.sleep(min((ev["t"] - prev) / args.speed, args.max_gap))
        prev = ev["t"]
        print(f"{ev['t']:10.4f} #{ev['seq']:<6} {what}", flush=True)
    return 0


def _taint(args: argparse.Namespace) -> int:
    for row in analyze.taint_report(_load(args)):
        if not row["stored"]:
            continue
        print(f"tag #{row['tag']} {row['source']} @{row['t']:.4f}s")
        for label, hits in (("stored by", row["stored"]), ("read out by", row["sinks"])):
            for handler in dict.fromkeys(h["handler"] for h in hits):
                group = [h for h in hits if h["handler"] == handler]
                print(f"    {label:<11} {handler} x{len(group)} ({sum(h['bytes'] for h in group)}/{sum(h['of'] for h in group)} B) "
                      f"@{group[0]['t']:.4f}-{group[-1]['t']:.4f}s")
        if not row["sinks"]:
            print("    LOST: stored in guest memory, never read out by a handler")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="hal_trace", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    def command(name: str, func, help_: str) -> argparse.ArgumentParser:  # type: ignore[no-untyped-def]
        p = sub.add_parser(name, help=help_)
        p.add_argument("events", help="JSONL from halucinator --event-log")
        p.add_argument("-c", "--config", action="append", default=[],
                       help="YAML with a symbols: map, to name calling firmware functions")
        p.add_argument("--from-t", type=float, help="window start (s)")
        p.add_argument("--to-t", type=float, help="window end (s)")
        p.set_defaults(func=func)
        return p

    p = command("map", _map, "domain-boundary diagram (DOT, or svg/png via graphviz)")
    p.add_argument("-o", "--output")
    p.add_argument("--hide-stubs", action="store_true", help="omit nopped intercepts")
    p = command("timeline", _timeline, "events in order; --speed replays them with their timing")
    p.add_argument("--skip", action="append", default=[], help="hide intercepts whose symbol contains this")
    p.add_argument("--speed", type=float, help="1=real time, 0.1=10x slower (omit for no delay)")
    p.add_argument("--max-gap", type=float, default=2.0, help="cap a scaled pause (s)")
    command("taint", _taint, "input -> output paths; tags that never reach an output are LOST")

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:  # e.g. piped into head
        return 0


if __name__ == "__main__":
    sys.exit(main())
