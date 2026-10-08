"""``hal_trace`` -- inspect an event log written by ``halucinator --event-log``."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from collections import Counter
from typing import List, Optional

from halucinator.trace import analyze


def _load(args: argparse.Namespace) -> List[dict]:
    lo, hi = getattr(args, "from_t", None), getattr(args, "to_t", None)
    return [e for e in analyze.load_events(args.events)
            if (lo is None or e["t"] >= lo) and (hi is None or e["t"] <= hi)]


def _cmd_map(args: argparse.Namespace) -> int:
    events = _load(args)
    if args.hide_stubs:
        events = [e for e in events if not (e.get("kind") == "intercept"
                                            and analyze.categorize(e) == analyze.STUB)]
    dot = analyze.to_dot(*analyze.build_graph(events, analyze.SymbolTable(*args.config)))
    if args.output is None or args.output.endswith(".dot"):
        with open(args.output or "/dev/stdout", "w", encoding="utf-8") as out:
            out.write(dot)
        return 0
    exe = shutil.which("dot")
    if exe is None:
        print("graphviz 'dot' not found; write a .dot file instead", file=sys.stderr)
        return 2
    subprocess.run([exe, f"-T{args.output.rsplit('.', 1)[-1]}", "-o", args.output],
                   input=dot.encode(), check=True)
    return 0


def _cmd_timeline(args: argparse.Namespace) -> int:
    prev: Optional[float] = None
    for row in analyze.crossings(_load(args), analyze.SymbolTable(*args.config)):
        if any(s in row["to"] for s in args.skip):
            continue
        if args.speed is not None and prev is not None and args.speed > 0:
            time.sleep(min((row["t"] - prev) / args.speed, args.max_gap))
        prev = row["t"]
        print(f"{row['t']:10.4f}  #{row['seq']:<6} {row['from']:<38} -> "
              f"{row['to']:<34} {row['via']}", flush=True)
    return 0


def _cmd_taint(args: argparse.Namespace) -> int:
    for row in analyze.taint_report(_load(args)):
        if not row["stored"]:
            continue  # received but never adopted into guest memory (e.g. not a handler path)
        print(f"tag #{row['tag']} {row['source']} @{row['t']:.4f}s")
        for label, hits in (("stored by", row["stored"]), ("read out by", row["sinks"])):
            by_handler: dict = {}
            for hit in hits:
                by_handler.setdefault(hit["handler"], []).append(hit)
            for handler, group in by_handler.items():
                print(f"    {label:<11} {handler} x{len(group)} ({sum(h['bytes'] for h in group)} B) "
                      f"@{group[0]['t']:.4f}-{group[-1]['t']:.4f}s")
        if not row["sinks"]:
            print("    LOST: stored in guest memory, never read out by a handler")
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    for kind, count in sorted(Counter(e.get("kind") for e in _load(args)).items()):
        print(f"{kind:<12}{count}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="hal_trace", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(name: str, func, help_: str) -> argparse.ArgumentParser:  # type: ignore[no-untyped-def]
        p = sub.add_parser(name, help=help_)
        p.add_argument("events", help="JSONL from halucinator --event-log")
        p.add_argument("-c", "--config", action="append", default=[],
                       help="YAML with a symbols: map, to name calling firmware functions")
        p.add_argument("--from-t", type=float, help="window start (s)")
        p.add_argument("--to-t", type=float, help="window end (s)")
        p.set_defaults(func=func)
        return p

    p = common("map", _cmd_map, "domain-boundary diagram (DOT, or svg/png via graphviz)")
    p.add_argument("-o", "--output")
    p.add_argument("--hide-stubs", action="store_true", help="omit nopped intercepts")
    p = common("timeline", _cmd_timeline, "ordered domain crossings; --speed replays them")
    p.add_argument("--skip", action="append", default=[], help="drop rows whose target contains this")
    p.add_argument("--speed", type=float, help="replay: 1=real time, 0.1=10x slower, 0=no delay")
    p.add_argument("--max-gap", type=float, default=2.0, help="cap a scaled pause (s)")
    common("taint", _cmd_taint, "input -> output paths (handler-boundary taint)")
    common("stats", _cmd_stats, "event counts by kind")

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:  # e.g. piped into head
        return 0


if __name__ == "__main__":
    sys.exit(main())
