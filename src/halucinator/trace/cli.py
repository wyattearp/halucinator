"""``hal_trace`` -- inspect an event log written by ``halucinator --event-log``."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from typing import List, Optional

from halucinator.trace import analyze


def _symbols(paths: List[str]) -> analyze.SymbolTable:
    table = analyze.SymbolTable()
    for path in paths:
        table.add_yaml(path)
    return table


def _window(events: List[dict], args: argparse.Namespace) -> List[dict]:
    lo = getattr(args, "from_t", None)
    hi = getattr(args, "to_t", None)
    return [e for e in events
            if (lo is None or e["t"] >= lo) and (hi is None or e["t"] <= hi)]


def _cmd_map(args: argparse.Namespace) -> int:
    events = _window(analyze.load_events(args.events), args)
    if args.hide_stubs:
        events = [e for e in events
                  if not (e.get("kind") == "intercept"
                          and analyze.categorize(e) == analyze.STUB)]
    graph = analyze.build_graph(events, _symbols(args.config),
                                include_links=args.value_links,
                                min_run=args.min_run)
    dot = analyze.to_dot(graph)
    if args.output is None or args.output.endswith(".dot"):
        with open(args.output or "/dev/stdout", "w", encoding="utf-8") as out:
            out.write(dot)
    else:
        exe = shutil.which("dot")
        if exe is None:
            print("graphviz 'dot' not found; write a .dot file instead", file=sys.stderr)
            return 2
        fmt = args.output.rsplit(".", 1)[-1]
        subprocess.run([exe, f"-T{fmt}", "-o", args.output], input=dot.encode(),
                       check=True)
    return 0


def _cmd_timeline(args: argparse.Namespace) -> int:
    events = analyze.load_events(args.events)
    for row in analyze.crossings(events, _symbols(args.config)):
        if args.skip and any(s in row["to"] for s in args.skip):
            continue
        extra = f" {row['hex']}" if row.get("hex") else ""
        print(f"{row['t']:10.4f}  #{row['seq']:<6} {row['from']:<38} -> "
              f"{row['to']:<34} {row['via']}{extra}")
    return 0


def _cmd_flow(args: argparse.Namespace) -> int:
    events = analyze.load_events(args.events)
    symbols = _symbols(args.config)
    by_seq = {e["seq"]: e for e in events}
    if args.from_seq is None:
        links = analyze.find_links(events, min_run=args.min_run)
        print(f"{len(links)} value-match links")
        for src, dst, hexval in links:
            print(f"  #{src} -> #{dst}  {hexval}")
            print(f"      {analyze.describe(by_seq[src], symbols)}")
            print(f"      {analyze.describe(by_seq[dst], symbols)}")
        return 0
    for seq in analyze.follow(events, args.from_seq, min_run=args.min_run):
        print(f"#{seq:<6} t={by_seq[seq]['t']:<10} {analyze.describe(by_seq[seq], symbols)}")
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    events = analyze.load_events(args.events)
    symbols = _symbols(args.config)
    prev_t: Optional[float] = None
    for ev in events:
        if ev.get("kind") == "meta":
            continue
        if prev_t is not None and args.speed > 0:
            gap = min((ev["t"] - prev_t) / args.speed, args.max_gap)
            if gap > 0:
                time.sleep(gap)
        prev_t = ev["t"]
        print(f"{ev['t']:10.4f}  #{ev['seq']:<6} {analyze.describe(ev, symbols)}",
              flush=True)
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    events = analyze.load_events(args.events)
    for kind, count in sorted(analyze.summarize(events).items()):
        print(f"{kind:<12}{count}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="hal_trace", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("events", help="JSONL from halucinator --event-log")
        p.add_argument("-c", "--config", action="append", default=[],
                       help="HALucinator YAML with a symbols: map, used to name "
                            "calling firmware functions (repeatable)")

    p_map = sub.add_parser("map", help="domain-boundary diagram (Graphviz DOT)")
    common(p_map)
    p_map.add_argument("-o", "--output", help="*.dot, or *.svg/*.png via graphviz")
    p_map.add_argument("--from-t", type=float, help="start of time window (s)")
    p_map.add_argument("--to-t", type=float, help="end of time window (s)")
    p_map.add_argument("--hide-stubs", action="store_true",
                       help="omit nopped/canned-return intercepts")
    p_map.add_argument("--value-links", action="store_true",
                       help="add heuristic value-match data-flow edges "
                            "(false positives on text streams; see docs)")
    p_map.add_argument("--min-run", type=int, default=2,
                       help="shortest byte run counted as a data-flow link")
    p_map.set_defaults(func=_cmd_map)

    p_tl = sub.add_parser("timeline", help="ordered domain crossings")
    common(p_tl)
    p_tl.add_argument("--skip", action="append", default=[],
                      help="drop crossings whose target contains this text")
    p_tl.set_defaults(func=_cmd_timeline)

    p_flow = sub.add_parser("flow", help="value-match data-flow links")
    common(p_flow)
    p_flow.add_argument("--from-seq", type=int,
                        help="follow forward from this event number")
    p_flow.add_argument("--min-run", type=int, default=2,
                        help="shortest byte run counted as a data-flow link")
    p_flow.set_defaults(func=_cmd_flow)

    p_rep = sub.add_parser("replay", help="print events with recorded timing")
    common(p_rep)
    p_rep.add_argument("--speed", type=float, default=1.0,
                       help="1=real time, 0.1=10x slower, 10=10x faster, "
                            "0=as fast as possible")
    p_rep.add_argument("--max-gap", type=float, default=2.0,
                       help="cap any single (scaled) pause, seconds")
    p_rep.set_defaults(func=_cmd_replay)

    p_stat = sub.add_parser("stats", help="event counts by kind")
    p_stat.add_argument("events")
    p_stat.set_defaults(func=_cmd_stats)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:  # e.g. piped into head
        return 0


if __name__ == "__main__":
    sys.exit(main())
