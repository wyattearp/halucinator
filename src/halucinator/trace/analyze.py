"""Domain-boundary map and taint report built from an event log (see events.py)."""
import bisect
import json
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import yaml

Event = Dict[str, Any]
# cluster -> (title, dot node style)
CLUSTERS = {
    "firmware": ("Emulated firmware (runs in Unicorn/QEMU)", 'style=filled, fillcolor="#dbe9f6"'),
    "stub": ("Nopped / canned-return intercepts", 'style="filled,dashed", fillcolor="#eeeeee"'),
    "hle": ("Python HLE (replaces firmware function)", 'style=filled, fillcolor="#fff2cc"'),
    "model": ("Python peripheral & device models", 'style="filled,rounded", fillcolor="#d9ead3"'),
    "device": ("External devices (ZMQ)", 'shape=component, style=filled, fillcolor="#f4cccc"'),
}
_STUB_MODULES = tuple(f"halucinator.bp_handlers.generic.{m}"
                      for m in ("common", "counter", "argument_loggers", "debug_print"))


def load_events(path: str) -> List[Event]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def load_symbols(paths: List[str]) -> List[Tuple[int, str]]:
    """Sorted (addr, name) from the ``symbols:`` maps of HALucinator YAML files."""
    table = {}
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            for addr, name in ((yaml.safe_load(handle) or {}).get("symbols") or {}).items():
                table[int(addr) & ~1] = str(name)
    return sorted(table.items())


def symbol_at(symbols: List[Tuple[int, str]], addr: Optional[int]) -> str:
    """Nearest symbol at or below addr (no sizes, so approximate)."""
    idx = bisect.bisect_right(symbols, ((addr or 0) & ~1, "\U0010ffff")) - 1
    return symbols[idx][1] if addr is not None and idx >= 0 else "<unknown caller>"


def category(event: Event) -> str:
    module = event.get("module") or ""
    if module in _STUB_MODULES:
        return "stub"
    return "hle" if module.startswith("halucinator.bp_handlers.generic.") else "model"


def topic(event: Event) -> Tuple[str, str]:
    """('UTTYModel.tx_buf', 'STDIO') for a model_tx/model_rx event."""
    payload = event.get("payload")
    iface = payload.get("interface_id", "") if isinstance(payload, dict) else ""
    return str(event.get("topic", "")).removeprefix("Peripheral."), str(iface)


def build_graph(events: List[Event], symbols: Optional[List[Tuple[int, str]]] = None):
    """Returns (nodes: id -> [label, cluster, count], edges, taint_edges); edges map
    (src, dst) -> count (taint_edges: tainted bytes).

    A model_tx is logged from inside the handler that produced it, just before
    that handler's own intercept event, so pending tx nodes belong to the next one.
    """
    nodes: Dict[str, list] = {}
    edges: Dict[Tuple[str, str], int] = defaultdict(int)
    taint_edges: Dict[Tuple[str, str], int] = defaultdict(int)
    rx_node: Dict[int, str] = {}                   # tag (model_rx seq) -> model node
    last: Dict[int, str] = {}                      # tag -> node its data was most recently seen in
    pending: List[str] = []

    def node(ident: str, label: str, cluster: str) -> None:
        nodes.setdefault(ident, [label, cluster, 0])[2] += 1

    for ev in events:
        kind = ev["kind"]
        if kind == "intercept":
            ident = f"h:{ev['sym'] or hex(ev['pc'])}"
            node(ident, f"{ev['sym']}\\n{ev['cls']}.{ev['fn']}", category(ev))
            caller = f"fw:{symbol_at(symbols or [], ev['lr'])}"
            node(caller, caller[3:], "firmware")
            edges[(caller, ident)] += 1
            for tx in pending:
                edges[(ident, tx)] += 1
            pending = []
        elif kind in ("model_tx", "model_rx"):
            name, iface = topic(ev)
            model, dev = f"m:{name}:{iface}", f"d:{name.split('.')[0]}:{iface}"
            node(model, f"{name}\\n[{iface}]", "model")
            node(dev, f"external device\\n{name.split('.')[0]} [{iface}]", "device")
            edges[(model, dev) if kind == "model_tx" else (dev, model)] += 1
            if kind == "model_tx":
                pending.append(model)
            else:
                rx_node[ev["seq"]] = model
        elif kind == "taint_src":
            for tag in ev["tags"]:
                if tag in rx_node:
                    taint_edges[(rx_node[tag], f"h:{ev['handler']}")] += ev["len"]
                last[tag] = f"h:{ev['handler']}"
        elif kind == "taint_code":  # firmware functions the tagged data passed through, in order
            for func in dict.fromkeys(symbol_at(symbols or [], pc) for pc in ev["pcs"]):
                nodes.setdefault(f"fw:{func}", [func, "firmware", 0])
                if last.get(ev["tag"]) not in (None, f"fw:{func}"):
                    taint_edges[(last[ev["tag"]], f"fw:{func}")] += 0
                last[ev["tag"]] = f"fw:{func}"
        elif kind == "taint_sink":
            for tag in ev["tags"]:
                if tag in last and last[tag] != f"h:{ev['handler']}":
                    taint_edges[(last[tag], f"h:{ev['handler']}")] += ev["tainted"]
                last[tag] = f"h:{ev['handler']}"
        elif kind == "irq":
            node(f"d:irq:{ev['source']}", f"IRQ source\\n{ev['source']}", "device")
            node("fw:<irq>", f"IRQ {ev['irq']}", "firmware")
            edges[(f"d:irq:{ev['source']}", "fw:<irq>")] += 1
        elif kind == "repeat" and f"h:{ev['of']}" in nodes:  # folded idle polls
            nodes[f"h:{ev['of']}"][2] += ev["count"]
            for edge in [e for e in edges if e[1] == f"h:{ev['of']}"]:
                edges[edge] += ev["count"]
    return nodes, edges, taint_edges


def to_dot(nodes, edges, taint_edges=None) -> str:
    taint_edges = taint_edges or {}
    ends = {d for _, d in taint_edges} - {s for s, _ in taint_edges}  # taint arrives, never leaves
    out = ["digraph halucinator {", "  rankdir=LR; compound=true; fontname=Helvetica;",
           "  node [shape=box, fontname=Helvetica, fontsize=10];",
           "  edge [fontname=Helvetica, fontsize=9];"]
    for cluster, (title, style) in CLUSTERS.items():
        members = [(i, n) for i, n in nodes.items() if n[1] == cluster]
        if members:
            out.append(f'  subgraph cluster_{cluster} {{ label="{title}"; style=rounded;')
            for ident, (label, _, count) in members:
                end = ident in ends
                out.append(f'    "{ident}" [label="{label}\\n×{count}' + ("\\n⚑ taint ends here" if end else "")
                           + f'", {style}' + (', color="#c0392b", penwidth=3' if end else "") + "];")
            out.append("  }")
    out += [f'  "{s}" -> "{d}" [label="{c}"];' for (s, d), c in edges.items()]
    for (s, d), n in taint_edges.items():  # n = tainted bytes, or 0 for a firmware-function hop
        label = f"taint {n}B" if n else "taint"
        out.append(f'  "{s}" -> "{d}" [label="{label}", color="#c0392b", fontcolor="#c0392b", '
                   "style=dashed, penwidth=2];")
    return "\n".join(out + ["}"]) + "\n"


def taint_report(events: List[Event], symbols: Optional[List[Tuple[int, str]]] = None) -> List[Dict[str, Any]]:
    """Per tagged input: handlers that stored it, firmware functions it passed through,
    and handlers that read it out (none = lost)."""
    rows: Dict[int, Dict[str, Any]] = {}
    for ev in events:
        if ev["kind"] == "model_rx":
            rows[ev["seq"]] = {"tag": ev["seq"], "t": ev["t"], "source": topic(ev)[0],
                               "stored": [], "through": [], "sinks": []}
        elif ev["kind"] == "taint_code" and ev["tag"] in rows:
            rows[ev["tag"]]["through"] += [symbol_at(symbols or [], pc) for pc in ev["pcs"]]
        elif ev["kind"] in ("taint_src", "taint_sink"):
            for tag in ev["tags"]:
                if tag in rows:
                    rows[tag]["stored" if ev["kind"] == "taint_src" else "sinks"].append(
                        {"t": ev["t"], "handler": ev["handler"], "bytes": ev.get("tainted", ev["len"]),
                         "of": ev["len"]})
    for row in rows.values():
        row["through"] = list(dict.fromkeys(row["through"]))
    return list(rows.values())
