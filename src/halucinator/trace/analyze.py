"""Domain-boundary map and timeline built from an event log (see events.py)."""
from __future__ import annotations

import bisect
import json
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import yaml

STUB, HLE, MODEL = "stub", "hle", "model"
_STUB_MODULES = ("halucinator.bp_handlers.generic.common",
                 "halucinator.bp_handlers.generic.counter",
                 "halucinator.bp_handlers.generic.argument_loggers",
                 "halucinator.bp_handlers.generic.debug_print")
TITLES = {
    "firmware": "Emulated firmware (runs in Unicorn/QEMU)",
    STUB: "Nopped / canned-return intercepts",
    HLE: "Python HLE (replaces firmware function)",
    MODEL: "Python peripheral & device models",
    "device": "External devices (ZMQ)",
}
_STYLE = {
    "firmware": 'style=filled, fillcolor="#dbe9f6"',
    STUB: 'style="filled,dashed", fillcolor="#eeeeee"',
    HLE: 'style=filled, fillcolor="#fff2cc"',
    MODEL: 'style="filled,rounded", fillcolor="#d9ead3"',
    "device": 'shape=component, style=filled, fillcolor="#f4cccc"',
}

Event = Dict[str, Any]


def load_events(path: str) -> List[Event]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


class SymbolTable:
    """addr -> function name from HALucinator ``symbols:`` YAML maps."""

    def __init__(self, *paths: str) -> None:
        pairs: Dict[int, str] = {}
        for path in paths:
            with open(path, encoding="utf-8") as handle:
                for addr, name in ((yaml.safe_load(handle) or {}).get("symbols") or {}).items():
                    pairs[int(addr) & ~1] = str(name)
        self._addrs = sorted(pairs)
        self._names = [pairs[a] for a in self._addrs]

    def lookup(self, addr: Optional[int]) -> Optional[str]:
        """Nearest symbol at or below *addr* (no sizes, so approximate)."""
        idx = bisect.bisect_right(self._addrs, (addr or 0) & ~1) - 1
        return self._names[idx] if addr is not None and idx >= 0 else None


def categorize(event: Event) -> str:
    module = event.get("module") or ""
    if module in _STUB_MODULES:
        return STUB
    return HLE if module.startswith("halucinator.bp_handlers.generic.") else MODEL


def _topic(event: Event) -> Tuple[str, str]:
    """('UTTYModel.tx_buf', 'STDIO') for a model_tx/model_rx event."""
    topic = str(event.get("topic", "")).removeprefix("Peripheral.")
    payload = event.get("payload")
    return topic, str(payload.get("interface_id", "")) if isinstance(payload, dict) else ""


def _hex(event: Event) -> Optional[str]:
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return None
    for key, val in payload.items():
        if key.endswith("_hex"):
            return str(val)
        if key in ("chars", "data") and isinstance(val, str):  # text payloads, e.g. UART rx
            return val.encode(errors="replace").hex()
    return None


def build_graph(events: List[Event], symbols: Optional[SymbolTable] = None
                ) -> Tuple[Dict[str, Tuple[str, str, int]], Dict[Tuple[str, str], int],
                           Dict[Tuple[str, str], int]]:
    """Returns (nodes: id -> (label, cluster, count), edges: (src, dst) -> count,
    taint_edges: (src, dst) -> tainted bytes).

    A ``model_tx`` is logged from inside the handler that produced it, i.e.
    just *before* that handler's own intercept event, so pending tx topics are
    attributed to the next intercept.
    """
    symbols = symbols or SymbolTable()
    nodes: Dict[str, List[Any]] = {}
    edges: Dict[Tuple[str, str], int] = defaultdict(int)
    taint_edges: Dict[Tuple[str, str], int] = defaultdict(int)
    rx_node: Dict[int, str] = {}              # tag (model_rx seq) -> model node
    stored_by: Dict[int, set] = defaultdict(set)  # tag -> handler nodes that stored it

    def node(ident: str, label: str, cluster: str, count: int = 1) -> None:
        nodes.setdefault(ident, [label, cluster, 0])[2] += count

    pending: List[str] = []
    for ev in events:
        kind = ev.get("kind")
        if kind == "intercept":
            ident = f"h:{ev.get('sym') or hex(ev.get('pc') or 0)}"
            node(ident, f"{ev.get('sym')}\\n{ev.get('cls')}.{ev.get('fn')}", categorize(ev))
            caller = f"fw:{symbols.lookup(ev.get('lr')) or '<unknown caller>'}"
            node(caller, caller[3:], "firmware")
            edges[(caller, ident)] += 1
            for topic in pending:
                edges[(ident, topic)] += 1
            pending = []
        elif kind in ("model_tx", "model_rx"):
            topic, iface = _topic(ev)
            model, dev = f"m:{topic}:{iface}", f"d:{topic.split('.')[0]}:{iface}"
            node(model, f"{topic}\\n[{iface}]", MODEL)
            node(dev, f"external device\\n{topic.split('.')[0]} [{iface}]", "device")
            edges[(model, dev) if kind == "model_tx" else (dev, model)] += 1
            if kind == "model_rx":
                rx_node[ev["seq"]] = model
            if kind == "model_tx":
                pending.append(model)
        elif kind == "taint_src":
            handler = f"h:{ev['handler']}"
            for tag in ev["tags"]:
                stored_by[tag].add(handler)
                if tag in rx_node:
                    taint_edges[(rx_node[tag], handler)] += ev["len"]
        elif kind == "taint_sink":
            handler = f"h:{ev['handler']}"
            for tag in ev["tags"]:
                for src in stored_by.get(tag, ()):
                    if src != handler:
                        taint_edges[(src, handler)] += ev["tainted"]
        elif kind == "irq":
            src = f"d:irq:{ev.get('source')}"
            node(src, f"IRQ source\\n{ev.get('source')}", "device")
            node("fw:<irq>", f"IRQ {ev.get('irq')}", "firmware")
            edges[(src, "fw:<irq>")] += 1
        elif kind == "repeat":  # folded idle polls: add to the node and its call edges
            key = f"h:{ev['of']}"
            if key in nodes:
                nodes[key][2] += ev["count"]
                for edge in [e for e in edges if e[1] == key]:
                    edges[edge] += ev["count"]
    return ({k: (v[0], v[1], v[2]) for k, v in nodes.items()}, dict(edges),
            dict(taint_edges))


def to_dot(nodes: Dict[str, Tuple[str, str, int]], edges: Dict[Tuple[str, str], int],
           taint_edges: Optional[Dict[Tuple[str, str], int]] = None) -> str:
    out = ["digraph halucinator {", "  rankdir=LR; compound=true; fontname=Helvetica;",
           "  node [shape=box, fontname=Helvetica, fontsize=10];",
           "  edge [fontname=Helvetica, fontsize=9];"]
    ends = {d for (_, d) in (taint_edges or {})} - {s for (s, _) in (taint_edges or {})}
    for cluster, title in TITLES.items():
        members = [(i, n) for i, n in nodes.items() if n[1] == cluster]
        if members:
            out.append(f'  subgraph cluster_{cluster} {{ label="{title}"; style=rounded;')
            out += [f'    "{i}" [label="{n[0]}\\n×{n[2]}'
                    + ('\\n⚑ taint ends here' if i in ends else '')
                    + f'", {_STYLE[cluster]}'
                    + (', color="#c0392b", penwidth=3' if i in ends else '') + '];'
                    for i, n in members]
            out.append("  }")
    out += [f'  "{s}" -> "{d}" [label="{c}"];' for (s, d), c in edges.items()]
    out += [f'  "{s}" -> "{d}" [label="taint {n}B", color="#c0392b", fontcolor="#c0392b", '
            f'style=dashed, penwidth=2];' for (s, d), n in (taint_edges or {}).items()]
    return "\n".join(out + ["}"]) + "\n"


def crossings(events: List[Event], symbols: Optional[SymbolTable] = None) -> List[Dict[str, Any]]:
    """One row per domain crossing, in order."""
    symbols = symbols or SymbolTable()
    rows = []
    for ev in events:
        kind = ev.get("kind")
        if kind == "intercept":
            frm, to, via = (f"firmware:{symbols.lookup(ev.get('lr')) or '?'}",
                            f"{categorize(ev)}:{ev.get('sym')}", f"{ev.get('cls')}.{ev.get('fn')}")
        elif kind in ("model_tx", "model_rx"):
            topic, iface = _topic(ev)
            model, dev = f"model:{topic}", f"device:{iface or topic.split('.')[0]}"
            frm, to = (model, dev) if kind == "model_tx" else (dev, model)
            via = f"zmq {_hex(ev) or ''}".strip()
        elif kind == "irq":
            frm, to, via = f"device:{ev.get('source')}", f"firmware:irq{ev.get('irq')}", "irq"
        else:
            continue
        rows.append({"seq": ev["seq"], "t": ev["t"], "from": frm, "to": to, "via": via})
    return rows


def taint_report(events: List[Event]) -> List[Dict[str, Any]]:
    """One row per tagged input: where it was stored, where it reached, or lost."""
    rows: Dict[int, Dict[str, Any]] = {}
    for ev in events:
        kind = ev.get("kind")
        if kind == "model_rx":
            rows[ev["seq"]] = {"tag": ev["seq"], "t": ev["t"], "source": _topic(ev)[0],
                               "stored": [], "sinks": []}
        elif kind in ("taint_src", "taint_sink"):
            key = "stored" if kind == "taint_src" else "sinks"
            for tag in ev["tags"]:
                if tag in rows:
                    rows[tag][key].append({"seq": ev["seq"], "t": ev["t"], "handler": ev["handler"],
                                           "bytes": ev.get("tainted", ev.get("len"))})
    return list(rows.values())
