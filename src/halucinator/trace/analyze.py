"""
Analysis of a HALucinator event log (see :mod:`halucinator.trace.events`).

Three views over the same JSONL trace:

* :func:`build_graph` / :func:`to_dot`  -- the domain-boundary diagram
* :func:`find_links` / :func:`follow`   -- data-flow links between I/O events
* :func:`crossings`                     -- ordered domain-transition timeline

Flow links here are **value matches**: an event that produced bytes is linked
to a later event that consumed the *same* bytes.  That is exact where a handler
or model moves data verbatim (a UART byte through a model, an I2C byte on the
bus) and blind where firmware transforms it (parsing "0xA0" text into the byte
0xA0).  Links are tagged so the diagram never presents inference as fact.
"""
from __future__ import annotations

import bisect
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

# Handler categories, i.e. what happens to the call at the boundary.
STUB = "stub"    # nopped / canned return: firmware call is simply skipped
HLE = "hle"      # Python reimplementation of a firmware or libc function
MODEL = "model"  # hardware/peripheral model (answers like a device would)

_STUB_MODULES = (
    "halucinator.bp_handlers.generic.common",
    "halucinator.bp_handlers.generic.counter",
    "halucinator.bp_handlers.generic.argument_loggers",
    "halucinator.bp_handlers.generic.debug_print",
)
_HLE_PREFIX = "halucinator.bp_handlers.generic."

CLUSTERS = ("firmware", "stub", "hle", "model", "device")
CLUSTER_TITLES = {
    "firmware": "Emulated firmware (runs in Unicorn/QEMU)",
    "stub": "Nopped / canned-return intercepts",
    "hle": "Python HLE (replaces firmware function)",
    "model": "Python peripheral & device models",
    "device": "External devices (ZMQ)",
}


def load_events(path: str) -> List[Dict[str, Any]]:
    events = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


class SymbolTable:
    """addr -> function name, from HALucinator ``symbols:`` YAML maps."""

    def __init__(self) -> None:
        self._addrs: List[int] = []
        self._names: List[str] = []

    def add_yaml(self, path: str) -> None:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        pairs = dict(zip(self._addrs, self._names))
        for addr, name in (data.get("symbols") or {}).items():
            pairs[int(addr) & ~1] = str(name)
        self._addrs = sorted(pairs)
        self._names = [pairs[a] for a in self._addrs]

    def lookup(self, addr: Optional[int]) -> Optional[str]:
        """Nearest symbol at or below *addr* (no size info, so approximate)."""
        if addr is None or not self._addrs:
            return None
        idx = bisect.bisect_right(self._addrs, addr & ~1) - 1
        return self._names[idx] if idx >= 0 else None


def categorize(event: Dict[str, Any]) -> str:
    module = event.get("module") or ""
    if module in _STUB_MODULES:
        return STUB
    if module.startswith(_HLE_PREFIX):
        return HLE
    return MODEL


@dataclass
class Node:
    ident: str
    label: str
    cluster: str
    count: int = 0


@dataclass
class Edge:
    src: str
    dst: str
    kind: str          # call | message | data
    count: int = 0
    inferred: bool = False
    detail: str = ""


@dataclass
class Graph:
    nodes: Dict[str, Node] = field(default_factory=dict)
    edges: Dict[Tuple[str, str, str], Edge] = field(default_factory=dict)

    def node(self, ident: str, label: str, cluster: str) -> Node:
        node = self.nodes.get(ident)
        if node is None:
            node = self.nodes[ident] = Node(ident, label, cluster)
        node.count += 1
        return node

    def edge(self, src: str, dst: str, kind: str, detail: str = "") -> None:
        key = (src, dst, kind)
        edge = self.edges.get(key)
        if edge is None:
            edge = self.edges[key] = Edge(src, dst, kind, detail=detail)
        edge.count += 1


def _topic_parts(event: Dict[str, Any]) -> Tuple[str, str]:
    """('UTTYModel.tx_buf', 'STDIO') from a model_tx/model_rx event."""
    topic = str(event.get("topic", ""))
    short = topic[len("Peripheral."):] if topic.startswith("Peripheral.") else topic
    payload = event.get("payload")
    iface = payload.get("interface_id") if isinstance(payload, dict) else None
    return short, str(iface) if iface is not None else ""


def _handler_ident(event: Dict[str, Any]) -> str:
    return f"h:{event.get('sym') or hex(event.get('pc') or 0)}"


def _hex_fields(event: Dict[str, Any]) -> List[str]:
    """Hex payloads an event carries, normalised to lowercase."""
    out = []
    if event.get("kind") == "data" and event.get("hex"):
        out.append(str(event["hex"]).lower())
    payload = event.get("payload")
    if isinstance(payload, dict):
        for key, val in payload.items():
            if key.endswith("_hex") and val:
                out.append(str(val).lower())
    return out


def _is_producer(event: Dict[str, Any]) -> bool:
    """Produces bytes toward the firmware side."""
    return event.get("kind") == "model_rx" or (
        event.get("kind") == "data" and event.get("dir") == "out")


def _is_consumer(event: Dict[str, Any]) -> bool:
    """Consumes bytes coming from the firmware side."""
    return event.get("kind") == "model_tx" or (
        event.get("kind") == "data" and event.get("dir") == "in")


def attribute(events: List[Dict[str, Any]]) -> Dict[int, str]:
    """Map event seq -> node id.

    Intercept events are logged when the handler *returns*, so ``data`` and
    ``model_tx`` events emitted from inside it appear just before it.  They are
    attributed to the next intercept's handler node (``model_tx`` keeps its own
    topic node; the owning handler is recorded separately by the caller).
    """
    owner: Dict[int, str] = {}
    pending: List[int] = []
    for ev in events:
        kind = ev.get("kind")
        if kind in ("data", "model_tx"):
            pending.append(ev["seq"])
        elif kind == "intercept":
            ident = _handler_ident(ev)
            for seq in pending:
                owner[seq] = ident
            pending = []
            owner[ev["seq"]] = ident
    return owner


def find_links(events: List[Dict[str, Any]],
               max_age: float = 1.0, min_run: int = 2) -> List[Tuple[int, int, str]]:
    """Value-match links ``(producer_seq, consumer_seq, hex)``.

    Bytes are matched as a stream: every byte a producer emits joins a FIFO
    for its value, and each byte a consumer takes is linked to the oldest
    still-unconsumed producer of that value no older than *max_age* seconds of
    event time.  Consecutive bytes from one producer collapse into one link.
    Bytes with no producer in range are simply left unlinked, and links
    shorter than *min_run* bytes are dropped: one- and two-byte coincidences
    (a shared ESC 0x1b, a repeated 0x00) are indistinguishable from real copies
    by value alone, so short matches are noise by default.
    """
    avail: Dict[str, List[Tuple[int, float]]] = defaultdict(list)
    links: List[Tuple[int, int, str]] = []
    for ev in events:
        now = ev.get("t", 0.0)
        if _is_consumer(ev):
            for hexval in _hex_fields(ev):
                matched: Dict[int, str] = {}
                for idx in range(0, len(hexval) - 1, 2):
                    byte = hexval[idx:idx + 2]
                    queue = avail[byte]
                    while queue and now - queue[0][1] > max_age:
                        queue.pop(0)
                    if queue:
                        seq, _ = queue.pop(0)
                        matched[seq] = matched.get(seq, "") + byte
                for seq, got in matched.items():
                    if len(got) // 2 < min_run:
                        continue
                    links.append((seq, ev["seq"], got))
        if _is_producer(ev):
            for hexval in _hex_fields(ev):
                for idx in range(0, len(hexval) - 1, 2):
                    avail[hexval[idx:idx + 2]].append((ev["seq"], now))
    return links


def build_graph(events: List[Dict[str, Any]],
                symbols: Optional[SymbolTable] = None,
                include_links: bool = True, min_run: int = 2) -> Graph:
    graph = Graph()
    symbols = symbols or SymbolTable()
    owner = attribute(events)
    node_of: Dict[int, str] = {}  # event seq -> graph node id
    handler_of: Dict[int, str] = {}  # model_tx seq -> owning handler node

    for ev in events:
        kind = ev.get("kind")
        if kind == "intercept":
            category = categorize(ev)
            ident = _handler_ident(ev)
            sym = ev.get("sym") or hex(ev.get("pc") or 0)
            graph.node(ident, f"{sym}\\n{ev.get('cls')}.{ev.get('fn')}", category)
            caller = symbols.lookup(ev.get("lr")) or "<unknown caller>"
            fw = f"fw:{caller}"
            graph.node(fw, caller, "firmware")
            graph.edge(fw, ident, "call")
            node_of[ev["seq"]] = ident
        elif kind == "repeat":
            continue
    # Idle-poll summaries: add their counts to the node/edge they folded.
    for ev in events:
        if ev.get("kind") == "repeat":
            key = f"h:{ev['of']}"
            if key in graph.nodes:
                graph.nodes[key].count += ev["count"]
                for (src, dst, kind), edge in graph.edges.items():
                    if dst == key and kind == "call":
                        edge.count += ev["count"]

    for ev in events:
        kind = ev.get("kind")
        if kind in ("model_tx", "model_rx"):
            short, iface = _topic_parts(ev)
            ident = f"m:{short}:{iface}"
            graph.node(ident, f"{short}\\n[{iface}]" if iface else short, "model")
            dev = f"d:{short.split('.')[0]}:{iface}"
            graph.node(dev, f"external device\\n{short.split('.')[0]}"
                       + (f" [{iface}]" if iface else ""), "device")
            node_of[ev["seq"]] = ident
            if kind == "model_tx":
                handler = owner.get(ev["seq"])
                if handler:
                    handler_of[ev["seq"]] = handler
                    graph.edge(handler, ident, "message")
                graph.edge(ident, dev, "message")
            else:
                graph.edge(dev, ident, "message")
        elif kind == "irq":
            dev = f"d:irq:{ev.get('source') or ''}"
            graph.node(dev, f"IRQ source\\n{ev.get('source') or ''}", "device")
            graph.node("fw:<irq>", f"IRQ {ev.get('irq')}", "firmware")
            graph.edge(dev, "fw:<irq>", "message")
        elif kind == "data" and ev["seq"] in owner:
            node_of[ev["seq"]] = owner[ev["seq"]]

    if include_links:
        for src_seq, dst_seq, hexval in find_links(events, min_run=min_run):
            src, dst = node_of.get(src_seq), node_of.get(dst_seq)
            if src and dst and src != dst:
                graph.edge(src, dst, "data", detail=hexval)
    return graph


def to_dot(graph: Graph, title: str = "HALucinator domain map") -> str:
    styles = {
        "firmware": 'shape=box, style="filled", fillcolor="#dbe9f6"',
        "stub": 'shape=box, style="filled,dashed", fillcolor="#eeeeee"',
        "hle": 'shape=box, style="filled", fillcolor="#fff2cc"',
        "model": 'shape=box, style="filled,rounded", fillcolor="#d9ead3"',
        "device": 'shape=component, style="filled", fillcolor="#f4cccc"',
    }
    lines = ["digraph halucinator {", f'  label="{title}"; labelloc=t;',
             "  rankdir=LR; compound=true; fontname=Helvetica;",
             "  node [fontname=Helvetica, fontsize=10];",
             "  edge [fontname=Helvetica, fontsize=9];"]
    for cluster in CLUSTERS:
        members = [n for n in graph.nodes.values() if n.cluster == cluster]
        if not members:
            continue
        lines.append(f"  subgraph cluster_{cluster} {{")
        lines.append(f'    label="{CLUSTER_TITLES[cluster]}"; style=rounded;')
        for node in members:
            lines.append(f'    "{node.ident}" [label="{node.label}\\n×{node.count}", '
                         f"{styles[cluster]}];")
        lines.append("  }")
    for edge in graph.edges.values():
        attrs = [f'label="{edge.count}"']
        if edge.kind == "data":
            attrs += ['style=dashed', 'color="#c0392b"', 'fontcolor="#c0392b"',
                      f'label="data ×{edge.count}"']
        elif edge.kind == "message":
            attrs += ["color=\"#1f6f43\""]
        lines.append(f'  "{edge.src}" -> "{edge.dst}" [{", ".join(attrs)}];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def crossings(events: List[Dict[str, Any]],
              symbols: Optional[SymbolTable] = None) -> List[Dict[str, Any]]:
    """Ordered domain-transition timeline, one row per crossing."""
    symbols = symbols or SymbolTable()
    rows = []
    for ev in events:
        kind = ev.get("kind")
        if kind == "intercept":
            caller = symbols.lookup(ev.get("lr")) or "?"
            rows.append({
                "seq": ev["seq"], "t": ev["t"],
                "from": f"firmware:{caller}",
                "to": f"{categorize(ev)}:{ev.get('sym')}",
                "via": f"{ev.get('cls')}.{ev.get('fn')}",
                "ret": ev.get("ret"),
            })
        elif kind == "model_tx":
            short, iface = _topic_parts(ev)
            rows.append({"seq": ev["seq"], "t": ev["t"], "from": f"model:{short}",
                         "to": f"device:{iface or short.split('.')[0]}",
                         "via": "zmq", "ret": None,
                         "hex": (_hex_fields(ev) or [None])[0]})
        elif kind == "model_rx":
            short, iface = _topic_parts(ev)
            rows.append({"seq": ev["seq"], "t": ev["t"],
                         "from": f"device:{iface or short.split('.')[0]}",
                         "to": f"model:{short}", "via": "zmq", "ret": None,
                         "hex": (_hex_fields(ev) or [None])[0]})
        elif kind == "irq":
            rows.append({"seq": ev["seq"], "t": ev["t"],
                         "from": f"device:{ev.get('source')}",
                         "to": f"firmware:irq{ev.get('irq')}", "via": "irq",
                         "ret": None})
    return rows


def follow(events: List[Dict[str, Any]], start_seq: int,
           min_run: int = 2) -> List[int]:
    """Forward closure of value-match links from *start_seq* (event seqs)."""
    out_links: Dict[int, List[int]] = defaultdict(list)
    for src, dst, _ in find_links(events, min_run=min_run):
        out_links[src].append(dst)
    seen, stack = [], [start_seq]
    while stack:
        seq = stack.pop()
        if seq in seen:
            continue
        seen.append(seq)
        stack.extend(sorted(out_links.get(seq, []), reverse=True))
    return sorted(seen)


def describe(event: Dict[str, Any], symbols: Optional[SymbolTable] = None) -> str:
    """One-line human description of an event."""
    symbols = symbols or SymbolTable()
    kind = event.get("kind")
    if kind == "intercept":
        caller = symbols.lookup(event.get("lr")) or "?"
        return (f"[{categorize(event)}] {caller} -> {event.get('sym')} "
                f"({event.get('cls')}.{event.get('fn')}) ret={event.get('ret')}")
    if kind in ("model_tx", "model_rx"):
        short, iface = _topic_parts(event)
        arrow = "model -> device" if kind == "model_tx" else "device -> model"
        return f"[zmq] {arrow}: {short} [{iface}] {(_hex_fields(event) or [''])[0]}"
    if kind == "data":
        return f"[data] {event.get('label')} {event.get('dir')} {event.get('hex')}"
    if kind == "irq":
        return f"[irq] {event.get('source')} -> IRQ {event.get('irq')}"
    if kind == "repeat":
        return f"[idle] {event.get('of')} repeated x{event.get('count')}"
    return f"[{kind}]"


def summarize(events: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = defaultdict(int)
    for ev in events:
        counts[ev.get("kind", "?")] += 1
    return dict(counts)
