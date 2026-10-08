"""Event log, domain map and handler-boundary taint."""
import json

import pytest

from halucinator.trace import analyze, events, taint

STUB = "halucinator.bp_handlers.generic.common"


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "ev.jsonl"
    events.enable(str(path))
    taint._pending.clear()
    taint._shadow.clear()
    yield path
    events.disable()


def read(path, *kinds):
    events.disable()
    return [e for e in map(json.loads, path.read_text().splitlines()) if not kinds or e["kind"] in kinds]


def icpt(seq, sym, module=STUB):
    return {"seq": seq, "t": seq / 10, "kind": "intercept", "sym": sym, "pc": 1, "lr": 0x1000,
            "cls": "C", "module": module, "fn": "f", "ret": 0}


class Target:
    def __init__(self):
        self.mem = {}

    def write_memory(self, addr, size, value, num_words=1, raw=False):
        for i, b in enumerate(value if raw else int(value).to_bytes(size, "little")):
            self.mem[addr + i] = b

    def read_memory(self, addr, size, num_words=1, raw=False):
        return bytes(self.mem.get(addr + i, 0) for i in range(size * num_words))


def test_disabled_is_noop():
    events.disable()
    assert events.emit("x") is None and not events.is_enabled()


def test_emit_is_ordered(log):
    events.emit("a")
    assert events.emit("b") == 2
    assert [e["seq"] for e in read(log)] == [1, 2]


def test_hot_polls_fold_and_keep_their_count_when_the_signature_changes(log):
    for _ in range(100):
        events.emit_poll("intercept", "poll", ("same",), sym="poll")
    events.emit_poll("intercept", "poll", ("different",), sym="poll")
    evs = read(log)
    assert sum(e["kind"] == "intercept" for e in evs) == events.POLL_THRESHOLD + 1
    assert [e["count"] for e in evs if e["kind"] == "repeat"] == [100 - events.POLL_THRESHOLD]


def test_symbol_lookup(tmp_path):
    yml = tmp_path / "s.yaml"
    yml.write_text("symbols:\n  4096: foo\n  8192: bar\n")
    symbols = analyze.load_symbols([str(yml)])
    assert [analyze.symbol_at(symbols, a) for a in (4100, 8193, 10)] == ["foo", "bar", "<unknown caller>"]


def test_graph_clusters_message_path_and_folded_polls():
    tx = {"seq": 2, "t": .2, "kind": "model_tx", "topic": "Peripheral.U.tx", "payload": {"interface_id": "S"}}
    evs = [icpt(1, "skip"), tx, icpt(3, "printf", "halucinator.bp_handlers.generic.libc"),
           {"seq": 4, "t": .4, "kind": "repeat", "of": "skip", "count": 500}]
    nodes, edges, _ = analyze.build_graph(evs)
    assert {n[1] for n in nodes.values()} == {"firmware", "stub", "hle", "model", "device"}
    assert ("h:printf", "m:U.tx:S") in edges and ("m:U.tx:S", "d:U:S") in edges   # tx belongs to printf
    assert nodes["h:skip"][2] == 501 and edges[("fw:<unknown caller>", "h:skip")] == 501


def test_handler_write_adopts_the_received_tag_and_a_later_read_is_a_sink(log):
    taint.feed(9, b"1234")
    target = Target()
    with taint.watch(target, "rx_h"):
        target.write_memory(0x100, 1, b"1234", 4, raw=True)
    with taint.watch(target, "tx_h"):
        target.read_memory(0x100, 1, 4, raw=True)
    src, sink = read(log, "taint_src", "taint_sink")
    assert (src["handler"], src["tags"]) == ("rx_h", [9])
    assert (sink["handler"], sink["tags"], sink["tainted"]) == ("tx_h", [9], 4)
    assert "write_memory" not in vars(target)


def test_overwrite_clears_taint_and_single_byte_writes_skip_stale_input(log):
    taint.feed(1, b"AB")
    taint.feed(5, b"xyz")           # 'x' is never stored; dropped when 'y' matches
    target = Target()
    with taint.watch(target, "h"):
        target.write_memory(0x10, 1, b"AB", 2, raw=True)
        target.write_memory(0x10, 1, b"ZZ", 2, raw=True)   # firmware overwrote it
        target.read_memory(0x10, 1, 2, raw=True)             # untainted now: no sink
        target.write_memory(0x20, 1, ord("y"))
    assert [(e["kind"], e["tags"]) for e in read(log, "taint_src", "taint_sink")] == [
        ("taint_src", [1]), ("taint_src", [5])]


def test_taint_edges_end_marker_and_lost_report():
    rx = {"seq": 1, "t": 0, "kind": "model_rx", "topic": "Peripheral.U.rx", "payload": {}}
    src = {"seq": 2, "t": .1, "kind": "taint_src", "handler": "rx_h", "len": 4, "tags": [1]}
    sink = {"seq": 3, "t": .2, "kind": "taint_sink", "handler": "tx_h", "len": 4, "tainted": 4, "tags": [1]}
    _, _, edges = analyze.build_graph([rx, src, sink])
    assert edges == {("m:U.rx:", "h:rx_h"): 4, ("h:rx_h", "h:tx_h"): 4}
    assert analyze.taint_report([rx, src, sink])[0]["sinks"][0]["handler"] == "tx_h"
    assert analyze.taint_report([rx, src])[0]["sinks"] == []                 # lost
    assert "taint ends here" in analyze.to_dot(*analyze.build_graph([rx, src, icpt(5, "rx_h")]))
