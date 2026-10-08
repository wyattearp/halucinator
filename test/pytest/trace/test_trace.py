"""Tests for the event log and the domain map / timeline."""
import json

import pytest

from halucinator.trace import analyze, events

STUB_MOD = "halucinator.bp_handlers.generic.common"


@pytest.fixture
def log_path(tmp_path):
    path = tmp_path / "ev.jsonl"
    events.enable(str(path))
    yield path
    events.disable()


def _read(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def _icpt(seq, t, sym, module=STUB_MOD, lr=0x1000):
    return {"seq": seq, "t": t, "kind": "intercept", "sym": sym, "pc": 0x2000, "lr": lr,
            "cls": "C", "module": module, "fn": "f"}


def _tx(seq, t):
    return {"seq": seq, "t": t, "kind": "model_tx", "topic": "Peripheral.UTTYModel.tx_buf",
            "payload": {"interface_id": "S", "chars_hex": "4142"}}


def test_disabled_emit_is_noop():
    events.disable()
    events.emit("intercept", "handler", sym="x")
    assert not events.is_enabled()


def test_emit_orders_events(log_path):
    events.emit("intercept", "handler", sym="a")
    events.emit("model_tx", "model", topic="t")
    events.disable()
    evs = _read(log_path)
    assert [e["seq"] for e in evs] == [1, 2, 3]
    assert evs[1]["t"] <= evs[2]["t"]


def test_hot_polls_fold_into_repeat(log_path):
    for _ in range(100):
        events.emit_poll("intercept", "handler", "poll", ("sig",), sym="poll")
    events.emit("model_tx", "model", topic="t")
    events.disable()
    evs = _read(log_path)
    assert sum(e["kind"] == "intercept" for e in evs) == events.POLL_THRESHOLD
    assert [e["count"] for e in evs if e["kind"] == "repeat"] == [100 - events.POLL_THRESHOLD]


def test_changing_signature_is_not_folded(log_path):
    for i in range(50):
        events.emit_poll("intercept", "handler", "k", (i,), sym="k")
    events.disable()
    assert sum(e["kind"] == "intercept" for e in _read(log_path)) == 50


def test_categorize():
    assert analyze.categorize(_icpt(1, 0, "a")) == analyze.STUB
    assert analyze.categorize(_icpt(1, 0, "a", "halucinator.bp_handlers.generic.libc")) == analyze.HLE
    assert analyze.categorize(_icpt(1, 0, "a", "halucinator.bp_handlers.bpv5.i2c")) == analyze.MODEL


def test_graph_attributes_tx_to_next_intercept_and_device():
    evs = [_icpt(1, .1, "skip_me"), _tx(2, .2),
           _icpt(3, .21, "printf", "halucinator.bp_handlers.generic.libc")]
    nodes, edges, _ = analyze.build_graph(evs)
    assert {n[1] for n in nodes.values()} == {"firmware", "stub", "hle", "model", "device"}
    assert ("h:printf", "m:UTTYModel.tx_buf:S") in edges
    assert ("m:UTTYModel.tx_buf:S", "d:UTTYModel:S") in edges
    assert "cluster_stub" in analyze.to_dot(nodes, edges, {})


def test_repeat_counts_fold_into_node_and_edge():
    evs = [_icpt(1, .1, "poll"), {"seq": 2, "t": .2, "kind": "repeat", "of": "poll", "count": 500}]
    nodes, edges, _ = analyze.build_graph(evs)
    assert nodes["h:poll"][2] == 501
    assert edges[("fw:<unknown caller>", "h:poll")] == 501


def test_symbol_lookup_nearest_below(tmp_path):
    yml = tmp_path / "s.yaml"
    yml.write_text("symbols:\n  4096: foo\n  8192: bar\n")
    table = analyze.SymbolTable(str(yml))
    assert (table.lookup(4100), table.lookup(8193), table.lookup(10)) == ("foo", "bar", None)


def test_crossings_rows():
    rows = analyze.crossings([_icpt(1, .1, "x"), _tx(2, .2)])
    assert rows[0]["to"] == "stub:x" and rows[1]["to"] == "device:S" and "4142" in rows[1]["via"]


def test_text_payload_is_shown_as_hex():
    ev = {"seq": 1, "t": 0.0, "kind": "model_rx", "topic": "Peripheral.UARTPublisher.rx_data",
          "payload": {"chars": "12", "id": 1}}
    assert "3132" in analyze.crossings([ev])[0]["via"]


# --- handler-boundary taint ------------------------------------------------
from halucinator.trace import taint  # noqa: E402


class FakeTarget:
    def __init__(self):
        self.mem = {}

    def write_memory(self, addr, size, value, num_words=1, raw=False):
        data = value if raw else int(value).to_bytes(size, "little")
        for i, b in enumerate(data):
            self.mem[addr + i] = b
        return True

    def read_memory(self, addr, size, num_words=1, raw=False):
        return bytes(self.mem.get(addr + i, 0) for i in range(size * num_words))


@pytest.fixture
def tainted(log_path):
    taint.reset()
    yield log_path
    taint.reset()


def _kinds(path, *kinds):
    events.disable()
    return [e for e in _read(path) if e["kind"] in kinds]


def test_write_adopts_pending_tag_and_read_reports_sink(tainted):
    taint.feed(9, b"1234")
    tgt = FakeTarget()
    with taint.watch(tgt, "rx_h"):
        tgt.write_memory(0x100, 1, b"1234", 4, raw=True)
    with taint.watch(tgt, "tx_h"):
        tgt.read_memory(0x100, 1, 4, raw=True)
    src, sink = _kinds(tainted, "taint_src", "taint_sink")
    assert (src["handler"], src["tags"], src["len"]) == ("rx_h", [9], 4)
    assert (sink["handler"], sink["tags"], sink["tainted"]) == ("tx_h", [9], 4)
    assert "write_memory" not in vars(tgt)  # patch removed afterwards


def test_untainted_overwrite_clears_and_unrelated_read_is_silent(tainted):
    taint.feed(1, b"AB")
    tgt = FakeTarget()
    with taint.watch(tgt, "h"):
        tgt.write_memory(0x10, 1, b"AB", 2, raw=True)
        tgt.write_memory(0x10, 1, b"ZZ", 2, raw=True)   # firmware overwrote it
        tgt.read_memory(0x10, 1, 2, raw=True)
        tgt.read_memory(0x900, 1, 4, raw=True)
    assert [e["kind"] for e in _kinds(tainted, "taint_src", "taint_sink")] == ["taint_src"]


def test_single_byte_int_writes_follow_the_stream_and_skip_stale(tainted):
    taint.feed(5, b"xyz")          # 'x' never stored: stale, dropped when 'y' matches
    tgt = FakeTarget()
    with taint.watch(tgt, "getc"):
        tgt.write_memory(0x20, 1, ord("y"))
        tgt.write_memory(0x21, 1, ord("z"))
    srcs = _kinds(tainted, "taint_src")
    assert [(e["addr"], e["tags"]) for e in srcs] == [(0x20, [5]), (0x21, [5])]


def test_graph_and_report_link_source_to_sink():
    evs = [
        {"seq": 1, "t": 0.0, "kind": "model_rx", "topic": "Peripheral.U.rx", "payload": {}},
        {"seq": 2, "t": 0.1, "kind": "taint_src", "handler": "rx_h", "addr": 0, "len": 4, "tags": [1]},
        _icpt(3, 0.11, "rx_h"),
        {"seq": 4, "t": 0.2, "kind": "taint_sink", "handler": "tx_h", "addr": 0, "len": 4,
         "tags": [1], "tainted": 4},
        _icpt(5, 0.21, "tx_h"),
    ]
    _, _, tedges = analyze.build_graph(evs)
    assert tedges[("m:U.rx:", "h:rx_h")] == 4 and tedges[("h:rx_h", "h:tx_h")] == 4
    row = analyze.taint_report(evs)[0]
    assert row["tag"] == 1 and row["sinks"][0]["handler"] == "tx_h"
    assert analyze.taint_report(evs[:3])[0]["sinks"] == []     # lost without the sink


def test_dot_marks_where_taint_ends():
    evs = [
        {"seq": 1, "t": 0.0, "kind": "model_rx", "topic": "Peripheral.U.rx", "payload": {}},
        {"seq": 2, "t": 0.1, "kind": "taint_src", "handler": "rx_h", "addr": 0, "len": 1, "tags": [1]},
        _icpt(3, 0.11, "rx_h"),
    ]
    dot = analyze.to_dot(*analyze.build_graph(evs))
    assert "taint ends here" in dot and "taint 1B" in dot
