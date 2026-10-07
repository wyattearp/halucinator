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
    nodes, edges = analyze.build_graph(evs)
    assert {n[1] for n in nodes.values()} == {"firmware", "stub", "hle", "model", "device"}
    assert ("h:printf", "m:UTTYModel.tx_buf:S") in edges
    assert ("m:UTTYModel.tx_buf:S", "d:UTTYModel:S") in edges
    assert "cluster_stub" in analyze.to_dot(nodes, edges)


def test_repeat_counts_fold_into_node_and_edge():
    evs = [_icpt(1, .1, "poll"), {"seq": 2, "t": .2, "kind": "repeat", "of": "poll", "count": 500}]
    nodes, edges = analyze.build_graph(evs)
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
