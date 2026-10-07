"""Tests for the event log and the domain-map / flow analysis."""
import json

import pytest

from halucinator.trace import analyze, events


@pytest.fixture
def log_path(tmp_path):
    path = tmp_path / "ev.jsonl"
    events.enable(str(path))
    yield path
    events.disable()


def _read(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_disabled_emit_is_noop(tmp_path):
    events.disable()
    events.emit("intercept", "handler", sym="x")  # must not raise
    assert not events.is_enabled()


def test_emit_orders_and_stamps(log_path):
    events.emit("intercept", "handler", sym="a")
    events.emit("model_tx", "model", topic="Peripheral.X.y")
    events.disable()
    evs = _read(log_path)
    assert [e["kind"] for e in evs] == ["meta", "intercept", "model_tx"]
    assert [e["seq"] for e in evs] == [1, 2, 3]
    assert evs[1]["t"] <= evs[2]["t"]


def test_hot_polls_fold_into_repeat(log_path):
    for _ in range(100):
        events.emit_poll("intercept", "handler", "poll", ("sig",), sym="poll")
    events.emit("model_tx", "model", topic="t")  # flushes the summary
    events.disable()
    evs = _read(log_path)
    verbatim = [e for e in evs if e["kind"] == "intercept"]
    repeat = [e for e in evs if e["kind"] == "repeat"]
    assert len(verbatim) == events.POLL_THRESHOLD
    assert len(repeat) == 1 and repeat[0]["count"] == 100 - events.POLL_THRESHOLD


def test_changed_signature_is_not_folded(log_path):
    for i in range(50):
        events.emit_poll("intercept", "handler", "k", (i,), sym="k")
    events.disable()
    assert len([e for e in _read(log_path) if e["kind"] == "intercept"]) == 50


def _intercept(seq, t, sym, cls="SkipFunc", module="halucinator.bp_handlers.generic.common",
               lr=0x1000):
    return {"seq": seq, "t": t, "kind": "intercept", "domain": "handler", "sym": sym,
            "pc": 0x2000, "lr": lr, "cls": cls, "module": module, "fn": "f", "ret": 0}


def test_categorize():
    assert analyze.categorize(_intercept(1, 0, "a")) == analyze.STUB
    assert analyze.categorize(
        _intercept(1, 0, "a", module="halucinator.bp_handlers.generic.libc")) == analyze.HLE
    assert analyze.categorize(
        _intercept(1, 0, "a", module="halucinator.bp_handlers.bpv5.i2c")) == analyze.MODEL


def test_graph_clusters_and_message_path():
    evs = [
        _intercept(1, 0.1, "skip_me"),
        {"seq": 2, "t": 0.2, "kind": "model_tx", "domain": "model",
         "topic": "Peripheral.UTTYModel.tx_buf",
         "payload": {"interface_id": "S", "chars_hex": "4142"}},
        _intercept(3, 0.21, "printf", module="halucinator.bp_handlers.generic.libc"),
    ]
    graph = analyze.build_graph(evs)
    clusters = {n.cluster for n in graph.nodes.values()}
    assert {"firmware", "stub", "hle", "model", "device"} <= clusters
    # model_tx emitted inside printf is attributed to printf, then to the device
    kinds = {(e.src, e.dst) for e in graph.edges.values() if e.kind == "message"}
    assert ("h:printf", "m:UTTYModel.tx_buf:S") in kinds
    assert ("m:UTTYModel.tx_buf:S", "d:UTTYModel:S") in kinds
    dot = analyze.to_dot(graph)
    assert dot.startswith("digraph") and "cluster_stub" in dot


def test_repeat_counts_fold_into_node():
    evs = [_intercept(1, 0.1, "poll"),
           {"seq": 2, "t": 0.2, "kind": "repeat", "domain": "tool", "of": "poll",
            "count": 500, "t_first": 0.1, "t_last": 0.2}]
    graph = analyze.build_graph(evs)
    assert graph.nodes["h:poll"].count == 501


def test_symbol_lookup_nearest_below(tmp_path):
    yml = tmp_path / "s.yaml"
    yml.write_text("symbols:\n  4096: foo\n  8192: bar\n")
    table = analyze.SymbolTable()
    table.add_yaml(str(yml))
    assert table.lookup(4100) == "foo"
    assert table.lookup(8193) == "bar"   # thumb bit ignored
    assert table.lookup(10) is None


def _rx(seq, t, hexval):
    return {"seq": seq, "t": t, "kind": "model_rx", "domain": "device",
            "topic": "Peripheral.UTTYModel.rx_char_or_buf",
            "payload": {"interface_id": "S", "chars_hex": hexval}}


def _tx(seq, t, hexval):
    return {"seq": seq, "t": t, "kind": "model_tx", "domain": "model",
            "topic": "Peripheral.UTTYModel.tx_buf",
            "payload": {"interface_id": "S", "chars_hex": hexval}}


def test_value_links_exact_copy():
    evs = [_rx(1, 0.0, "68656c6c6f"), _tx(2, 0.1, "68656c6c6f")]
    assert analyze.find_links(evs) == [(1, 2, "68656c6c6f")]


def test_value_links_ignore_short_coincidences_and_stale():
    assert analyze.find_links([_rx(1, 0, "1b"), _tx(2, 0.1, "1b")]) == []
    assert analyze.find_links([_rx(1, 0, "1b"), _tx(2, 0.1, "1b")], min_run=1)
    stale = [_rx(1, 0.0, "68656c6c6f"), _tx(2, 30.0, "68656c6c6f")]
    assert analyze.find_links(stale) == []


def test_follow_forward_chain():
    evs = [_rx(1, 0, "aabb"), _tx(2, 0.1, "aabb")]
    assert analyze.follow(evs, 1) == [1, 2]


def test_crossings_rows():
    rows = analyze.crossings([_intercept(1, 0.1, "x"), _tx(2, 0.2, "41")])
    assert rows[0]["to"] == "stub:x" and rows[1]["to"] == "device:S"
