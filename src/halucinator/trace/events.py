"""
Structured event log for domain-crossing analysis.

When enabled, HALucinator appends one JSON object per line (JSONL) for every
point where execution or data moves between domains:

* ``intercept``  firmware -> Python bp_handler (the emulated/modelled line)
* ``model_tx``   peripheral model -> external device (ZMQ)
* ``model_rx``   external device -> peripheral model (ZMQ)
* ``irq``        peripheral/model -> firmware interrupt injection

Every event carries ``seq`` (strict ordering) and ``t`` (seconds since the log
was opened, monotonic) so a trace can be replayed at any speed.  When no log is
enabled every entry point is a cheap no-op.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, Optional, TextIO

SCHEMA_VERSION = 1
# Bound the size of any single recorded payload; the log is for flow analysis,
# not a packet capture.
MAX_PAYLOAD_BYTES = 256

# A key repeating the identical signature this many times in a row is treated
# as an idle poll (e.g. the firmware spinning on rx_fifo_try_get) and folded
# into a single ``repeat`` summary event instead of one line per call.
POLL_THRESHOLD = 8

_lock = threading.Lock()
_out: Optional[TextIO] = None
# key -> [signature, consecutive_count, suppressed_count, first_t, last_t]
_polls: Dict[Any, list] = {}
_seq = 0
_t0 = 0.0


def is_enabled() -> bool:
    return _out is not None


def enable(path: str) -> None:
    """Start logging to *path* (truncating it)."""
    global _out, _seq, _t0  # pylint: disable=global-statement
    with _lock:
        if _out is not None:
            _flush_polls()
            _out.close()
        _polls.clear()
        _out = open(path, "w", encoding="utf-8")  # pylint: disable=consider-using-with
        _seq = 0
        _t0 = time.monotonic()
    emit("meta", "tool", schema=SCHEMA_VERSION)


def disable() -> None:
    global _out  # pylint: disable=global-statement
    with _lock:
        if _out is not None:
            _flush_polls()
            _out.close()
            _out = None


def emit(kind: str, domain: str, **fields: Any) -> Optional[int]:
    """Append one event and return its ``seq``.  No-op (None) unless
    :func:`enable` was called."""
    if _out is None:
        return None
    with _lock:
        if _out is None:
            return None
        _flush_polls()
        return _write(kind, domain, fields)


def emit_poll(kind: str, domain: str, key: Any, signature: Any,
              **fields: Any) -> None:
    """Like :func:`emit`, but folds hot identical repeats.

    Calls for the same *key* with an unchanged *signature* are written
    verbatim for the first :data:`POLL_THRESHOLD` occurrences, then counted and
    summarised as one ``repeat`` event the next time anything else is logged.
    """
    if _out is None:
        return
    with _lock:
        if _out is None:
            return
        now = round(time.monotonic() - _t0, 6)
        ent = _polls.get(key)
        if ent is not None and ent[0] == signature:
            ent[1] += 1
            if ent[1] > POLL_THRESHOLD:
                ent[2] += 1
                if ent[2] == 1:
                    ent[3] = now
                ent[4] = now
                return
        else:
            _polls[key] = [signature, 1, 0, now, now]
        _flush_polls(skip=key)
        _write(kind, domain, fields)


def _flush_polls(skip: Any = None) -> None:
    """Write pending ``repeat`` summaries (caller holds the lock)."""
    for key, ent in _polls.items():
        if key == skip or ent[2] == 0:
            continue
        _write("repeat", "tool", {"of": key if isinstance(key, str) else repr(key),
                                  "count": ent[2], "t_first": ent[3],
                                  "t_last": ent[4]})
        ent[2] = 0


def _write(kind: str, domain: str, fields: Dict[str, Any]) -> int:
    global _seq  # pylint: disable=global-statement
    assert _out is not None
    _seq += 1
    event: Dict[str, Any] = {
        "seq": _seq,
        "t": round(time.monotonic() - _t0, 6),
        "kind": kind,
        "domain": domain,
    }
    event.update(fields)
    _out.write(json.dumps(event, default=repr) + "\n")
    _out.flush()
    return _seq

