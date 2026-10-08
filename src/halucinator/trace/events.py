"""JSONL log of domain crossings (see doc/tracing.md). Every call is a no-op until enable()."""
import json
import threading
import time
from typing import Any, Dict, Optional

POLL_THRESHOLD = 8  # identical consecutive calls before a poll is folded into a "repeat" event

_lock = threading.Lock()
_out = None
_seq = 0
_t0 = 0.0
_polls: Dict[str, list] = {}  # key -> [signature, run length, folded count]


def is_enabled() -> bool:
    return _out is not None


def enable(path: str) -> None:
    global _out, _seq, _t0  # pylint: disable=global-statement
    disable()
    _out, _seq, _t0 = open(path, "w", encoding="utf-8"), 0, time.monotonic()  # pylint: disable=consider-using-with
    _polls.clear()


def disable() -> None:
    global _out  # pylint: disable=global-statement
    with _lock:
        if _out:
            _flush()
            _out.close()
            _out = None


def emit(kind: str, **fields: Any) -> Optional[int]:
    """Log one event; returns its seq (None when disabled)."""
    return _emit(kind, fields)


def emit_poll(kind: str, key: str, signature: Any, **fields: Any) -> None:
    """Like emit, but identical repeats of *key* past POLL_THRESHOLD are only counted."""
    _emit(kind, fields, key, signature)


def _emit(kind: str, fields: Dict[str, Any], key: Optional[str] = None, sig: Any = None) -> Optional[int]:
    if _out is None:
        return None
    with _lock:
        if _out is None:
            return None
        if key is not None:
            run = _polls.get(key)
            if run and run[0] == sig:
                run[1] += 1
                if run[1] > POLL_THRESHOLD:
                    run[2] += 1
                    return None
            else:
                _flush()
                _polls[key] = [sig, 1, 0]
        _flush()
        return _write(kind, fields)


def _flush() -> None:
    """Write pending "repeat" summaries (caller holds the lock)."""
    for key, run in _polls.items():
        if run[2]:
            _write("repeat", {"of": key, "count": run[2]})
            run[2] = 0


def _write(kind: str, fields: Dict[str, Any]) -> int:
    global _seq  # pylint: disable=global-statement
    _seq += 1
    _out.write(json.dumps({"seq": _seq, "t": round(time.monotonic() - _t0, 6), "kind": kind,
                           **fields}, default=repr) + "\n")
    _out.flush()
    return _seq
