"""
Level-1 taint: shadow memory at the handler boundary.

Bytes that arrive from an external device (``model_rx``) are tagged with that
event's ``seq``.  When a bp_handler then writes those same bytes into guest
memory the shadow map records the tag (``taint_src``); when a handler later
reads tagged bytes back out of guest memory (``taint_sink``) the path
input -> output is recorded.

Only handler memory accesses are watched.  Firmware that copies or transforms
the data between two handlers is invisible here, so a tag that has a source
but no sink means "lost somewhere in the firmware" -- by design that is the
cue to look at the map.
"""
from __future__ import annotations

import threading
from collections import deque
from contextlib import contextmanager
from typing import Any, Deque, Dict, Iterator, Optional, Tuple

from halucinator.trace import events

_MAX_PENDING = 65536
_lock = threading.Lock()
_pending: Deque[Tuple[int, int]] = deque()  # (byte, tag): received, not yet in guest memory
_shadow: Dict[int, int] = {}                # guest address -> tag


def reset() -> None:
    with _lock:
        _pending.clear()
        _shadow.clear()


def payload_bytes(msg: Any) -> bytes:
    """The raw bytes carried by a model message, or b'' if it has none."""
    if not isinstance(msg, dict):
        return b""
    for key in ("chars", "data", "char"):
        val = msg.get(key)
        if isinstance(val, str):
            return val.encode(errors="replace")
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
        if isinstance(val, int) and 0 <= val < 256:
            return bytes([val])
        if isinstance(val, (list, tuple)) and all(isinstance(v, int) and 0 <= v < 256 for v in val):
            return bytes(val)
    return b""


def feed(tag: Optional[int], data: bytes) -> None:
    """Queue freshly received bytes; they are tagged once a handler stores them."""
    if tag is None or not data:
        return
    with _lock:
        _pending.extend((b, tag) for b in data)
        while len(_pending) > _MAX_PENDING:
            _pending.popleft()


def on_write(handler: Optional[str], addr: int, data: bytes) -> None:
    adopted = None
    with _lock:
        if data and _pending:
            idx = bytes(b for b, _ in _pending).find(data)
            if idx >= 0:  # stale bytes before the match are dropped
                for _ in range(idx):
                    _pending.popleft()
                adopted = [_pending.popleft() for _ in range(len(data))]
        for i in range(len(data)):
            if adopted:
                _shadow[addr + i] = adopted[i][1]
            else:
                _shadow.pop(addr + i, None)  # overwritten with untainted data
    if adopted:
        events.emit("taint_src", "handler", handler=handler, addr=addr, len=len(data),
                    tags=sorted({t for _, t in adopted}))


def on_read(handler: Optional[str], addr: int, length: int) -> None:
    if not _shadow:
        return
    with _lock:
        hit = [_shadow[a] for a in range(addr, addr + length) if a in _shadow]
    if hit:
        events.emit("taint_sink", "handler", handler=handler, addr=addr, len=length,
                    tags=sorted(set(hit)), tainted=len(hit))


@contextmanager
def watch(target: Any, handler: Optional[str]) -> Iterator[None]:
    """Report this handler's guest-memory reads and writes while it runs."""
    orig = {n: getattr(target, n) for n in ("write_memory", "read_memory")}
    shadowed = {n: n in getattr(target, "__dict__", {}) for n in orig}

    def write_memory(addr: int, size: int, value: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(value, int) and 0 < size <= 8:
            data = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")
        elif isinstance(value, (bytes, bytearray)):
            data = bytes(value)
        else:
            data = b""
        on_write(handler, addr, data)
        return orig["write_memory"](addr, size, value, *args, **kwargs)

    def read_memory(addr: int, size: int, num_words: int = 1, *args: Any, **kwargs: Any) -> Any:
        on_read(handler, addr, size * num_words)
        return orig["read_memory"](addr, size, num_words, *args, **kwargs)

    try:
        target.write_memory, target.read_memory = write_memory, read_memory
    except AttributeError:  # target forbids instance attributes: run unwatched
        yield
        return
    try:
        yield
    finally:
        for name, fn in orig.items():
            if shadowed[name]:
                setattr(target, name, fn)
            else:
                delattr(target, name)
