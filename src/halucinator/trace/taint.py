"""Handler-boundary taint: shadow memory over bp_handler reads and writes.

Bytes received from a device are tagged with their model_rx event number. A
handler that stores those bytes in guest memory records the tag (taint_src); a
handler that later reads tagged bytes out records a taint_sink. Firmware that
copies or parses the data between two handlers is not seen, so a tag with a
source but no sink is "lost in the firmware".
"""
import threading
from collections import deque
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from halucinator.trace import events

_lock = threading.Lock()
_pending: deque = deque(maxlen=65536)  # (byte, tag): received, not yet stored by a handler
_shadow: dict = {}                     # guest address -> tag


def payload_bytes(msg: Any) -> bytes:
    """Bytes carried by a model message (str/bytes/int/list under chars|data|char)."""
    val = next((msg[k] for k in ("chars", "data", "char") if isinstance(msg, dict) and k in msg), b"")
    if isinstance(val, str):
        return val.encode(errors="replace")
    if isinstance(val, int):
        return bytes([val & 0xFF])
    try:
        return bytes(val)
    except (TypeError, ValueError):
        return b""


def feed(tag: Optional[int], data: bytes) -> None:
    if tag is not None:
        with _lock:
            _pending.extend((b, tag) for b in data)


def on_write(handler: Optional[str], addr: int, data: bytes) -> None:
    adopted = None
    with _lock:
        idx = bytes(b for b, _ in _pending).find(data) if data else -1
        if idx >= 0:  # bytes queued before the match were never stored: drop them
            for _ in range(idx):
                _pending.popleft()
            adopted = [_pending.popleft() for _ in data]
        for i in range(len(data)):
            if adopted:
                _shadow[addr + i] = adopted[i][1]
            else:
                _shadow.pop(addr + i, None)  # overwritten with untainted data
    if adopted:
        events.emit("taint_src", handler=handler, addr=addr, len=len(data),
                    tags=sorted({t for _, t in adopted}))


def on_read(handler: Optional[str], addr: int, length: int) -> None:
    with _lock:
        hit = [_shadow[a] for a in range(addr, addr + length) if a in _shadow] if _shadow else []
    if hit:
        events.emit("taint_sink", handler=handler, addr=addr, len=length,
                    tags=sorted(set(hit)), tainted=len(hit))


@contextmanager
def watch(target: Any, handler: Optional[str]) -> Iterator[None]:
    """Report the handler's guest-memory reads and writes while it runs."""
    write, read = target.write_memory, target.read_memory

    def write_memory(addr: int, size: int, value: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(value, int):
            on_write(handler, addr, (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))
        elif isinstance(value, (bytes, bytearray)):
            on_write(handler, addr, bytes(value))
        return write(addr, size, value, *args, **kwargs)

    def read_memory(addr: int, size: int, num_words: int = 1, *args: Any, **kwargs: Any) -> Any:
        on_read(handler, addr, size * num_words)
        return read(addr, size, num_words, *args, **kwargs)

    target.write_memory, target.read_memory = write_memory, read_memory
    try:
        yield
    finally:
        del target.write_memory, target.read_memory
