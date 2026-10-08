"""Taint: shadow memory over bp_handler accesses, plus instruction-level propagation.

Bytes received from a device are tagged with their model_rx event number. A
handler that stores those bytes in guest memory records the tag (taint_src); a
handler that later reads tagged bytes (or receives a tagged register argument)
records a taint_sink.

On a Unicorn Cortex-M target, arm() adds a per-instruction hook so the tag also
follows the data through firmware code: loads and stores move it between shadow
memory and registers, ALU ops union their source registers. The firmware
instructions it passes through are logged as taint_code. Not followed: control
dependence (a branch on tainted data), tainted pointers, and handlers that copy
memory on the firmware's behalf (memcpy intercepts).
"""
import threading
from collections import deque
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

import capstone
from capstone import arm_const as A
from unicorn import unicorn_const

from halucinator.trace import events

_lock = threading.Lock()
_pending: deque = deque(maxlen=65536)  # (byte, tag): received, not yet stored by a handler
_shadow: Dict[int, frozenset] = {}     # guest address -> tags
_rt: Dict[int, frozenset] = {}         # capstone register id -> tags (instruction level)
_touched: Dict[int, Dict[int, None]] = {}  # tag -> instruction addresses it passed, in order
_NONE: frozenset = frozenset()


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
                _shadow[addr + i] = frozenset((adopted[i][1],))
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
                    tags=sorted(_NONE.union(*hit)), tainted=len(hit))


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

    def get_arg(idx: int, *args: Any, **kwargs: Any) -> Any:  # a register argument is read here
        tags = _rt.get(_ARG_REGS[idx], _NONE) if 0 <= idx < 4 else _NONE
        if tags:
            events.emit("taint_sink", handler=handler, reg=True, tags=sorted(tags), tainted=1, len=1)
        return orig_get_arg(idx, *args, **kwargs)

    _enter(target)
    orig_get_arg = getattr(target, "get_arg", None)
    target.write_memory, target.read_memory = write_memory, read_memory
    if orig_get_arg:
        target.get_arg = get_arg
    try:
        yield
    finally:
        del target.write_memory, target.read_memory
        if orig_get_arg:
            del target.get_arg
        _rt.pop(A.ARM_REG_R0, None)  # the return value is not tainted; memory the handler wrote is seen above
        if _shadow:
            arm(target)


# --- instruction level (Unicorn, Cortex-M/Thumb) -----------------------------------------
_md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
_md.detail = True
_SKIP = (A.ARM_REG_CPSR, A.ARM_REG_PC)  # flags and pc are not tracked
_decoded: Dict[int, tuple] = {}   # address -> (kind, reads, writes, data regs, destination regs)
_cur: Optional[list] = None       # instruction in flight: [address, decoded, source taint, memory-read taints]
_armed_uc = None
_ARG_REGS = (A.ARM_REG_R0, A.ARM_REG_R1, A.ARM_REG_R2, A.ARM_REG_R3)


def _decode(code: bytes, address: int) -> tuple:
    insn = next(_md.disasm(code, address), None)
    if insn is None:
        return ("op", (), (), (), ())
    name = insn.mnemonic
    kind = "ld" if name.startswith(("ldr", "ldm", "pop")) else "st" if name.startswith(("str", "stm", "push")) else "op"
    regs = [o for o in insn.operands if o.type == A.ARM_OP_REG][name.startswith(("ldm", "stm")):]  # first is the base
    reads, writes = (tuple(r for r in rw if r not in _SKIP) for rw in insn.regs_access())
    return (kind, reads, writes, tuple(o.reg for o in regs if o.access & 1 and o.reg not in _SKIP),
            tuple(o.reg for o in regs if o.access & 2 and o.reg not in _SKIP))


def _set_reg(reg: int, tags: frozenset) -> None:
    if tags:
        _rt[reg] = tags
    else:
        _rt.pop(reg, None)


def _finish() -> None:
    """Apply the register effects of the instruction that just ran."""
    global _cur  # pylint: disable=global-statement
    if _cur is None:
        return
    address, (kind, reads, writes, _, dsts), tags, loaded = _cur
    _cur = None
    if kind == "ld":
        for k, reg in enumerate(dsts):
            _set_reg(reg, loaded[k] if k < len(loaded) else _NONE)
        tags = _NONE.union(*loaded)
    elif kind == "op":
        for reg in writes:
            _set_reg(reg, tags)
    for tag in tags:
        _touched.setdefault(tag, {})[address] = None


def _on_code(uc: Any, address: int, size: int, _: Any) -> None:
    global _cur  # pylint: disable=global-statement
    _finish()
    if not _shadow and not _rt:
        return  # nothing is tainted anywhere: skip decoding
    info = _decoded.get(address)
    if info is None:
        info = _decoded[address] = _decode(bytes(uc.mem_read(address, size)), address)
    kind, reads, _, data, _ = info
    _cur = [address, info, _NONE.union(*(_rt.get(r, _NONE) for r in (reads if kind == "op" else ()))), []]


def _on_read(uc: Any, access: int, address: int, size: int, value: int, _: Any) -> None:
    if _cur and _cur[1][0] == "ld":
        _cur[3].append(_NONE.union(*(_shadow.get(a, _NONE) for a in range(address, address + size))))


def _on_write(uc: Any, access: int, address: int, size: int, value: int, _: Any) -> None:
    if _cur and _cur[1][0] == "st":
        data, stored = _cur[1][3], _cur[3]
        tags = _rt.get(data[len(stored)], _NONE) if len(stored) < len(data) else _NONE
        stored.append(tags)
        for a in range(address, address + size):
            if tags:
                _shadow[a] = tags
            else:
                _shadow.pop(a, None)
        for tag in tags:
            _touched.setdefault(tag, {})[_cur[0]] = None


def arm_uc(uc: Any) -> None:
    """Install the per-instruction hooks on a Unicorn instance (once)."""
    global _armed_uc  # pylint: disable=global-statement
    if uc is _armed_uc:
        return
    _armed_uc = uc
    uc.hook_add(unicorn_const.UC_HOOK_CODE, _on_code)
    uc.hook_add(unicorn_const.UC_HOOK_MEM_READ, _on_read)
    uc.hook_add(unicorn_const.UC_HOOK_MEM_WRITE, _on_write)
    uc.ctl_flush_tb()  # code translated before the hooks existed must be retranslated


def arm(target: Any) -> None:
    if getattr(target, "_uc", None) is not None and str(getattr(target, "arch_name", "")).startswith("cortex-m"):
        arm_uc(target._uc)  # pylint: disable=protected-access


def _enter(target: Any) -> None:
    """Firmware -> handler: settle the last instruction and log the code the taint passed through."""
    global _cur  # pylint: disable=global-statement
    if _cur is not None:
        try:
            phantom = _cur[0] == target.read_register("pc") & ~1  # the breakpoint instruction never ran
        except Exception:  # noqa: BLE001
            phantom = False
        if phantom:
            _cur = None
        _finish()
    for tag, pcs in _touched.items():
        events.emit("taint_code", tag=tag, pcs=list(pcs)[:2000])
    _touched.clear()
