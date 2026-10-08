"""Event-log hook for bp_handler methods, applied once by the ``@bp_handler`` decorator.

Wrapping at decoration time (rather than at registration) keeps the handler
function stored in ``bp2handler_lut`` the very same object the class exposes,
and covers every dispatch path with one hook.  The wrapper is a plain
pass-through while no event log is enabled.
"""
from __future__ import annotations

import time
from functools import wraps
from typing import Any, Callable, Dict, Optional

from halucinator.trace import events, taint

_symbols: Dict[int, str] = {}   # intercept address -> symbol, filled at registration


def note_symbol(addr: Optional[int], symbol: Optional[str]) -> None:
    if addr is not None and symbol:
        _symbols[addr] = symbol


def traced(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(self: Any, target: Any, bp_addr: int) -> Any:
        if not events.is_enabled():
            return func(self, target, bp_addr)
        symbol = _symbols.get(bp_addr)
        args = []
        for idx in range(4):
            try:
                args.append(int(target.get_arg(idx)) & 0xFFFFFFFF)
            except Exception:  # noqa: BLE001 - tracing must never break dispatch
                break
        try:
            lr = int(target.get_ret_addr()) & 0xFFFFFFFF
        except Exception:  # noqa: BLE001
            lr = None
        start = time.monotonic()
        with taint.watch(target, symbol):
            result = func(self, target, bp_addr)
        bypass, ret = result if isinstance(result, tuple) else (None, None)
        ret_val = (int(ret) & 0xFFFFFFFF) if isinstance(ret, int) else None
        events.emit_poll(
            "intercept", "handler", symbol or hex(bp_addr), (tuple(args), ret_val, lr),
            sym=symbol, pc=bp_addr, lr=lr, args=args, cls=type(self).__name__,
            module=type(self).__module__, fn=func.__name__, bypass=bypass, ret=ret_val,
            dur_us=int((time.monotonic() - start) * 1e6))
        return result

    return wrapper
