"""Event-log hook for bp_handler methods, applied once by the @bp_handler decorator.

Wrapping in the decorator (not at registration) keeps the function stored in
bp2handler_lut the same object the class exposes. A plain pass-through unless
an event log is enabled.
"""
from functools import wraps
from typing import Any, Callable, Dict, Optional

from halucinator.trace import events, taint

_symbols: Dict[int, str] = {}  # intercept address -> symbol, filled at registration


def note_symbol(addr: Optional[int], symbol: Optional[str]) -> None:
    if addr is not None and symbol:
        _symbols[addr] = symbol


def traced(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(self: Any, target: Any, bp_addr: int) -> Any:
        if not events.is_enabled():
            return func(self, target, bp_addr)
        sym = _symbols.get(bp_addr)
        try:
            args = [target.get_arg(i) & 0xFFFFFFFF for i in range(4)]
            lr = target.get_ret_addr() & 0xFFFFFFFF
        except Exception:  # noqa: BLE001 - tracing must never break dispatch
            args, lr = [], None
        with taint.watch(target, sym):
            result = func(self, target, bp_addr)
        ret = result[1] if isinstance(result, tuple) and isinstance(result[1], int) else None
        events.emit_poll("intercept", sym or hex(bp_addr), (args, ret, lr), sym=sym, pc=bp_addr,
                         lr=lr, args=args, ret=ret, cls=type(self).__name__,
                         module=type(self).__module__, fn=func.__name__)
        return result

    return wrapper
