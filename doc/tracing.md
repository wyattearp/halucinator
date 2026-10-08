# Domain-crossing trace, map and replay

`halucinator --event-log run.jsonl ...` (or `HAL_EVENT_LOG=run.jsonl`) records
every point where execution or data crosses a domain boundary:

| kind | boundary |
|------|----------|
| `intercept` | emulated firmware -> Python bp_handler (logged when the handler returns) |
| `model_tx` / `model_rx` | peripheral model <-> external device over ZMQ |
| `irq` | external device -> firmware interrupt |
| `taint_src` / `taint_sink` | a handler stored tagged input bytes in guest memory / read tagged bytes back out |
| `repeat` | summary of an idle poll that repeated identical calls |

Handlers are bucketed as **stub** (nopped / canned return), **hle** (Python
replacement of a firmware or libc function) or **model** (device model).

```
hal_trace stats    run.jsonl
hal_trace map      run.jsonl -c bpv5_addrs.yaml -o map.svg          # or .png / .dot
hal_trace map      run.jsonl -c bpv5_addrs.yaml --from-t 17 --to-t 17.4 --hide-stubs -o i2c.svg
hal_trace timeline run.jsonl -c bpv5_addrs.yaml --skip printf_
hal_trace timeline run.jsonl -c bpv5_addrs.yaml --speed 0.1        # replay, 10x slower; 0 = no delay
```

`-c` supplies a `symbols:` map so calling firmware functions are named from the
intercept's return address (nearest symbol below it, so approximate).

## Taint (handler-boundary)

Bytes from an external device are tagged with their `model_rx` event number.
When a bp_handler stores them in guest memory (`taint_src`) and another handler
later reads them back (`taint_sink`), the path is recorded.

```
hal_trace taint run.jsonl        # per input: stored by / read out by / LOST
hal_trace map   run.jsonl ...    # red dashed edges; red-bordered nodes = taint ends here
```

Only handler memory accesses are watched. Where firmware itself copies or parses
the data between two handlers (e.g. the bpv5 shell consuming typed keystrokes),
the tag is reported **LOST** and the map shows a red "taint ends here" node: that
is where the data left the traceable boundary. Input is matched to the handler
that stores it by exact byte equality against bytes received but not yet stored.

## Limits

* No instruction-level taint, so firmware-internal data flow is not followed.
* The firmware domain is only visible at intercept boundaries; code running
  between two intercepts is not itself traced.
* Caller names use the nearest symbol below the return address (approximate).
* MMIO-mapped peripherals (e.g. the bpv5 NMEA UART source) bypass handlers, so
  their data is neither logged nor tagged.
