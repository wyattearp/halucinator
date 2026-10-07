# Domain-crossing trace, map and replay

`halucinator --event-log run.jsonl ...` (or `HAL_EVENT_LOG=run.jsonl`) records
every point where execution or data crosses a domain boundary:

| kind | boundary |
|------|----------|
| `intercept` | emulated firmware -> Python bp_handler (logged when the handler returns) |
| `model_tx` / `model_rx` | peripheral model <-> external device over ZMQ |
| `irq` | external device -> firmware interrupt |
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

## Limits

* This is a record of *crossings*, not data flow: there is no taint tracking, so
  it shows that bytes went model -> device, not where they came from.
* The firmware domain is only visible at intercept boundaries; code running
  between two intercepts is not itself traced.
* Caller names use the nearest symbol below the return address (approximate).
