# Domain-crossing trace, map and replay

`halucinator --event-log run.jsonl ...` (or `HAL_EVENT_LOG=run.jsonl`) records
every point where execution or data crosses a domain boundary:

| kind | boundary |
|------|----------|
| `intercept` | emulated firmware -> Python bp_handler (logged when the handler returns) |
| `model_tx` / `model_rx` | peripheral model <-> external device over ZMQ |
| `irq` | external device -> firmware interrupt |
| `data` | bytes a handler declares via `halucinator.trace.record_data()` |
| `repeat` | summary of an idle poll that repeated identical calls |

Handlers are bucketed as **stub** (nopped / canned return), **hle** (Python
replacement of a firmware or libc function) or **model** (device model).

```
hal_trace stats    run.jsonl
hal_trace map      run.jsonl -c bpv5_addrs.yaml -o map.svg          # or .png / .dot
hal_trace map      run.jsonl -c bpv5_addrs.yaml --from-t 17 --to-t 17.4 --hide-stubs -o i2c.svg
hal_trace timeline run.jsonl -c bpv5_addrs.yaml --skip printf_
hal_trace replay   run.jsonl -c bpv5_addrs.yaml --speed 0.1         # 10x slower; 0 = no delay
```

`-c` supplies a `symbols:` map so calling firmware functions are named from the
intercept's return address (nearest symbol below it, so approximate).

## Limits

* This is **not instruction-level taint.** `hal_trace flow` / `map --value-links`
  link a producer and consumer only when the *same bytes* appear on both sides.
  That is blind to firmware transforming data (the shell parsing the text
  `0xA0` into the byte 0xA0) and gives false positives on text streams, so it
  is off by default and ignores runs shorter than `--min-run` bytes.
* The firmware domain is only visible at intercept boundaries; code that runs
  between two intercepts is not itself traced.
