# Domain-crossing trace, map and taint

`halucinator --event-log run.jsonl ...` (or `HAL_EVENT_LOG=run.jsonl`) writes one JSON line per
crossing between domains: `intercept` (firmware -> Python bp_handler), `model_tx` / `model_rx`
(peripheral model <-> external device over ZMQ), `irq`, plus `taint_src` / `taint_sink` and
`repeat` (idle polls folded into a count). Handlers are drawn as **stub** (nopped / canned
return), **hle** (Python replacement of a firmware function) or **model** (device model).

```
hal_trace map      run.jsonl -c addrs.yaml -o map.svg      # or .png / .dot
hal_trace map      run.jsonl -c addrs.yaml --from-t 17 --to-t 17.4 --hide-stubs -o i2c.svg
hal_trace timeline run.jsonl -c addrs.yaml --skip printf_  # add --speed 0.1 to replay 10x slower
hal_trace taint    run.jsonl                               # input -> output paths, or LOST
```

`-c` supplies a `symbols:` map so the calling firmware function is named from the intercept's
return address (nearest symbol below it, so approximate).

## Taint

Bytes from a device are tagged with their `model_rx` event number. A handler that stores them in
guest memory records the tag; a handler that later reads them out is the sink. The map shows this
as red dashed edges, and a red-bordered "taint ends here" node where a tag arrives but never leaves.

Only handler memory accesses are seen. When firmware itself copies or parses the data between two
handlers (the bpv5 shell consuming typed keystrokes) the tag is reported **LOST**: that is where
the data left the traceable boundary. The shadow map cannot see firmware overwriting memory, so a reused address keeps a stale tag:
a read-out like `1/64 B` is probably that, not a real flow. Memory-mapped peripherals (the bpv5 NMEA UART source)
bypass handlers, so their data is neither logged nor tagged. Firmware between two intercepts is
not traced.
