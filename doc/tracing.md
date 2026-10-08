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
guest memory records the tag (`taint_src`); a handler that later reads tagged bytes, or reads a
tagged register argument through `get_arg`, is the sink (`taint_sink`).

On a **Unicorn Cortex-M** target a per-instruction hook (armed after the first tagged byte is
stored) also follows the tag through firmware: loads and stores move it between shadow memory and
registers, ALU ops union their source registers, constants clear it. The firmware instructions it
passes through are logged as `taint_code` and drawn as red dashed edges through the functions that
touched it (in order of first contact; this is not the call graph). A red-bordered node marks where
a tag arrives but never leaves.

```
hal_trace taint run.jsonl -c addrs.yaml   # per input: stored by / passed through / read out by, or LOST
```

Example, bpv5 I2C: typed `[0xA0 0x00 [0xA1 r:2]` passes through the shell's command-line parser and
reaches `pio_i2c_write_timeout` carrying 3 of 3 bytes.

## Limits

* Not followed: control dependence (a branch on tagged data), tagged pointers/indices, IT-block
  conditional execution, and handlers that copy memory for the firmware (e.g. a memcpy intercept).
  Over-tainting is possible; a read-out like `1/64 B` is probably stale taint, since firmware
  overwriting memory is only seen while the instruction hook is armed.
* Other backends and architectures get handler-boundary taint only.
* Memory-mapped peripherals (the bpv5 NMEA UART source) bypass handlers, so their data is neither
  logged nor tagged. Firmware between two intercepts is only seen through `taint_code`.
* Caller and function names use the nearest symbol below an address (approximate); addresses
  below the first symbol (boot ROM) show as `<unknown caller>`.
