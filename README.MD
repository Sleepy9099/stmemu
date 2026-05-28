# stmemu

`stmemu` is a Cortex-M oriented STM emulator scaffold built on Unicorn + CMSIS-SVD.

It is designed for firmware bring-up, bootloader reversing, and iterative command-driven emulation runs.

## Current Capabilities

- Firmware loading:
  - raw `.bin` at configurable base address
  - ELF with segment-aware mapping
- Boot flow:
  - vector-table boot (MSP + Reset_Handler)
- MMIO model:
  - CMSIS-SVD parsing and address map construction
  - peripheral bus + model factory (generic + specialized models)
- Debug/control surface:
  - register/memory/peripheral read/write
  - PC breakpoints and MMIO breakpoints
  - generic watchpoints (`r/w/x`) for memory ranges
  - snapshots (`save/load/diff`) and checkpoint/reload workflow
  - trace modes (all, mmio-only, call/return, branch, register deltas)
  - fault/exception report with stacked context
  - PC-triggered actions (`atpc`, `ret`, `skip`, `stub`)
- Automation/artifacts:
  - scenario scripts (`include`, `wait`, `assert`, regular shell commands)
  - export (`pcprof`, `mmioprof`, `trace`, `snapdiff`) to JSON/CSV/TXT
  - session command logging (`log start/run/note/stop`)
- UART workflow helpers:
  - RX/TX injection and inspection
  - transfer helpers (`xfer`, `waittx`, `sweep`, `sweepfile`)
  - file-backed large payload I/O (`@file`, `hex@file`, `txsave`)

## Install

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

## CLI

```bash
stmemu <image.bin|image.elf> --svd <device.svd> [options]
```

Important options:

- `--base <addr>`: base for raw `.bin` images (ignored for ELF)
- `--sram-base <addr>`, `--sram-size <bytes>`
- `--tick-scale <n>`: peripheral/core ticks per instruction
- `--stuck-threshold <n>`, `--interrupt-stuck-threshold <n>`, `--stuck-manual`
- `--shell`: enter interactive shell after startup commands
- `--cfg <file>`: startup script file, or YAML/JSON scenario config with `target`, `emulator`, board, events, and `startup_commands`
- `--cmd "<c1; c2; ...>"`: one-shot semicolon command chain
- `--log-level`, `--quiet`

## Usage Modes

### 1) Interactive Shell

```bash
stmemu test/Pixhawk6C_bl.elf --svd path/to/STM32H743.svd --shell
```

### 2) Batch Run via `--cmd`

```bash
stmemu fw.elf --svd dev.svd --cmd "regs; run 100000; fault show"
```

### 3) Startup Harness via `--cfg`

`--cfg` can be a newline/semicolon command script, or a YAML/JSON scenario config. In YAML/JSON configs, `target.svd` can provide the SVD path before the emulator starts. `--cfg` startup commands execute first, then `--cmd`.

```bash
stmemu fw.elf --svd dev.svd --cfg scripts/startup.cmd --cmd "scenario run scripts/case1.scn"
```

```yaml
# test/Pixhawk6C_bl_smoke.yaml
target:
  svd: cmsis-svd-stm32/stm32h7/STM32H743.svd
  sram_size: 0x80000

emulator:
  bus_policy: permissive

startup_commands:
  - mmioprof 250000 20
  - pcprof 250000 10
  - fault show
```

Place the local CMSIS-SVD checkout under `cmsis-svd-stm32/`, or set `STMEMU_STM32H743_SVD` when running the Pixhawk smoke test.

### 4) Scenario Script Execution

```text
# scripts/case1.scn
reg set pc 0x08000438
wait pc 0x080006B8 200000
uart rx UART7 2120
run 1000000
assert out contains 1210
```

Run with:

```bash
stmemu fw.elf --svd dev.svd --cmd "scenario run scripts/case1.scn"
```

## Shell Command Groups

- Execution/state: `regs`, `reg`, `run`, `step`, `fault`, `trace`, `stuck`, `tickscale`
- Memory/peripherals: `mem`, `periph`, `addr2reg`, `mmio`, `irq`, `image`, `vtbl`
- Break/control: `bp`, `bl`, `bc`, `wp`, `atpc`, `ret`, `skip`, `stub`
- Snapshots/testing: `snap`, `checkpoint`, `reload`, `repeat`, `test`
- Profiling/export: `pcprof`, `mmioprof`, `export`
- Scripting/logging: `scenario`, `log`
- UART: `uart list|status|rx|tx|txsave|waittx|xfer|sweep|sweepfile`

## Large I/O Specs (`mem` and `uart`)

Where payload specs are accepted:

- inline hex: `2120`
- binary file bytes: `@payload.bin`
- text-hex file: `hex@payload.txt`

Examples:

```bash
# memory
mem load 0x20000000 input.bin
mem save 0x20000000 0x100 dump.bin
mem w 0x20000100 @chunk.bin
mem w 0x20000200 hex@chunk_hex.txt

# uart
uart rx UART7 @cmd.bin
uart xfer UART7 2120 1000000 expect 1210 clear
uart txsave UART7 out.bin clear
```

## Bootloader Command Sweep Workflow

Typical repeatable loop:

```text
ret 0x08002A30 0
run 5000000
checkpoint ready
uart sweep UART7 ready 1000000 2120 220120 220220 220320
```

Or file-driven:

```text
# boot_cmds.txt
2120 => 1210
220120 ~> 05000000
220220 ~> 38000000
220320 ~> 00000000
```

```text
uart sweepfile UART7 ready 1000000 boot_cmds.txt
```

`=>` means exact expected TX, `~>` means expected TX prefix.

## Test/Dev

```bash
python -m compileall src/stmemu
python -m unittest test.test_loader test.test_shell_commands
```
