"""Dogfood the stall analyzer + transaction tracer on a real firmware stall.

  python test/diag_stall_trace.py <snap> <name> [run_instr] [tick] [sources]

Loads a snapshot, turns on stall diagnostics + (optionally filtered) bus
tracing, runs, then prints the stall report (symbol-enriched via the ELF
crutch when present) and a decoded trace summary. Replaces hand-rolled
exchange()/stack-scan diagnostics with the built-in tooling.
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "test"))

from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config

snap = sys.argv[1] if len(sys.argv) > 1 else "test/snap_insinit.snap"
name = sys.argv[2] if len(sys.argv) > 2 else "ins_init"
run_instr = int(sys.argv[3]) if len(sys.argv) > 3 else 6_000_000
tick = int(sys.argv[4]) if len(sys.argv) > 4 else 10
sources = sys.argv[5].split(",") if len(sys.argv) > 5 else None

fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments,
               sram_base=0x24000000, sram_size=0x80000, firmware_format=fw.format,
               firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=tick,
               stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000,
               stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT / "test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT / "test")
emu.import_snapshot(str(ROOT / snap), name=name)
emu.load_snapshot(name)

emu.enable_stall_diagnostics()
tr = emu.enable_tracing(sources=sources)
print(f"loaded {name}: pc=0x{emu.pc:08X}; running {run_instr} @tick={tick}; trace sources={sources}")
emu.run(run_instr)
print(f"stopped at pc=0x{emu.pc:08X}\n")

# Optional symbol enrichment (ELF crutch — never required by the tools).
resolver = None
elf = ROOT / "test" / "arducopter.elf"
if elf.exists():
    from elf_symbols import parse_elf_symbols, resolve  # type: ignore
    _syms = parse_elf_symbols(elf)
    resolver = lambda a: resolve(_syms, a)  # noqa: E731

print(emu.diagnose_stall(resolver=resolver))

print("\n== trace counts ==")
for k, v in sorted(tr.counts().items(), key=lambda kv: -kv[1]):
    print(f"  {k}: {v}")

print("\n== trace sample (first 12 + last 12) ==")
lines = tr.dump().splitlines()
for ln in lines[:12]:
    print("  " + ln)
if len(lines) > 24:
    print("  ...")
for ln in lines[-12:]:
    print("  " + ln)
