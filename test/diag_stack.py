"""Diagnostic: load a snapshot, run a bit, then scan a thread stack for
flash code addresses and resolve them to symbols. Reveals where a blocked
ChibiOS thread is parked (its on-stack return-address chain).

Usage:
  python test/diag_stack.py <snapshot.snap> <snap_name> [run_instr] [tickscale]
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator

from elf_symbols import parse_elf_symbols, resolve  # type: ignore


def main(argv: list[str]) -> int:
    snap_path = argv[1] if len(argv) > 1 else "test/snap_setup.snap"
    snap_name = argv[2] if len(argv) > 2 else "setup_entry"
    run_instr = int(argv[3]) if len(argv) > 3 else 2_000_000
    tick = int(argv[4]) if len(argv) > 4 else 1

    svd = ROOT / "cmsis-svd-stm32" / "stm32h7" / "STM32H743.svd"
    fw = load_firmware(ROOT / "test" / "arducopter_with_bl.bin", base_addr=0x08000000)
    device = load_svd(svd)
    bus, core = build_default_bus(build_address_map(device), flash_base=0x08000000)
    emu = Emulator(
        bus=bus, flash_base=0x08000000, firmware_segments=fw.segments,
        sram_base=0x24000000, sram_size=0x80000,
        firmware_format=fw.format, firmware_entry_point=fw.entry_point,
        core_peripheral=core, tick_scale=tick,
        stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000,
        stuck_loop_auto=False,
    )
    emu.boot_from_vector_table()
    from stmemu.board_config import load_board_config, apply_board_config
    cfg = load_board_config(ROOT / "test" / "arducopter_with_bl.yaml")
    apply_board_config(cfg, bus, emu, base_dir=ROOT / "test")
    emu.import_snapshot(str(ROOT / snap_path), name=snap_name)
    emu.load_snapshot(snap_name)
    print(f"loaded {snap_name}: pc=0x{emu.pc:08X}")

    emu.run(run_instr)
    print(f"after {run_instr} @tick={tick}: pc=0x{emu.pc:08X}")

    syms = parse_elf_symbols(ROOT / "test" / "arducopter.elf")

    def code_ptr(w: int) -> bool:
        return 0x08020000 <= (w & ~1) < 0x081DC000 and (w & 1) == 1

    # daemon_task pointer -> main thread_t. Scan the main thread stack
    # region for code return addresses.
    daemon_ptr = int.from_bytes(emu.mem_read(0x2400E910, 4), "little")
    print(f"daemon_task -> 0x{daemon_ptr:08X}")

    print("\n== main thread stack scan (0x24000600..0x24002200) ==")
    base, top = 0x24000600, 0x24002200
    data = emu.mem_read(base, top - base)
    last = None
    for off in range(0, len(data) - 4, 4):
        w = int.from_bytes(data[off:off + 4], "little")
        if code_ptr(w):
            label = resolve(syms, w)
            if label != last:
                print(f"  [sp+0x{off:04X}] 0x{w:08X}  {label}")
                last = label

    # Also resolve the live PC and current stacked frame.
    print(f"\nlive pc 0x{emu.pc:08X} -> {resolve(syms, emu.pc | 1)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
