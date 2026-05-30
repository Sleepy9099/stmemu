"""Pinpoint the Shared_DMA / bus-thread starvation that blocks gyro cal.

Loads a snapshot, runs with stall diagnostics + SPI1/I2C4/UART5 tracing,
then reports: stall verdict, disassembly around the top hot PCs (spin vs
park), the MAIN-thread stack backtrace (ChibiOS daemon_task region), and
per-bus trace activity.

  python test/diag_dma_stall.py [run_instr] [tick]
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
from elf_symbols import parse_elf_symbols, resolve  # type: ignore

run_instr = int(sys.argv[1]) if len(sys.argv) > 1 else 8_000_000
tick = int(sys.argv[2]) if len(sys.argv) > 2 else 10

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
emu.import_snapshot(str(ROOT / "test/snap_insinit.snap"), name="ins_init")
emu.load_snapshot("ins_init")

emu.enable_stall_diagnostics()
tr = emu.enable_tracing(sources=["SPI1", "I2C4", "UART5"])
print(f"running {run_instr} @tick={tick} from pc=0x{emu.pc:08X}")
emu.run(run_instr)
print(f"stopped at pc=0x{emu.pc:08X}\n")

syms = parse_elf_symbols(ROOT / "test" / "arducopter.elf")
res = lambda a: resolve(syms, a)  # noqa: E731

report = emu.diagnose_stall(as_text=False)
print(report.format(res))

# Disassemble around the hottest PCs to see whether they are a tight spin
# (branch-to-self / poll loop) or just a hot function body.
print("\n== disasm around top hot PCs ==")
for pc, cnt in report.hot_pcs[:3]:
    print(f"-- 0x{pc:08X} (x{cnt})  {res(pc | 1)}")
    try:
        code = emu.mem_read(pc - 8, 28)
        for ins in emu._disasm.disasm(code, pc - 8):
            mark = "  <<<" if (ins.address & ~1) == (pc & ~1) else ""
            print(f"   0x{ins.address:08X}  {ins.mnemonic:<8}{ins.op_str}{mark}")
    except Exception as e:
        print(f"   (disasm failed: {e})")

# Main thread (ChibiOS) stack scan — the active-thread backtrace above may be
# a transient thread; the main thread is where _init_gyro lives.
print("\n== main-thread stack scan (0x24000600..0x24002200) ==")
base, top = 0x24000600, 0x24002200
data = emu.mem_read(base, top - base)
last = None
for off in range(0, len(data) - 3, 4):
    w = int.from_bytes(data[off:off + 4], "little")
    if (w & 1) and 0x08000000 <= (w & ~1) < 0x081DB1C8:
        label = res(w)
        if label != last:
            print(f"  [+0x{off:04X}] 0x{w & ~1:08X}  {label}")
            last = label

print("\n== trace counts ==")
for k, v in sorted(tr.counts().items(), key=lambda kv: -kv[1]):
    print(f"  {k}: {v}")
print("\n== trace tail ==")
for ln in tr.dump().splitlines()[-16:]:
    print("  " + ln)
