"""cProfile a representative firmware run to find throughput hotspots."""
from __future__ import annotations
import sys, cProfile, pstats, io, time as _wall
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config

N = int(sys.argv[1]) if len(sys.argv) > 1 else 300_000

fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments,
               sram_base=0x24000000, sram_size=0x80000, firmware_format=fw.format,
               firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
               stuck_loop_threshold=0, interrupt_stuck_threshold=0)
emu.boot_from_vector_table()
cfg = load_board_config(ROOT / "test/arducopter_with_bl.yaml")
apply_board_config(cfg, bus, emu, base_dir=ROOT / "test")
emu.import_snapshot(str(ROOT / "test/snap_i2c.snap"), name="s")
emu.load_snapshot("s")

# Warm up a touch so we profile steady-state, not snapshot-load.
emu.run(20_000)
i0 = emu.time.instructions
t0 = _wall.perf_counter()
pr = cProfile.Profile()
pr.enable()
emu.run(N)
pr.disable()
wall = _wall.perf_counter() - t0
di = emu.time.instructions - i0
print(f"\nran {di} instructions in {wall:.2f}s = {di/wall:,.0f} instr/s\n")
s = io.StringIO()
ps = pstats.Stats(pr, stream=s).sort_stats("tottime")
ps.print_stats(22)
print(s.getvalue())
