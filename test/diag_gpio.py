"""Count GPIO edge events per (port,pin) during a run from a snapshot.
The CS line of an actively-polled SPI device toggles frequently, so the
top-toggled pins reveal chip-select wiring without needing the hwdef."""
from __future__ import annotations
import sys
from collections import Counter
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config

run_instr = int(sys.argv[1]) if len(sys.argv) > 1 else 3_000_000

fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments,
               sram_base=0x24000000, sram_size=0x80000, firmware_format=fw.format,
               firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=1,
               stuck_loop_threshold=0, interrupt_stuck_threshold=0)
emu.boot_from_vector_table()
cfg = load_board_config(ROOT / "test/arducopter_with_bl.yaml")
apply_board_config(cfg, bus, emu, base_dir=ROOT / "test")
emu.import_snapshot(str(ROOT / "test/snap_setup.snap"), name="s")
emu.load_snapshot("s")

edges: Counter = Counter()
falls: Counter = Counter()

def on_edge(ev):
    p = ev.payload or {}
    key = f"{ev.source}.{p.get('pin')}"
    edges[key] += 1
    if p.get("falling"):
        falls[key] += 1

bus.subscribe("gpio_edge", on_edge)
emu.run(run_instr)

print(f"after {run_instr} instr, pc=0x{emu.pc:08X}")
print("\nTop GPIO pins by edge count (port.pin: edges / falling):")
for key, n in edges.most_common(20):
    print(f"  {key:12s} edges={n:6d} falling={falls.get(key,0)}")
