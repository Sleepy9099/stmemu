import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
from elf_symbols import parse_elf_symbols, resolve
fw = load_firmware(ROOT/"test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT/"cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000, sram_size=0x80000,
    firmware_format=fw.format, firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
    stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT/"test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT/"test")
emu.import_snapshot(str(ROOT/"test/snap_insinit.snap"), name="ins_init"); emu.load_snapshot("ins_init")
syms = parse_elf_symbols(ROOT/"test"/"arducopter.elf")
DT=0x0816CA4C
emu.add_breakpoint(DT)
emu.run(2_000_000)   # get to a do_transfer
print(f"at do_transfer, t={emu.time.cycles/1e6:.4f}s")
emu.remove_breakpoint(DT)
# sample PC over the gap in tiny chunks
import collections
samp=collections.Counter()
t0=emu.time.cycles
for _ in range(40):
    emu.run(3000)
    samp[resolve(syms, emu.pc|1)] += 1
dt=(emu.time.cycles-t0)/1e6
print(f"after 40 chunks: +{dt:.4f}s emulated")
print("PC distribution during gap:")
for label,c in samp.most_common(12):
    print(f"  {c:3d}x  {label}")
