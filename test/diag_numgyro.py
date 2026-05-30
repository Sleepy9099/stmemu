import sys, struct; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
from unicorn.arm_const import UC_ARM_REG_R0
fw = load_firmware(ROOT/"test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT/"cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000, sram_size=0x80000,
    firmware_format=fw.format, firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
    stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT/"test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT/"test")
emu.import_snapshot(str(ROOT/"test/snap_insinit.snap"), name="ins_init"); emu.load_snapshot("ins_init")
emu.add_breakpoint(0x08062044)
emu.run(8_000_000)
if emu.last_pc_break == 0x08062044:
    this = emu.uc.reg_read(UC_ARM_REG_R0) & 0xFFFFFFFF
    print(f"_init_gyro entry: this(INS)=0x{this:08X}")
    fields = emu.mem_read(this+0x260, 0x20)
    print("bytes[0x260..0x280]:", fields.hex())
    print(f"  num_gyros [+0x268] = {fields[0x268-0x260]}")
    print(f"  [+0x269] = {fields[0x269-0x260]}  [+0x26a]={fields[0x26a-0x260]}  [+0x26b]={fields[0x26b-0x260]}")
else:
    print("did not hit _init_gyro entry; pc=0x%08X" % emu.pc)
