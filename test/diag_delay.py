import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
from elf_symbols import parse_elf_symbols, resolve
from unicorn.arm_const import UC_ARM_REG_R1, UC_ARM_REG_LR
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
DM=0x0816D2C0; BT0=0x081768C0; BT1=BT0+216
emu.add_breakpoint(DM)
busn=0; othern=0
for _ in range(8000):
    if busn>=20: break
    emu.run(120000)
    if emu.last_pc_break != DM: continue
    r1=emu.uc.reg_read(UC_ARM_REG_R1); lr=emu.uc.reg_read(UC_ARM_REG_LR)&~1
    if BT0<=lr<BT1:
        print(f"  BUS_THREAD delay_us = {r1}", flush=True); busn+=1
    else:
        othern+=1
print(f"\nbus_thread delay calls={busn}  other-caller delay calls={othern}")
