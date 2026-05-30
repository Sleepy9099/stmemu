import sys, struct; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
from unicorn.arm_const import UC_ARM_REG_S0, UC_ARM_REG_SP, UC_ARM_REG_R4, UC_ARM_REG_R3
fw = load_firmware(ROOT/"test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT/"cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000, sram_size=0x80000,
    firmware_format=fw.format, firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
    stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT/"test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT/"test")
emu.import_snapshot(str(ROOT/"test/snap_insinit.snap"), name="ins_init"); emu.load_snapshot("ins_init")
ACCEL_CHK=0x08062236   # vcmpe s0(accel_diff), s20(0.2)
LOOP_CHK=0x08062332    # ldr r3,[sp,#0x1c](num_converged); cmp r3,r4(num_gyros)
def f32(reg): 
    import struct as _s; return _s.unpack("<f", _s.pack("<I", emu.uc.reg_read(reg)&0xFFFFFFFF))[0]
emu.add_breakpoint(ACCEL_CHK); emu.add_breakpoint(LOOP_CHK)
n=0
for _ in range(800):
    if n>=24: break
    emu.run(400000)
    b=emu.last_pc_break
    if b is None: continue
    sp=emu.uc.reg_read(UC_ARM_REG_SP)&0xFFFFFFFF
    if b==ACCEL_CHK:
        print(f"  ACCEL_DIFF metric s0 = {f32(UC_ARM_REG_S0):.6f}   (skip if > 0.2)"); n+=1
    elif b==LOOP_CHK:
        ncv=int.from_bytes(emu.mem_read(sp+0x1c,4),'little'); ng=emu.uc.reg_read(UC_ARM_REG_R4)&0xFF
        j=struct.unpack('<i',emu.mem_read(sp+0x14,4))[0]
        print(f"  LOOP: num_converged={ncv} num_gyros={ng} j={j}"); n+=1
