import sys, struct; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_R4
fw = load_firmware(ROOT/"test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT/"cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000, sram_size=0x80000,
    firmware_format=fw.format, firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
    stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT/"test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT/"test")
emu.import_snapshot(str(ROOT/"test/snap_insinit.snap"), name="ins_init"); emu.load_snapshot("ins_init")
LOOP_CHK=0x08062332
def v3(sp,off):
    raw=emu.mem_read((sp+off)&0xFFFFFFFF,12); return struct.unpack("<fff",raw)
emu.add_breakpoint(LOOP_CHK)
n=0
for _ in range(900):
    if n>=9: break
    emu.run(400000)
    if emu.last_pc_break != LOOP_CHK: continue
    sp=emu.uc.reg_read(UC_ARM_REG_SP)&0xFFFFFFFF
    j=struct.unpack('<i',emu.mem_read(sp+0x14,4))[0]
    ncv=int.from_bytes(emu.mem_read(sp+0x1c,4),'little')
    a0=v3(sp,0x120); a1=v3(sp,0x12c); d0=v3(sp,0x144); d1=v3(sp,0x150)
    import math
    ld0=math.sqrt(sum(x*x for x in d0)); ld1=math.sqrt(sum(x*x for x in d1))
    print(f"j={j:3d} ncv={ncv} | avg0=({a0[0]:+.5f},{a0[1]:+.5f},{a0[2]:+.5f}) |diff0|={ld0:.6f} | avg1=({a1[0]:+.5f},{a1[1]:+.5f},{a1[2]:+.5f}) |diff1|={ld1:.6f}  (thr=0.001745)")
    n+=1
