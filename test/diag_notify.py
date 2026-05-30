import sys, struct; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
from elf_symbols import parse_elf_symbols
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1
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
def addr(sub):
    cands = sorted([(v,n) for v,s,n in syms if sub in n], key=lambda x:x[0])
    return cands[0][0] & ~1 if cands else None
g = addr("notify_new_gyro_raw_sample"); a = addr("notify_new_accel_raw_sample")
print(f"gyro_notify=0x{g:08X}  accel_notify=0x{a:08X}")
emu.add_breakpoint(g); emu.add_breakpoint(a)
gN=[]; aN=[]
for _ in range(400):
    if len(gN)>=20 and len(aN)>=20: break
    emu.run(300000)
    b = emu.last_pc_break
    if b is None: continue
    inst = emu.uc.reg_read(UC_ARM_REG_R0); ptr = emu.uc.reg_read(UC_ARM_REG_R1)
    try: x,y,z = struct.unpack("<fff", emu.mem_read(ptr & 0xFFFFFFFF, 12))
    except Exception: x=y=z=float('nan')
    (gN if b==g else aN).append((inst,x,y,z))
print(f"\n-- gyro notify samples ({len(gN)}) [instance, x, y, z] rad/s --")
for s in gN[:20]: print(f"  inst={s[0]}  ({s[1]:+.6f}, {s[2]:+.6f}, {s[3]:+.6f})")
print(f"\n-- accel notify samples ({len(aN)}) [instance, x, y, z] m/s^2 --")
for s in aN[:20]: print(f"  inst={s[0]}  ({s[1]:+.4f}, {s[2]:+.4f}, {s[3]:+.4f})")
