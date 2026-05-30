import sys, struct; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
from elf_symbols import parse_elf_symbols, resolve
from unicorn.arm_const import UC_ARM_REG_R8, UC_ARM_REG_R2
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
def rd(a,n): 
    try: return emu.mem_read(a&0xFFFFFFFF,n)
    except Exception: return b"\x00"*n
def u32(a): return int.from_bytes(rd(a,4),"little")
def u64(a): return int.from_bytes(rd(a,8),"little")
BP=0x08176974
emu.add_breakpoint(BP)
seen={}
for _ in range(3000):
    if len(seen)>=4: break
    emu.run(120000)
    if emu.last_pc_break != BP: continue
    binfo=emu.uc.reg_read(UC_ARM_REG_R8)&0xFFFFFFFF
    delay=emu.uc.reg_read(UC_ARM_REG_R2)&0xFFFF
    if binfo in seen and seen[binfo][0]>=3:
        continue
    seen.setdefault(binfo,[0,[]]); seen[binfo][0]+=1
    cbs=[]
    cb=u32(binfo+0x20); guard=0
    while cb and guard<8:
        period=u32(cb+0xc); meth=u32(cb+8)
        cbs.append((period, resolve(syms, meth|1)))
        cb=u32(cb); guard+=1
    seen[binfo][1]=cbs
    print(f"DeviceBus 0x{binfo:08X}  delay={delay}us  callbacks:")
    for p,m in cbs: print(f"    period={p:7d}us  {m}")
