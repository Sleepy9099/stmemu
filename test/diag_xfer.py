import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
from elf_symbols import parse_elf_symbols
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
    c=sorted([(v,n) for v,s,n in syms if sub in n], key=lambda x:x[0]); return c[0][0]&~1 if c else None
RF=addr("BMI08814read_fifo_gyro"); DT=addr("9SPIDevice11do_transfer"); SUS=addr("osalThreadSuspendTimeoutS") or addr("ThreadSuspend")
print(f"read_fifo_gyro=0x{RF:08X} do_transfer=0x{DT and DT:08X} suspend={SUS and hex(SUS)}")
for a in (RF,DT):
    if a: emu.add_breakpoint(a)
last={}; hits=0
import sys as _s
for _ in range(4000):
    if hits>=24: break
    emu.run(200000)
    b=emu.last_pc_break
    if b is None: continue
    t=emu.time.cycles
    nm = "read_fifo_gyro" if b==RF else "do_transfer" if b==DT else hex(b)
    d = t-last.get(b,t)
    print(f"  {nm:16} t={t/1e6:9.4f}s  +{d/1e6:7.4f}s since last {nm}", flush=True)
    last[b]=t; hits+=1
