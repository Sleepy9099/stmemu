import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
fw = load_firmware(ROOT/"test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT/"cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000, sram_size=0x80000,
    firmware_format=fw.format, firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
    stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT/"test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT/"test")
emu.import_snapshot(str(ROOT/"test/snap_insinit.snap"), name="ins_init"); emu.load_snapshot("ins_init")
t2 = bus.model_for_name("TIM2")
print("TIM2 model:", type(t2).__name__)
def reg(off): return t2.read_register_value(off)
for i in range(12):
    emu.run(50000)
    cr1=reg(0x00); dier=reg(0x0C); cnt=reg(0x24); psc=reg(0x28); arr=reg(0x2C); ccr1=reg(0x34)
    cu = t2.cycles_until_irq()
    busirq = bus.cycles_until_irq()
    ccdist = (ccr1 - cnt) & 0xFFFFFFFF
    print(f"[{i}] CEN={cr1&1} DIER=0x{dier:x}(UIE={dier&1},CC1IE={(dier>>1)&1}) cnt={cnt} ccr1={ccr1} (ccr1-cnt={ccdist}) arr={arr} psc={psc} | TIM2.cuI={cu} bus.cuI={busirq}")
