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
emu.add_breakpoint(0x0806280A)   # return into AP_InertialSensor::init after _init_gyro -> cal done
t0 = emu.time.cycles; done = 0
while done < 60_000_000:
    emu.run(4_000_000); done += 4_000_000
    dt = (emu.time.cycles - t0)/1e6
    print(f"[{done:>9}] emu_t=+{dt:8.3f}s  pc=0x{emu.pc:08X}  brk={emu.last_pc_break and hex(emu.last_pc_break)}", flush=True)
    if emu.last_pc_break == 0x0806280A:
        print("CAL EXITED (gyro calibration returned)"); break
print(f"done; emulated +{(emu.time.cycles-t0)/1e6:.3f}s in {done} instr")
