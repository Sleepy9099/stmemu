import sys; from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT/"src")); sys.path.insert(0, str(ROOT/"test"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config
tick = int(sys.argv[1]) if len(sys.argv) > 1 else 1
budget = int(sys.argv[2]) if len(sys.argv) > 2 else 50_000_000
fw = load_firmware(ROOT/"test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT/"cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000, sram_size=0x80000,
    firmware_format=fw.format, firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=tick,
    stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT/"test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT/"test")
emu.import_snapshot(str(ROOT/"test/snap_insinit.snap"), name="ins_init"); emu.load_snapshot("ins_init")
tr = emu.enable_tracing(sources=["SPI1","UART5"])
MILES = {0x0806280A:"CAL_EXIT", 0x08053C25:"AP_GPS::update", 0x08043471:"alloc_error(FATAL)", 0x080528ED:"GPS_detect"}
for a in MILES: emu.add_breakpoint(a)
t0 = emu.time.cycles; done = 0; gps_at = None
print(f"tick_scale={tick} budget={budget} from pc=0x{emu.pc:08X}", flush=True)
while done < budget:
    emu.run(4_000_000); done += 4_000_000
    c = tr.counts()
    gyro = c.get("SPI1 imu_bmi088_g", 0); uart = sum(v for k,v in c.items() if k.startswith("UART5"))
    et = (emu.time.cycles - t0)/1e6
    brk = emu.last_pc_break
    tag = MILES.get(brk) if brk else ""
    print(f"[{done:>9}] et=+{et:7.2f}s pc=0x{emu.pc:08X} gyroRd={gyro} uart={uart} brk={tag}", flush=True)
    if brk == 0x0806280A: print(">>> CAL RETURNED"); emu.remove_breakpoint(brk)
    elif brk == 0x08043471: print(">>> FATAL alloc_error"); break
    elif brk in (0x08053C25,0x080528ED):
        if gps_at is None: gps_at = done; print(f">>> GPS PHASE REACHED ({tag})")
        emu.remove_breakpoint(brk)
    if gps_at and done-gps_at >= 8_000_000: print(">>> captured GPS, stopping"); break
print(f"\nstopped pc=0x{emu.pc:08X} after {done} instr, +{(emu.time.cycles-t0)/1e6:.2f}s emulated")
print("trace counts:", dict(sorted(tr.counts().items(), key=lambda kv:-kv[1])[:8]))
