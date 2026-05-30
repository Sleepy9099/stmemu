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
# Force gyro-cal loop to exit at next iteration: r3(=j+1) -> 200 at the j<=120 check.
emu.add_pc_cpu_action("setreg", pc=0x0806232C, reg="r3", value=200, once=True)
emu.add_pc_cpu_action("ret", pc=0x08062044, once=False)   # also stub entry if re-called
tr = emu.enable_tracing(sources=["UART5"])
MILES={0x08053C25:"AP_GPS::update",0x080528ED:"GPS_detect",0x0805D82D:"UBLOX_cfg",0x08043471:"alloc_error",0x0806280A:"CAL_EXIT"}
for a in MILES: emu.add_breakpoint(a)
t0=emu.time.cycles; done=0; gps_at=None
print(f"force-cal-exit run from pc=0x{emu.pc:08X}", flush=True)
while done<130_000_000:
    emu.run(3_000_000); done+=3_000_000
    c=tr.counts(); uart=sum(v for k,v in c.items() if k.startswith("UART5"))
    et=(emu.time.cycles-t0)/1e6; b=emu.last_pc_break; tag=MILES.get(b) if b else ""
    print(f"[{done:>9}] et=+{et:7.2f}s pc=0x{emu.pc:08X} uartLines={uart} brk={tag}", flush=True)
    if b==0x08043471: print(">>> FATAL"); break
    if b==0x0806280A: print(">>> CAL EXITED"); emu.remove_breakpoint(b)
    elif b in MILES:
        if gps_at is None: gps_at=done; print(f">>> GPS PHASE: {tag}")
        emu.remove_breakpoint(b)
    if gps_at and done-gps_at>=9_000_000: print(">>> captured GPS window"); break
print("\n== UART5 trace tail =="); 
for ln in tr.dump().splitlines()[-24:]: print("  "+ln)
