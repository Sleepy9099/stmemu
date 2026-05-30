"""Reach AP_GPS::update -- v6: real-rate active clock in the main loop.

Root cause (memory item 23): the default clock advances tick_scale us per
instruction, so the EKF AHRS::update "takes" ~500ms of measured micros() and
AP_Scheduler zeroes time_available -> the 50Hz AP_GPS::update task is starved
every loop (uart stays 0 forever; confirmed empirically in v2 at +525s).

Fix: emu.set_active_throttle(480) makes ACTIVE execution advance 1us every 480
instructions (~the 480MHz H743 core), so a compute task's measured duration is
realistic (EKF ~100us << 2500us loop budget) and optional tasks run -- like
real HW. Idle is still jumped, so boot stays fast. We boot at tick_scale=10,
then switch to real-rate on the first AP_Scheduler::run (main-loop entry).

  python test/diag_gps_reach6.py [budget] [instr_per_us]
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "test"))

from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config

budget = int(sys.argv[1]) if len(sys.argv) > 1 else 130_000_000
ipus = int(sys.argv[2]) if len(sys.argv) > 2 else 480
SCHED_RUN, GPS_UPDATE, UBLOX_READ = 0x0809E8B0, 0x08053C24, 0x0805D90C
CAL_EXIT, ALLOC_ERR = 0x0806280A, 0x08043471

fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000,
               sram_size=0x80000, firmware_format=fw.format, firmware_entry_point=fw.entry_point,
               core_peripheral=core, tick_scale=10, stuck_loop_threshold=10_000_000,
               interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT / "test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT / "test")
emu.import_snapshot(str(ROOT / "test/snap_insinit.snap"), name="ins_init")
emu.load_snapshot("ins_init")

emu.add_pc_cpu_action("setreg", pc=0x0806232C, reg="r3", value=200, once=True)
emu.add_pc_cpu_action("ret", pc=0x08062044, once=False)
emu.add_pc_cpu_action("ret", pc=0x08070BE4, once=False)        # stub convert_parameters

tr = emu.enable_tracing(sources=["UART5"])
NAMES = {SCHED_RUN: "Sched::run", GPS_UPDATE: "AP_GPS::update", UBLOX_READ: "UBLOX::read",
         CAL_EXIT: "CAL_EXIT", ALLOC_ERR: "alloc_error"}
for a in NAMES:
    emu.add_breakpoint(a)

t0 = emu.time.cycles
done = 0
switched = False
snapped = False
hits = {GPS_UPDATE: 0, UBLOX_READ: 0}
print(f"reach-GPS v6 (real-rate {ipus} instr/us in main loop) from pc=0x{emu.pc:08X}", flush=True)
while done < budget:
    emu.run(3_000_000)
    done += 3_000_000
    b = emu.last_pc_break
    if b == ALLOC_ERR:
        print(">>> FATAL alloc_error"); break
    if b == CAL_EXIT:
        print(">>> CAL EXITED"); emu.remove_breakpoint(b)
    elif b == SCHED_RUN and not switched:
        emu.set_active_throttle(ipus)
        switched = True
        emu.remove_breakpoint(b)
        print(f">>> MAIN LOOP reached (Sched::run) at ~{done} instr, +{(emu.time.cycles-t0)/1e6:.1f}s "
              f"-- switched to real-rate {ipus} instr/us", flush=True)
    elif b in hits:
        hits[b] += 1
        print(f">>> HIT {NAMES[b]} at ~{done} instr, +{(emu.time.cycles-t0)/1e6:.2f}s", flush=True)
        if b == GPS_UPDATE and not snapped:
            emu.save_snapshot("mainloop")
            n = emu.export_snapshot("mainloop", str(ROOT / "test/snap_mainloop.snap"))
            snapped = True
            print(f">>> saved snap_mainloop.snap ({n} bytes)")
        emu.remove_breakpoint(b)
    c = tr.counts()
    uart = sum(v for k, v in c.items() if k.startswith("UART5"))
    et = (emu.time.cycles - t0) / 1e6
    print(f"[{done:>9}] et=+{et:8.2f}s pc=0x{emu.pc:08X} uart={uart} fp={emu._fp_emulated_count} "
          f"thr={'on' if switched else 'off'} gpsupd={hits[GPS_UPDATE]} ublox={hits[UBLOX_READ]}", flush=True)
    if snapped:
        print(">>> GPS reached; running short trace window then stopping")
        emu.run(8_000_000)
        break

c = tr.counts()
uart = sum(v for k, v in c.items() if k.startswith("UART5"))
print(f"\nstopped pc=0x{emu.pc:08X} after ~{done} instr, +{(emu.time.cycles-t0)/1e6:.1f}s, fp={emu._fp_emulated_count}")
print(f"switched={switched} gpsupd_hits={hits[GPS_UPDATE]} ublox_hits={hits[UBLOX_READ]} UART5_total={uart}")
print("== UART5 trace tail ==")
for ln in tr.dump().splitlines()[-30:]:
    print("  " + ln)
