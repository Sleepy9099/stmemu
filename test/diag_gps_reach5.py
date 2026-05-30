"""Reach AP_GPS::update -- v5 with CORRECT AP_GPS entry addresses.

The earlier breakpoint 0x08053C25 was actually update_instance+0x2E7 (deep
inside, only reached once GPS data already flows). Correct entries:
    AP_GPS::init        0x08051F40   (called during init_ardupilot)
    AP_GPS::update      0x08053C24   (front-end scheduler task)
    AP_GPS_UBLOX::read  0x0805D90C   (driver; sends CFG + parses NAV/ACK)

Question this settles: is AP_GPS::update *called* at all? At +500s firmware
with uart=0 the EKF is running but the GPS task never TX'd -- so either the
front-end update() is never scheduled (starved by the EKF consuming the loop
budget) or it runs but never TXes. Correct breakpoints distinguish these.

convert_parameters is stubbed (kills the per-loop AP_Param::scan over FRAM).
On the first AP_GPS::update we snapshot snap_mainloop.snap (the deliverable).

  python test/diag_gps_reach5.py [budget]
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

budget = int(sys.argv[1]) if len(sys.argv) > 1 else 90_000_000
GPS_INIT, GPS_UPDATE, UBLOX_READ = 0x08051F40, 0x08053C24, 0x0805D90C
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
NAMES = {GPS_INIT: "AP_GPS::init", GPS_UPDATE: "AP_GPS::update", UBLOX_READ: "UBLOX::read",
         CAL_EXIT: "CAL_EXIT", ALLOC_ERR: "alloc_error"}
for a in NAMES:
    emu.add_breakpoint(a)
hits = {a: 0 for a in NAMES}

t0 = emu.time.cycles
done = 0
snapped = False
print(f"reach-GPS v5 (correct AP_GPS bp) from pc=0x{emu.pc:08X}", flush=True)
while done < budget:
    emu.run(3_000_000)
    done += 3_000_000
    b = emu.last_pc_break
    if b in hits:
        hits[b] += 1
        tag = NAMES[b]
        if b == ALLOC_ERR:
            print(">>> FATAL alloc_error"); break
        if b == CAL_EXIT:
            print(">>> CAL EXITED"); emu.remove_breakpoint(b); continue
        print(f">>> HIT {tag} (1st) at ~{done} instr, +{(emu.time.cycles-t0)/1e6:.1f}s", flush=True)
        if b == GPS_UPDATE and not snapped:
            emu.save_snapshot("mainloop")
            n = emu.export_snapshot("mainloop", str(ROOT / "test/snap_mainloop.snap"))
            snapped = True
            print(f">>> saved snap_mainloop.snap ({n} bytes)")
        emu.remove_breakpoint(b)   # one-shot: count first arrival of each
    c = tr.counts()
    uart = sum(v for k, v in c.items() if k.startswith("UART5"))
    et = (emu.time.cycles - t0) / 1e6
    hitstr = " ".join(f"{NAMES[a][:9]}={hits[a]}" for a in (GPS_INIT, GPS_UPDATE, UBLOX_READ))
    print(f"[{done:>9}] et=+{et:7.2f}s pc=0x{emu.pc:08X} uart={uart} fp={emu._fp_emulated_count} {hitstr}", flush=True)
    if snapped:
        print(">>> reached AP_GPS::update; running short window then stopping")
        emu.run(6_000_000)
        break

print(f"\nstopped pc=0x{emu.pc:08X} after ~{done} instr, +{(emu.time.cycles-t0)/1e6:.1f}s, fp={emu._fp_emulated_count}")
print(f"hits: " + ", ".join(f"{NAMES[a]}={hits[a]}" for a in NAMES))
c = tr.counts()
print(f"UART5 total: {sum(v for k,v in c.items() if k.startswith('UART5'))}")
print("== UART5 trace tail ==")
for ln in tr.dump().splitlines()[-25:]:
    print("  " + ln)
