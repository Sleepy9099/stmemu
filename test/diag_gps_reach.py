"""Reach AP_GPS::update and capture a main-loop snapshot.

Drives from the INS-init snapshot with the gyro-cal loop force-exited (the
firmware filter rings on perfectly-zero synthetic gyro input, so cal never
converges) and ARMv8-M FP emulation active (the EKF uses vrint/vsel). When
AP_GPS::update / GPS detect is reached it saves snap_mainloop.snap so future
GPS / device-interaction testing starts at the running main loop instead of
re-doing the whole boot -> init -> EKF, then captures the UART5 ublox exchange.

  python test/diag_gps_reach.py [budget]
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

budget = int(sys.argv[1]) if len(sys.argv) > 1 else 150_000_000

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

# Force the gyro-cal loop to exit at its next iteration (r3 = j+1 at the
# `cmp r3,#0x78` check), and stub _init_gyro's entry in case it is re-called.
emu.add_pc_cpu_action("setreg", pc=0x0806232C, reg="r3", value=200, once=True)
emu.add_pc_cpu_action("ret", pc=0x08062044, once=False)

tr = emu.enable_tracing(sources=["UART5"])
MILES = {0x08053C25: "AP_GPS::update", 0x080528ED: "GPS_detect",
         0x0805D82D: "UBLOX_cfg", 0x08043471: "alloc_error", 0x0806280A: "CAL_EXIT"}
for a in MILES:
    emu.add_breakpoint(a)

t0 = emu.time.cycles
done = 0
gps_at = None
snapped = False
print(f"reach-GPS run from pc=0x{emu.pc:08X}", flush=True)
while done < budget:
    emu.run(3_000_000)
    done += 3_000_000
    c = tr.counts()
    uart = sum(v for k, v in c.items() if k.startswith("UART5"))
    et = (emu.time.cycles - t0) / 1e6
    b = emu.last_pc_break
    tag = MILES.get(b) if b else ""
    print(f"[{done:>9}] et=+{et:7.2f}s pc=0x{emu.pc:08X} uart={uart} fp={emu._fp_emulated_count} brk={tag}", flush=True)
    if b == 0x08043471:
        print(">>> FATAL alloc_error"); break
    if b == 0x0806280A:
        print(">>> CAL EXITED"); emu.remove_breakpoint(b); continue
    if b in (0x08053C25, 0x080528ED, 0x0805D82D):
        if not snapped:
            emu.save_snapshot("mainloop")
            n = emu.export_snapshot("mainloop", str(ROOT / "test/snap_mainloop.snap"))
            snapped = True
            print(f">>> GPS PHASE: {tag} -- saved snap_mainloop.snap ({n} bytes)")
        if gps_at is None:
            gps_at = done
        emu.remove_breakpoint(b)
    if gps_at and done - gps_at >= 12_000_000:
        print(">>> captured GPS window, stopping"); break

print(f"\nstopped pc=0x{emu.pc:08X} after {done} instr, +{(emu.time.cycles - t0) / 1e6:.1f}s, "
      f"fp_emulated={emu._fp_emulated_count}, gps_at={gps_at}")
print("== UART5 trace tail ==")
for ln in tr.dump().splitlines()[-30:]:
    print("  " + ln)
