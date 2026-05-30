"""Re-capture a GPS-LIVE main-loop snapshot (GPS actively exchanging on UART5).

reach6 saved snap_mainloop.snap at the FIRST AP_GPS::update (EKF mid-init, GPS
pre-detection, ublox frozen silent). This re-captures later -- once UART5 RX is
flowing (the firmware is reading the receiver) -- so the snapshot starts from a
live GPS conversation and the verify needs no post-load mode override.

Same recipe as reach6: fast boot (tick_scale=10) -> switch to the real-rate
active clock at the main-loop entry so AP_Scheduler runs the GPS task ->
convert_parameters stub for the FRAM param-scan starvation. The ublox streams
(YAML mode=both), so once the main loop services the GPS, RX climbs and we
snapshot.

  python test/diag_gps_reach7.py [budget] [instr_per_us] [rx_threshold]
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
ipus = int(sys.argv[2]) if len(sys.argv) > 2 else 4
rx_thresh = int(sys.argv[3]) if len(sys.argv) > 3 else 2000
SCHED_RUN, GPS_UPDATE = 0x0809E8B0, 0x08053C24
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

# The snapshot restores the ublox to whatever mode it had at capture (often a
# silent UBX-only state), so force it to stream NMEA+UBX -- otherwise the
# firmware never receives anything and rx stays 0 (the snapshot-overrides-mode
# trap; same fix as diag_gps_verify.py).
for _ln in bus.serial_lines().values():
    _d = getattr(_ln, "device", None)
    if _d is not None and hasattr(_d, "mode"):
        _d.mode = "both"
        _d._cycle_counter = 0

emu.add_pc_cpu_action("setreg", pc=0x0806232C, reg="r3", value=200, once=True)
emu.add_pc_cpu_action("ret", pc=0x08062044, once=False)
emu.add_pc_cpu_action("ret", pc=0x08070BE4, once=False)

# count UART5 GPS bytes via the drain/inject hooks (ground truth)
u5 = bus.model_for_name("UART5")
gps = {"tx": 0, "rx": 0}
if u5 is not None:
    _d, _i = u5.drain_tx_bytes, u5.inject_rx_bytes
    u5.drain_tx_bytes = lambda: (lambda b: (gps.__setitem__("tx", gps["tx"] + len(b)), b)[1])(_d())
    u5.inject_rx_bytes = lambda data: (gps.__setitem__("rx", gps["rx"] + len(data)), _i(data))[1]

for a in (SCHED_RUN, CAL_EXIT, ALLOC_ERR):
    emu.add_breakpoint(a)

t0 = emu.time.cycles
done = 0
switched = False
snapped = False
print(f"reach-GPS v7 (re-capture GPS-live; real-rate {ipus}, rx>={rx_thresh}) pc=0x{emu.pc:08X}", flush=True)
while done < budget:
    emu.run(3_000_000)
    done += 3_000_000
    b = emu.last_pc_break
    if b == ALLOC_ERR:
        print(">>> FATAL alloc_error"); break
    if b == CAL_EXIT:
        print(">>> CAL EXITED"); emu.remove_breakpoint(b)
    elif b == SCHED_RUN and not switched:
        emu.set_active_throttle(ipus); switched = True; emu.remove_breakpoint(b)
        # The ublox streamed into the UART5 RX buffer during boot before the
        # firmware read it; reset the counters (and the device tx buffer) so the
        # snapshot is taken on FRESH main-loop GPS traffic, not boot backlog.
        gps["rx"] = 0; gps["tx"] = 0
        for _ln in bus.serial_lines().values():
            _dv = getattr(_ln, "device", None)
            if _dv is not None and hasattr(_dv, "_tx_buf"):
                _dv._tx_buf.clear()
        print(f">>> MAIN LOOP @~{done} -> real-rate {ipus} instr/us (counters reset)", flush=True)
    et = (emu.time.cycles - t0) / 1e6
    print(f"[{done:>9}] et=+{et:8.2f}s pc=0x{emu.pc:08X} tx={gps['tx']} rx={gps['rx']} "
          f"thr={'on' if switched else 'off'}", flush=True)
    if not snapped and switched and gps["rx"] >= rx_thresh:
        emu.save_snapshot("mainloop_gps")
        n = emu.export_snapshot("mainloop_gps", str(ROOT / "test/snap_mainloop_gps.snap"))
        snapped = True
        print(f">>> GPS LIVE (rx={gps['rx']}) -- saved snap_mainloop_gps.snap ({n} bytes)")
        emu.run(4_000_000)
        break

print(f"\nstopped pc=0x{emu.pc:08X} after ~{done} instr, +{(emu.time.cycles-t0)/1e6:.1f}s; "
      f"UART5 tx={gps['tx']} rx={gps['rx']} snapped={snapped}")
