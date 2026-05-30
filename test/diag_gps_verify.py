"""Verify the GPS exchange from the captured main-loop snapshot.

Loads snap_mainloop.snap (saved by diag_gps_reach.py at AP_GPS::update) and
runs a short window with UART5 + I2C4 + SPI1 tracing, so you can confirm the
ublox config TX (CFG_PRT/MSG/RATE) and NAV/ACK RX without re-doing the slow
boot -> init -> EKF. This is the fast device-interaction test loop the
snapshot exists to enable.

  python test/diag_gps_verify.py [run_instr]
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

run_instr = int(sys.argv[1]) if len(sys.argv) > 1 else 8_000_000
snap = ROOT / "test/snap_mainloop.snap"
if not snap.exists():
    raise SystemExit(f"{snap} not found -- run diag_gps_reach.py first to capture it")

fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000,
               sram_size=0x80000, firmware_format=fw.format, firmware_entry_point=fw.entry_point,
               core_peripheral=core, tick_scale=10, stuck_loop_threshold=10_000_000,
               interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT / "test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT / "test")
emu.import_snapshot(str(snap), name="mainloop")
emu.load_snapshot("mainloop")

# Also tally raw UART5 GPS bytes via the drain/inject hooks (ground truth).
u5 = bus.model_for_name("UART5")
gps = {"tx": 0, "rx": 0}
if u5 is not None:
    _d, _i = u5.drain_tx_bytes, u5.inject_rx_bytes
    u5.drain_tx_bytes = lambda: (lambda b: (gps.__setitem__("tx", gps["tx"] + len(b)), b)[1])(_d())
    u5.inject_rx_bytes = lambda data: (gps.__setitem__("rx", gps["rx"] + len(data)), _i(data))[1]

tr = emu.enable_tracing(sources=["UART5", "I2C4", "SPI1"])
print(f"loaded snap_mainloop @pc=0x{emu.pc:08X}; running {run_instr} @tick=10", flush=True)
emu.run(run_instr)
print(f"stopped pc=0x{emu.pc:08X}  fp_emulated={emu._fp_emulated_count}")
print(f"\nUART5 GPS bytes: tx={gps['tx']}  rx={gps['rx']}")
print("\n== bus activity (counts) ==")
for k, v in sorted(tr.counts().items(), key=lambda kv: -kv[1]):
    print(f"  {k}: {v}")
print("\n== UART5 trace (ublox exchange) ==")
for ln in tr.dump().splitlines():
    if ln.strip().startswith("UART5"):
        print("  " + ln)
