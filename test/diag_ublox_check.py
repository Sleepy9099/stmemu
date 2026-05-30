"""Direct check of the ublox <-> UART5 serial bridge from the snapshot.

uart=0 in both directions during the verify means either the ublox isn't
emitting or the SerialLine bridge isn't moving bytes. This pokes the device
and the bus directly (no long firmware run) to localize it.
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

fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments, sram_base=0x24000000,
               sram_size=0x80000, firmware_format=fw.format, firmware_entry_point=fw.entry_point,
               core_peripheral=core, tick_scale=10, stuck_loop_threshold=10_000_000,
               interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT / "test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT / "test")
emu.import_snapshot(str(ROOT / "test/snap_mainloop.snap"), name="mainloop")
emu.load_snapshot("mainloop")

lines = bus.serial_lines()
print("serial lines:", list(lines.keys()))
line = next(iter(lines.values()))
ub = line.device
print(f"device={ub.name} mode={ub.mode!r} rate_cycles={ub.rate_cycles} "
      f"tx_buf={len(ub._tx_buf)} total_ticks={ub._total_ticks}")

# 1) Does the device itself emit when ticked directly?
ub.tick(200_000)
direct = ub.read_tx_to_mcu()
print(f"[direct device.tick(200000)] mode={ub.mode!r} emitted {len(direct)} bytes: {direct[:32].hex()}")

# 1b) Force 'both' (a real ublox powers up emitting NMEA+UBX so the host can
#     auto-detect it) and re-check.
ub.mode = "both"
ub._cycle_counter = 0
ub.tick(200_000)
forced = ub.read_tx_to_mcu()
print(f"[force mode=both device.tick(200000)] emitted {len(forced)} bytes: {forced[:48]!r}")

# 2) Does the SerialLine bridge move device output into the UART on bus tick?
u5 = bus.model_for_name("UART5")
injected = {"n": 0}
_orig = u5.inject_rx_bytes
u5.inject_rx_bytes = lambda d: (injected.__setitem__("n", injected["n"] + len(d)), _orig(d))[1]
before_rx = line._total_rx_bytes
emu.advance_time(300_000)   # -> bus.tick -> line.tick -> device.tick + inject
print(f"[advance_time(300000)] line.total_rx delta={line._total_rx_bytes - before_rx} "
      f"uart.inject_rx_bytes bytes={injected['n']}")

# 3) Is the UART5 RX path even enabled (does the firmware read it)? Show the
#    UART model's pending-RX depth after injection.
for attr in ("rx_fifo", "_rx_fifo", "rx_buffer", "_rx_buffer", "pending_rx"):
    if hasattr(u5, attr):
        v = getattr(u5, attr)
        try:
            print(f"  u5.{attr} len={len(v)}")
        except Exception:
            print(f"  u5.{attr}={v}")
