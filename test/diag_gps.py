"""From the INS-init snapshot, drive setup() forward and report: SPI1 IMU
exchange counts (detection), UART5 GPS TX/RX bytes, and which milestone is
reached (config_error fatal vs AP_GPS::update = main loop running)."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from stmemu.core.loader import load_firmware
from stmemu.svd.svd_loader import load_svd
from stmemu.svd.address_map import build_address_map
from stmemu.peripherals.factory import build_default_bus
from stmemu.core.emulator import Emulator
from stmemu.board_config import load_board_config, apply_board_config

snap = sys.argv[1] if len(sys.argv) > 1 else "test/snap_insinit.snap"
name = sys.argv[2] if len(sys.argv) > 2 else "ins_init"
budget = int(sys.argv[3]) if len(sys.argv) > 3 else 80_000_000

fw = load_firmware(ROOT / "test/arducopter_with_bl.bin", base_addr=0x08000000)
dev = load_svd(ROOT / "cmsis-svd-stm32/stm32h7/STM32H743.svd")
bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
emu = Emulator(bus=bus, flash_base=0x08000000, firmware_segments=fw.segments,
               sram_base=0x24000000, sram_size=0x80000, firmware_format=fw.format,
               firmware_entry_point=fw.entry_point, core_peripheral=core, tick_scale=10,
               stuck_loop_threshold=10_000_000, interrupt_stuck_threshold=5_000_000_000,
               stuck_loop_auto=False)
emu.boot_from_vector_table()
apply_board_config(load_board_config(ROOT / "test/arducopter_with_bl.yaml"), bus, emu, base_dir=ROOT / "test")
emu.import_snapshot(str(ROOT / snap), name=name)
emu.load_snapshot(name)

# Count exchanges per SPI device (IMUs on SPI1, FRAM on SPI2).
spi_counts: dict[str, int] = {}
for dname, d in (getattr(bus, "_spi_attached_devices", {}) or {}).items():
    if hasattr(d, "exchange"):
        _o = d.exchange
        def mk(nm, fn):
            def w(b):
                spi_counts[nm] = spi_counts.get(nm, 0) + 1
                return fn(b)
            return w
        d.exchange = mk(dname, _o)

# Count UART5 GPS traffic.
u5 = bus.model_for_name("UART5")
gps = {"tx": 0, "rx": 0}
if u5 is not None:
    _drain = u5.drain_tx_bytes
    def drain():
        d = _drain()
        gps["tx"] += len(d)
        return d
    u5.drain_tx_bytes = drain
    _inj = u5.inject_rx_bytes
    def inj(data):
        gps["rx"] += len(data)
        return _inj(data)
    u5.inject_rx_bytes = inj

MILES = {0x08043471: "config_error(FATAL)", 0x08053C25: "AP_GPS::update",
         0x0805D82D: "AP_GPS_UBLOX ctor(DETECTED)", 0x080528ED: "GPS detect_instance"}
for a in MILES:
    emu.add_breakpoint(a)

hit = None
done = 0
gps_seen_at = None
CHUNK = 2_000_000
while done < budget:
    emu.run(CHUNK)
    done += CHUNK
    if emu.last_pc_break is not None:
        a = emu.last_pc_break
        hit = MILES.get(a, f"0x{a:08X}")
        print(f"[{done:>10}] reached {hit} at pc=0x{emu.pc:08X}  spi={spi_counts} gps={gps}", flush=True)
        if a == 0x08043471:   # fatal config_error -> stop
            break
        if a in (0x08053C25, 0x0805D82D):  # GPS update/detect -> note + keep going briefly
            emu.remove_breakpoint(a)
            if gps_seen_at is None:
                gps_seen_at = done
    elif done % 10_000_000 == 0:
        # heartbeat so a long run shows where it is even with no milestone
        print(f"[{done:>10}] pc=0x{emu.pc:08X}  spi={spi_counts} gps={gps}", flush=True)
    # once GPS phase is reached, run a bit more to capture tx/rx then stop
    if gps_seen_at is not None and done - gps_seen_at >= 8_000_000:
        print(f"[{done:>10}] captured GPS phase, stopping early", flush=True)
        break

print(f"\nstopped at pc=0x{emu.pc:08X} after {done} instr  (first GPS milestone at {gps_seen_at})")
print("SPI device exchanges:", spi_counts or "(none)")
print(f"UART5 GPS: tx={gps['tx']}  rx={gps['rx']}")
