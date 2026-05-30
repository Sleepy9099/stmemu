"""Shared harness for firmware-milestone regression tests (C2).

Boots the committed ArduCopter raw bin under the emulator so a test can run to
an address (emu.run_until) and assert device-interaction counts -- locking in
boot -> init -> device-probe progress so timing/refactor changes can't silently
regress it. Skips cleanly (FIRMWARE_AVAILABLE) when the assets are absent.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_BIN = ROOT / "test" / "arducopter_with_bl.bin"
_YAML = ROOT / "test" / "arducopter_with_bl.yaml"
_SVD = ROOT / "cmsis-svd-stm32" / "stm32h7" / "STM32H743.svd"

FIRMWARE_AVAILABLE = _BIN.exists() and _YAML.exists() and _SVD.exists()


def make_emulator(*, tick_scale: int = 10):
    """Build a fresh emulator booted from the committed firmware bin + board YAML."""
    from stmemu.core.loader import load_firmware
    from stmemu.svd.svd_loader import load_svd
    from stmemu.svd.address_map import build_address_map
    from stmemu.peripherals.factory import build_default_bus
    from stmemu.core.emulator import Emulator
    from stmemu.board_config import load_board_config, apply_board_config

    fw = load_firmware(_BIN, base_addr=0x08000000)
    dev = load_svd(str(_SVD))
    bus, core = build_default_bus(build_address_map(dev), flash_base=0x08000000)
    emu = Emulator(
        bus=bus, flash_base=0x08000000, firmware_segments=fw.segments,
        sram_base=0x24000000, sram_size=0x80000, firmware_format=fw.format,
        firmware_entry_point=fw.entry_point, core_peripheral=core,
        tick_scale=tick_scale, stuck_loop_threshold=10_000_000,
        interrupt_stuck_threshold=5_000_000_000, stuck_loop_auto=False,
    )
    emu.boot_from_vector_table()
    apply_board_config(load_board_config(_YAML), bus, emu, base_dir=ROOT / "test")
    return emu, bus


def bus_counts(tracer) -> dict:
    """Sum tracer counts per bus prefix, e.g. {'SPI1': n, 'I2C4': m, 'UART5': k}."""
    out: dict[str, int] = {}
    for key, n in tracer.counts().items():
        prefix = key.split()[0] if key else key
        out[prefix] = out.get(prefix, 0) + n
    return out


# Main-loop snapshots (newest/most-useful first). Created during dev runs and
# NOT committed (gitignored), so the snapshot-based regression skips in CI but
# runs locally where one is present -- a fast guard that device interactions
# still work from a known-good state without re-doing the slow cold boot.
_SNAP_CANDIDATES = (
    "snap_mainloop_gps.snap", "snap_mainloop.snap",
    "snapshot_post_init.snap", "snap_insinit.snap",
)


def find_snapshot():
    """Return the first present main-loop snapshot path, or None."""
    for name in _SNAP_CANDIDATES:
        p = ROOT / "test" / name
        if p.exists():
            return p
    return None


def emulator_from_snapshot(snap_path, *, tick_scale: int = 10):
    """Boot + apply board config, then load a saved snapshot. Returns (emu, bus)."""
    emu, bus = make_emulator(tick_scale=tick_scale)
    emu.import_snapshot(str(snap_path), name="rt")
    emu.load_snapshot("rt")
    return emu, bus
