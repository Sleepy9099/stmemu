"""Firmware device-interaction regression (cluster C2).

Loads a known-good main-loop snapshot and asserts the IMU (SPI1) and baro
(I2C4) are STILL exchanged with -- a fast guard that the device models + bus
plumbing didn't silently regress. Skips when the firmware bin / a snapshot are
absent (e.g. a fresh CI checkout -- snapshots are gitignored).

For a full BOOT regression (catching boot/timing breakage), the harness also
exposes make_emulator() + emu.run_until(pc): boot cold and run to a milestone
address, asserting bus_counts(). That is much slower (the cold boot is tens of
millions of instructions), so it is left as a developer-invoked check rather
than part of the default suite. Example:

    emu, _ = make_emulator()
    tr = emu.enable_tracing(sources=["SPI1", "I2C4"])
    assert emu.run_until(0x08062044, max_instructions=60_000_000)  # _init_gyro
    assert bus_counts(tr).get("SPI1", 0) > 0
"""
from __future__ import annotations

import unittest

from firmware_harness import (
    FIRMWARE_AVAILABLE, bus_counts, emulator_from_snapshot, find_snapshot,
)

_SNAP = find_snapshot() if FIRMWARE_AVAILABLE else None


@unittest.skipUnless(_SNAP is not None, "firmware bin / main-loop snapshot not present")
class FirmwareDeviceInteractionTest(unittest.TestCase):
    def test_imu_exchange_from_snapshot(self):
        # The IMU on SPI1 is the highest-rate device (the firmware polls it
        # continuously via the bus thread), so it is the reliable device-
        # interaction regression signal across any main-loop snapshot. If the
        # IMU device model or the SPI bus plumbing regresses, this goes to 0.
        emu, _bus = emulator_from_snapshot(_SNAP)
        tr = emu.enable_tracing(sources=["SPI1", "SPI2", "I2C4"])
        emu.run(2_000_000)
        counts = bus_counts(tr)
        self.assertGreater(
            counts.get("SPI1", 0), 0,
            f"no SPI1 IMU traffic from {_SNAP.name}: {counts}",
        )


if __name__ == "__main__":
    unittest.main()
