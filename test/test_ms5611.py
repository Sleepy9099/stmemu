"""MS5611 barometer model: PROM CRC4 and command/read sequencing.

ArduPilot's MS56XX driver validates the PROM with a CRC4 and clocks ADC /
PROM results out in a read transaction that is separate from (and STOP-
terminated after) the command write. These tests pin both behaviours.
"""
from __future__ import annotations

import unittest

from stmemu.external.ms5611 import Ms5611I2cDevice


def _read_n(dev: Ms5611I2cDevice, n: int) -> int:
    dev.start(read=True)
    value = 0
    for _ in range(n):
        value = (value << 8) | dev.read_byte()
    dev.stop()
    return value


class Ms5611CrcTests(unittest.TestCase):
    def test_crc4_matches_datasheet_vector(self):
        # AN520 worked example: this PROM has CRC4 == 0x0B.
        ds = [0x3132, 0x3334, 0x3536, 0x3738, 0x3940, 0x4142, 0x4344, 0x4546]
        self.assertEqual(Ms5611I2cDevice._crc4(ds), 0x0B)

    def test_default_prom_carries_valid_crc(self):
        dev = Ms5611I2cDevice()
        stored = dev.prom[7] & 0x0F
        computed = Ms5611I2cDevice._crc4(list(dev.prom))
        self.assertEqual(stored, computed, "PROM word 7 CRC nibble must validate")

    def test_custom_prom_gets_valid_crc(self):
        # A caller supplying coefficients with a bogus CRC nibble still ends up
        # with a self-consistent PROM (the model behaves like a healthy chip).
        custom = (0x0000, 0x1234, 0x5678, 0x9ABC, 0xDEF0, 0x1357, 0x2468, 0xFFFF)
        dev = Ms5611I2cDevice(prom=custom)
        self.assertEqual(dev.prom[7] & 0x0F, Ms5611I2cDevice._crc4(list(dev.prom)))
        # Coefficients C1..C6 are untouched.
        self.assertEqual(dev.prom[1:7], custom[1:7])


class Ms5611ReadSequenceTests(unittest.TestCase):
    def test_adc_read_survives_stop_between_command_and_read(self):
        dev = Ms5611I2cDevice()
        dev.write_byte(0x40)   # D1 (pressure) conversion, OSR 256
        dev.write_byte(0x00)   # ADC_READ
        dev.stop()             # STOP terminates the command write transaction
        value = _read_n(dev, 3)
        self.assertNotEqual(value, 0xFFFFFF, "ADC value lost across STOP")
        self.assertEqual(value, (dev.base_pressure + 1) & 0xFFFFFF)

    def test_prom_read_survives_stop_between_command_and_read(self):
        dev = Ms5611I2cDevice()
        dev.write_byte(0xA2)   # PROM_READ word 1 (C1)
        dev.stop()
        value = _read_n(dev, 2)
        self.assertEqual(value, dev.prom[1])

    def test_adc_read_combined_transaction_still_works(self):
        # Repeated-start (no STOP between command and read) must also work.
        dev = Ms5611I2cDevice()
        dev.write_byte(0x50)   # D2 (temperature) conversion
        dev.write_byte(0x00)   # ADC_READ
        value = _read_n(dev, 3)  # read transaction, no intervening stop
        self.assertEqual(value, (dev.base_temperature + 1) & 0xFFFFFF)


if __name__ == "__main__":
    unittest.main()
