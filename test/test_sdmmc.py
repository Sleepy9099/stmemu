"""SDMMC 'no card present' stub tests.

The stub exists to terminate the ChibiOS SDMMC command-polling loops: a command
either flags CMDSENT (no-response command) or CTIMEOUT (response expected, no
card answered), and ICR clears STAR bits. These pin that polling behaviour.
"""
from __future__ import annotations

import unittest

from stmemu.svd.model import SvdPeripheral, SvdRegister
from stmemu.peripherals.sdmmc import build_sdmmc


_CMDR = 0x0C
_RESP1R = 0x14
_STAR = 0x34
_ICR = 0x38

_CPSMEN = 1 << 12
_WAITRESP_SHIFT = 8
_CMDSENT = 1 << 7
_CTIMEOUT = 1 << 2

_SDMMC_REGS = (
    SvdRegister(name="CMDR", offset=_CMDR),
    SvdRegister(name="RESP1R", offset=_RESP1R),
    SvdRegister(name="STAR", offset=_STAR),
    SvdRegister(name="ICR", offset=_ICR),
)


def _sdmmc():
    svd = SvdPeripheral(
        name="SDMMC1", base_address=0x52007000, size=0x400,
        registers=_SDMMC_REGS, interrupts=(),
    )
    return build_sdmmc(svd)


class SdmmcStubTests(unittest.TestCase):
    def test_no_response_command_sets_cmdsent(self):
        sd = _sdmmc()
        sd.write(_CMDR, 4, _CPSMEN | (0 << _WAITRESP_SHIFT))  # WAITRESP=0
        star = sd.read(_STAR, 4)
        self.assertTrue(star & _CMDSENT, "no-response command must flag CMDSENT")
        self.assertFalse(star & _CTIMEOUT)

    def test_response_command_times_out(self):
        sd = _sdmmc()
        sd.write(_CMDR, 4, _CPSMEN | (1 << _WAITRESP_SHIFT))  # WAITRESP=short resp
        star = sd.read(_STAR, 4)
        self.assertTrue(star & _CTIMEOUT, "no card -> CTIMEOUT")
        self.assertFalse(star & _CMDSENT)

    def test_command_without_cpsmen_does_nothing(self):
        sd = _sdmmc()
        sd.write(_CMDR, 4, 0x40)  # CMDINDEX only, CPSMEN not set
        self.assertEqual(sd.read_register_value(_STAR) & (_CMDSENT | _CTIMEOUT), 0)

    def test_icr_clears_star_bits(self):
        sd = _sdmmc()
        sd.write_register_value(_STAR, _CMDSENT | _CTIMEOUT | (1 << 0))
        sd.write(_ICR, 4, _CMDSENT | _CTIMEOUT)  # clear those two
        star = sd.read_register_value(_STAR)
        self.assertFalse(star & _CMDSENT)
        self.assertFalse(star & _CTIMEOUT)
        self.assertTrue(star & (1 << 0), "unrelated STAR bits are preserved")

    def test_star_read_settles_pending_command(self):
        # Mid-poll state (e.g. snapshot-restored) where CPSMEN is set in CMDR
        # but the write-side hook never ran: a STAR read must settle it.
        sd = _sdmmc()
        sd.write_register_value(_CMDR, _CPSMEN | (1 << _WAITRESP_SHIFT))
        self.assertEqual(sd.read_register_value(_STAR), 0)
        star = sd.read(_STAR, 4)
        self.assertTrue(star & _CTIMEOUT, "STAR read settles the pending command")


if __name__ == "__main__":
    unittest.main()
