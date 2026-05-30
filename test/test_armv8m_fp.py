"""Tests for software emulation of ARMv8-M FP instructions."""
from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from stmemu.core import armv8m_fp as fp  # noqa: E402

# Other tests stub sys.modules['unicorn'] with a non-package mock; under
# `unittest discover` that leaves the real VFP register table unresolvable
# here. Register-dependent cases skip in that case (they run when this file is
# executed directly, the normal dev path); the pure-logic cases always run.
_HAVE_REGS = bool(fp._regs())


class _FakeUc:
    def __init__(self):
        self.r = {}

    def reg_read(self, rid):
        return self.r.get(rid, 0)

    def reg_write(self, rid, val):
        self.r[rid] = int(val)


class Armv8mFpTest(unittest.TestCase):
    @unittest.skipUnless(_HAVE_REGS, "real unicorn VFP regs unavailable")
    def test_vrintp_f64_from_crash_bytes(self):
        # The exact instruction that faulted in NavEKF3_core::setup_core:
        #   vrintp.f64 d7, d7   (round toward +inf)
        uc = _FakeUc()
        fp._write(uc, "d7", 3.2)
        size = fp.try_emulate(uc, bytes.fromhex("bafe477b"), 0x0808D4CE)
        self.assertEqual(size, 4)
        self.assertEqual(fp._read(uc, "d7"), 4.0)

    @unittest.skipUnless(_HAVE_REGS, "real unicorn VFP regs unavailable")
    def test_vrintp_negative(self):
        uc = _FakeUc()
        fp._write(uc, "d7", -3.2)
        fp.try_emulate(uc, bytes.fromhex("bafe477b"), 0)
        self.assertEqual(fp._read(uc, "d7"), -3.0)  # ceil(-3.2) = -3

    @unittest.skipUnless(_HAVE_REGS, "real unicorn VFP regs unavailable")
    def test_vselgt_f64_from_crash_bytes(self):
        # The instruction that faulted in NavEKF3_core::readIMUData:
        #   vselgt.f64 d7, d7, d5   (d7 = GT ? d7 : d5)
        code = bytes.fromhex("37fe057b")
        uc = _FakeUc()
        fp._write(uc, "d7", 11.0)
        fp._write(uc, "d5", 22.0)
        # GT true (Z=0, N==V): pick d7
        uc.reg_write(fp._regs()["cpsr"], 0)            # N=Z=C=V=0 -> GT true
        self.assertEqual(fp.try_emulate(uc, code, 0), 4)
        self.assertEqual(fp._read(uc, "d7"), 11.0)
        # GT false (Z=1): pick d5
        fp._write(uc, "d7", 11.0)
        uc.reg_write(fp._regs()["cpsr"], 1 << 30)      # Z=1 -> GT false
        fp.try_emulate(uc, code, 0)
        self.assertEqual(fp._read(uc, "d7"), 22.0)

    def test_unsupported_returns_none(self):
        uc = _FakeUc()
        # A plain 'nop' (0xbf00) is not one of our FP ops.
        self.assertIsNone(fp.try_emulate(uc, bytes.fromhex("00bf"), 0))

    def test_round_mode_helpers(self):
        self.assertEqual(fp._VRINT["vrintp"](2.1), 3.0)   # ceil
        self.assertEqual(fp._VRINT["vrintm"](2.9), 2.0)   # floor
        self.assertEqual(fp._VRINT["vrintz"](-2.9), -2.0)  # truncate
        self.assertEqual(fp._VRINT["vrintn"](2.5), 2.0)   # ties to even
        self.assertEqual(fp._VRINT["vrintn"](3.5), 4.0)   # ties to even
        self.assertEqual(fp._VRINT["vrinta"](2.5), 3.0)   # ties away
        self.assertTrue(math.isnan(fp._VRINT["vrintp"](float("nan"))))

    @unittest.skipUnless(_HAVE_REGS, "real unicorn VFP regs unavailable")
    def test_read_write_roundtrip_f32_f64(self):
        uc = _FakeUc()
        fp._write(uc, "s14", 1.5)
        self.assertEqual(fp._read(uc, "s14"), 1.5)
        fp._write(uc, "d3", -123456.75)
        self.assertEqual(fp._read(uc, "d3"), -123456.75)


if __name__ == "__main__":
    unittest.main()
