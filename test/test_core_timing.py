"""Regression tests for Cortex-M core timing semantics.

Reading DWT.CYCCNT or SysTick.VAL must NOT advance time. Previously both
read hooks called self.tick(), so a register *read* advanced SysTick (and
could pend a spurious SysTick interrupt) and double-counted cycles already
advanced by the main per-instruction tick loop.
"""

from __future__ import annotations

import unittest

from stmemu.peripherals.core_cm import CortexMCorePeripheral


# PPB-relative offsets (see CortexMCorePeripheral)
DWT_CTRL = 0x1000
DWT_CYCCNT = 0x1004
DEMCR = 0xEDFC
SYST_CSR = 0xE010
SYST_RVR = 0xE014
SYST_CVR = 0xE018

CSR_ENABLE = 1 << 0
CSR_TICKINT = 1 << 1
DEMCR_TRCENA = 1 << 24
DWT_CTRL_CYCCNTENA = 1 << 0


def _enable_cyccnt(core) -> None:
    core.write(DEMCR, 4, DEMCR_TRCENA)
    core.write(DWT_CTRL, 4, DWT_CTRL_CYCCNTENA)


def _core() -> CortexMCorePeripheral:
    return CortexMCorePeripheral(vtor=0x08000000)


class CoreTimingTests(unittest.TestCase):
    def test_cyccnt_read_has_no_side_effect(self) -> None:
        core = _core()
        _enable_cyccnt(core)
        first = core.read(DWT_CYCCNT, 4)
        # Reading repeatedly must not advance the cycle counter.
        self.assertEqual(core.read(DWT_CYCCNT, 4), first)
        self.assertEqual(core.read(DWT_CYCCNT, 4), first)
        # Only an explicit tick advances it, and by exactly the cycle count.
        core.tick(5)
        self.assertEqual(core.read(DWT_CYCCNT, 4), first + 5)
        self.assertEqual(core.read(DWT_CYCCNT, 4), first + 5)

    def test_cyccnt_does_not_run_until_enabled(self) -> None:
        # CYCCNT must stay at 0 until DEMCR.TRCENA and DWT_CTRL.CYCCNTENA are
        # both set, matching hardware.
        core = _core()
        core.tick(10)
        self.assertEqual(core.read(DWT_CYCCNT, 4), 0, "counter must be gated off")
        core.write(DEMCR, 4, DEMCR_TRCENA)  # TRCENA only
        core.tick(10)
        self.assertEqual(core.read(DWT_CYCCNT, 4), 0, "CYCCNTENA still off")
        core.write(DWT_CTRL, 4, DWT_CTRL_CYCCNTENA)  # now both set
        core.tick(7)
        self.assertEqual(core.read(DWT_CYCCNT, 4), 7)

    def test_systick_val_read_has_no_side_effect(self) -> None:
        core = _core()
        core.write(SYST_CSR, 4, CSR_ENABLE)
        core.write(SYST_RVR, 4, 1000)
        core.tick(1)  # CVR: 0 -> wrap -> 1000
        core.tick(1)  # 1000 -> 999
        value = core.read(SYST_CVR, 4)
        # Hammering reads must leave the counter exactly where it was; with the
        # old code each read ticked 1 and the value would keep decreasing.
        for _ in range(2000):
            self.assertEqual(core.read(SYST_CVR, 4), value)

    def test_systick_val_read_does_not_pend_interrupt(self) -> None:
        core = _core()
        core.write(SYST_CSR, 4, CSR_ENABLE | CSR_TICKINT)
        core.write(SYST_RVR, 4, 10)  # small reload: old code would wrap within ~10 reads
        core.tick(1)  # legitimate first wrap from the 0 reset value
        core.set_system_pending("SysTick", False)
        self.assertNotIn("SysTick", core.pending_system_exceptions())
        for _ in range(100):
            core.read(SYST_CVR, 4)
        self.assertNotIn("SysTick", core.pending_system_exceptions())

    def test_tick_still_drives_systick(self) -> None:
        # Sanity: removing the read side-effects must not stop the canonical
        # per-instruction tick from clocking SysTick.
        core = _core()
        core.write(SYST_CSR, 4, CSR_ENABLE | CSR_TICKINT)
        core.write(SYST_RVR, 4, 3)
        core.set_system_pending("SysTick", False)
        for _ in range(10):
            core.tick(1)
        self.assertIn("SysTick", core.pending_system_exceptions())


if __name__ == "__main__":
    unittest.main()
