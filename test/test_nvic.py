"""Tests for NVIC priority, preemption, masking, and exception model."""
from __future__ import annotations

import unittest

from stmemu.peripherals.core_cm import CortexMCorePeripheral


class NvicPriorityTests(unittest.TestCase):
    def _make_core(self):
        return CortexMCorePeripheral(vtor=0x08000000)

    def test_default_priority_zero(self):
        core = self._make_core()
        self.assertEqual(core.irq_priority(0), 0)
        self.assertEqual(core.irq_priority(15), 0)

    def test_set_irq_priority(self):
        core = self._make_core()
        core.set_irq_priority(5, 0x40)
        self.assertEqual(core.irq_priority(5), 0x40)

    def test_ipr_register_write_read(self):
        core = self._make_core()
        core.write(0xE400, 4, 0x80604020)
        self.assertEqual(core.irq_priority(0), 0x20)
        self.assertEqual(core.irq_priority(1), 0x40)
        self.assertEqual(core.irq_priority(2), 0x60)
        self.assertEqual(core.irq_priority(3), 0x80)

    def test_ipr_register_read_reflects_priority(self):
        core = self._make_core()
        core.set_irq_priority(4, 0xA0)
        core.set_irq_priority(5, 0xB0)
        val = core.read(0xE404, 4)
        self.assertEqual(val & 0xFF, 0xA0)
        self.assertEqual((val >> 8) & 0xFF, 0xB0)

    def test_exception_priority_nmi(self):
        core = self._make_core()
        self.assertEqual(core.exception_priority(2), -2)

    def test_exception_priority_irq(self):
        core = self._make_core()
        core.set_irq_priority(10, 0x40)
        self.assertEqual(core.exception_priority(26), 0x40)

    def test_exception_priority_pendsv_default(self):
        core = self._make_core()
        self.assertEqual(core.exception_priority(14), 0)

    def test_exception_priority_systick_default(self):
        core = self._make_core()
        self.assertEqual(core.exception_priority(15), 0)

    def test_exception_priority_pendsv_configurable(self):
        core = self._make_core()
        core.set_system_priority(14, 0xFF)
        self.assertEqual(core.exception_priority(14), 0xFF)

    def test_exception_priority_systick_configurable(self):
        core = self._make_core()
        core.set_system_priority(15, 0xC0)
        self.assertEqual(core.exception_priority(15), 0xC0)

    def test_exception_priority_svc_configurable(self):
        core = self._make_core()
        core.set_system_priority(11, 0x10)
        self.assertEqual(core.exception_priority(11), 0x10)


class NvicPreemptionTests(unittest.TestCase):
    def _make_core(self):
        return CortexMCorePeripheral(vtor=0x08000000)

    def test_higher_priority_preempts(self):
        core = self._make_core()
        core.set_irq_priority(0, 0x40)
        core.set_irq_priority(1, 0x80)
        core.set_irq_enabled(0, True)
        core.set_irq_enabled(1, True)
        core.set_irq_pending(1, True)
        core.enter_exception(16 + 1)

        core.set_irq_pending(0, True)
        exc = core.next_pending_exception()
        self.assertEqual(exc, 16 + 0, "higher priority IRQ should preempt")

    def test_lower_priority_does_not_preempt(self):
        core = self._make_core()
        core.set_irq_priority(0, 0x40)
        core.set_irq_priority(1, 0x80)
        core.set_irq_enabled(0, True)
        core.set_irq_enabled(1, True)
        core.set_irq_pending(0, True)
        core.enter_exception(16 + 0)

        core.set_irq_pending(1, True)
        exc = core.next_pending_exception()
        self.assertIsNone(exc, "lower priority should not preempt")

    def test_same_priority_does_not_preempt(self):
        core = self._make_core()
        core.set_irq_priority(0, 0x40)
        core.set_irq_priority(1, 0x40)
        core.set_irq_enabled(0, True)
        core.set_irq_enabled(1, True)
        core.set_irq_pending(0, True)
        core.enter_exception(16 + 0)

        core.set_irq_pending(1, True)
        exc = core.next_pending_exception()
        self.assertIsNone(exc)

    def test_active_irq_not_re_entered(self):
        core = self._make_core()
        core.set_irq_enabled(5, True)
        core.set_irq_pending(5, True)
        core.enter_exception(16 + 5)
        core.set_irq_pending(5, True)
        exc = core.next_pending_exception()
        self.assertIsNone(exc)

    def test_nmi_always_preempts(self):
        core = self._make_core()
        core.set_irq_priority(0, 0x00)
        core.set_irq_enabled(0, True)
        core.set_irq_pending(0, True)
        core.enter_exception(16 + 0)

        core.set_system_pending("NMI", True)
        exc = core.next_pending_exception()
        self.assertEqual(exc, 2)

    def test_thread_mode_accepts_any_priority(self):
        core = self._make_core()
        core.set_irq_priority(0, 0xFF)
        core.set_irq_enabled(0, True)
        core.set_irq_pending(0, True)
        exc = core.next_pending_exception()
        self.assertEqual(exc, 16)

    def test_highest_priority_wins_among_pending(self):
        core = self._make_core()
        core.set_irq_priority(0, 0x80)
        core.set_irq_priority(1, 0x20)
        core.set_irq_priority(2, 0x60)
        core.set_irq_enabled(0, True)
        core.set_irq_enabled(1, True)
        core.set_irq_enabled(2, True)
        core.set_irq_pending(0, True)
        core.set_irq_pending(1, True)
        core.set_irq_pending(2, True)
        exc = core.next_pending_exception()
        self.assertEqual(exc, 16 + 1)


class NvicMaskingTests(unittest.TestCase):
    def _make_core(self):
        return CortexMCorePeripheral(vtor=0x08000000)

    def test_primask_blocks_irq(self):
        core = self._make_core()
        core.set_irq_enabled(0, True)
        core.set_irq_pending(0, True)
        exc = core.next_pending_exception(primask=True)
        self.assertIsNone(exc)

    def test_primask_does_not_block_nmi(self):
        core = self._make_core()
        core.set_system_pending("NMI", True)
        exc = core.next_pending_exception(primask=True)
        self.assertEqual(exc, 2)

    def test_basepri_blocks_low_priority(self):
        core = self._make_core()
        core.set_irq_priority(0, 0x80)
        core.set_irq_enabled(0, True)
        core.set_irq_pending(0, True)
        exc = core.next_pending_exception(basepri=0x40)
        self.assertIsNone(exc)

    def test_basepri_allows_high_priority(self):
        core = self._make_core()
        core.set_irq_priority(0, 0x20)
        core.set_irq_enabled(0, True)
        core.set_irq_pending(0, True)
        exc = core.next_pending_exception(basepri=0x40)
        self.assertEqual(exc, 16)

    def test_basepri_zero_allows_all(self):
        core = self._make_core()
        core.set_irq_priority(0, 0xFF)
        core.set_irq_enabled(0, True)
        core.set_irq_pending(0, True)
        exc = core.next_pending_exception(basepri=0)
        self.assertEqual(exc, 16)

    def test_basepri_blocks_pendsv(self):
        core = self._make_core()
        core.set_system_priority(14, 0xFF)
        core.set_system_pending("PendSV", True)
        exc = core.next_pending_exception(basepri=0x40)
        self.assertIsNone(exc, "PendSV priority 0xFF should be blocked by basepri 0x40")

    def test_basepri_blocks_systick(self):
        core = self._make_core()
        core.set_system_priority(15, 0xFF)
        core.set_system_pending("SysTick", True)
        exc = core.next_pending_exception(basepri=0x40)
        self.assertIsNone(exc)


class NvicSnapshotTests(unittest.TestCase):
    def test_priority_in_snapshot(self):
        core = CortexMCorePeripheral(vtor=0x08000000)
        core.set_irq_priority(10, 0x40)
        core.set_irq_priority(20, 0x80)
        state = core.snapshot_state()
        self.assertIn("irq_priority", state)
        core2 = CortexMCorePeripheral(vtor=0x08000000)
        core2.restore_state(state)
        self.assertEqual(core2.irq_priority(10), 0x40)
        self.assertEqual(core2.irq_priority(20), 0x80)


class NvicRunningPriorityTests(unittest.TestCase):
    def test_thread_mode_priority(self):
        core = CortexMCorePeripheral(vtor=0x08000000)
        self.assertEqual(core._running_priority(), 0x100)

    def test_active_exception_priority(self):
        core = CortexMCorePeripheral(vtor=0x08000000)
        core.set_irq_priority(5, 0x40)
        core.set_irq_enabled(5, True)
        core.set_irq_pending(5, True)
        core.enter_exception(16 + 5)
        self.assertEqual(core._running_priority(), 0x40)

    def test_nested_uses_highest_active(self):
        core = CortexMCorePeripheral(vtor=0x08000000)
        core.set_irq_priority(5, 0x80)
        core.set_irq_priority(3, 0x20)
        core.enter_exception(16 + 5)
        core.enter_exception(16 + 3)
        self.assertEqual(core._running_priority(), 0x20)


class ShprRegisterTests(unittest.TestCase):
    def _make_core(self):
        return CortexMCorePeripheral(vtor=0x08000000)

    def test_shpr3_write_pendsv_systick(self):
        core = self._make_core()
        # SHPR3: byte2=PendSV(exc14), byte3=SysTick(exc15)
        core.write(0xED20, 4, 0xF0E00000)
        self.assertEqual(core.exception_priority(14), 0xE0)
        self.assertEqual(core.exception_priority(15), 0xF0)

    def test_shpr3_read(self):
        core = self._make_core()
        core.set_system_priority(14, 0xA0)
        core.set_system_priority(15, 0xB0)
        val = core.read(0xED20, 4)
        self.assertEqual((val >> 16) & 0xFF, 0xA0)
        self.assertEqual((val >> 24) & 0xFF, 0xB0)

    def test_shpr2_write_svc(self):
        core = self._make_core()
        # SHPR2: byte3=SVCall(exc11)
        core.write(0xED1C, 4, 0x40000000)
        self.assertEqual(core.exception_priority(11), 0x40)

    def test_shpr2_read_svc(self):
        core = self._make_core()
        core.set_system_priority(11, 0x30)
        val = core.read(0xED1C, 4)
        self.assertEqual((val >> 24) & 0xFF, 0x30)

    def test_shpr1_write_memmanage(self):
        core = self._make_core()
        # SHPR1: byte0=MemManage(exc4)
        core.write(0xED18, 4, 0x00000020)
        self.assertEqual(core.exception_priority(4), 0x20)

    def test_rtos_typical_config(self):
        core = self._make_core()
        core.set_system_priority(11, 0x00)  # SVC highest configurable
        core.set_system_priority(14, 0xFF)  # PendSV lowest
        core.set_system_priority(15, 0xFF)  # SysTick lowest
        core.set_irq_priority(0, 0x40)      # EXTI0 mid

        core.set_irq_enabled(0, True)
        core.set_irq_pending(0, True)
        core.set_system_pending("PendSV", True)
        core.set_system_pending("SysTick", True)

        exc = core.next_pending_exception()
        self.assertEqual(exc, 16 + 0, "EXTI0 at 0x40 should win over PendSV/SysTick at 0xFF")

    def test_pendsv_yields_to_irq(self):
        core = self._make_core()
        core.set_system_priority(14, 0xFF)
        core.set_system_pending("PendSV", True)
        core.enter_exception(14)

        core.set_irq_priority(5, 0x40)
        core.set_irq_enabled(5, True)
        core.set_irq_pending(5, True)

        exc = core.next_pending_exception()
        self.assertEqual(exc, 16 + 5, "IRQ at 0x40 should preempt PendSV at 0xFF")

    def test_systick_priority_affects_ordering(self):
        core = self._make_core()
        core.set_system_priority(15, 0x20)
        core.set_irq_priority(0, 0x80)
        core.set_irq_enabled(0, True)
        core.set_irq_pending(0, True)
        core.set_system_pending("SysTick", True)

        exc = core.next_pending_exception()
        self.assertEqual(exc, 15, "SysTick at 0x20 should win over IRQ0 at 0x80")

    def test_snapshot_restore_sys_priority(self):
        core = self._make_core()
        core.set_system_priority(11, 0x10)
        core.set_system_priority(14, 0xF0)
        core.set_system_priority(15, 0xE0)
        state = core.snapshot_state()
        core2 = CortexMCorePeripheral(vtor=0x08000000)
        core2.restore_state(state)
        self.assertEqual(core2.exception_priority(11), 0x10)
        self.assertEqual(core2.exception_priority(14), 0xF0)
        self.assertEqual(core2.exception_priority(15), 0xE0)


if __name__ == "__main__":
    unittest.main()
