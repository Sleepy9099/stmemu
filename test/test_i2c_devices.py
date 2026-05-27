"""Tests for I2C state machine, bus routing, and external devices."""
from __future__ import annotations

import unittest

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus
from stmemu.peripherals.i2c import I2cPeripheral
from stmemu.external.i2c_bus import I2cBus
from stmemu.external.i2c_device import (
    I2cDevice, RegisterI2cDevice, EepromI2cDevice, ImuI2cDevice,
)


_I2C_REGS = (
    SvdRegister(name="CR1", offset=0x00),
    SvdRegister(name="CR2", offset=0x04),
    SvdRegister(name="TIMINGR", offset=0x10),
    SvdRegister(name="ISR", offset=0x18),
    SvdRegister(name="ICR", offset=0x1C),
    SvdRegister(name="RXDR", offset=0x24),
    SvdRegister(name="TXDR", offset=0x28),
)


def _make_svd(name, base, registers=(), interrupts=()):
    return SvdPeripheral(
        name=name, base_address=base, size=0x400,
        registers=registers, interrupts=interrupts,
    )


class _FakeNvic:
    def __init__(self):
        self.pending: dict[int, bool] = {}
    def set_irq_pending(self, irq, pending=True):
        self.pending[irq] = pending
    def set_system_pending(self, name, pending=True):
        pass


def _make_i2c_with_bus(*devices):
    i2c_svd = _make_svd("I2C1", 0x40005400, _I2C_REGS,
        interrupts=(SvdInterrupt(name="I2C1_EV", value=31),))
    ranges = (AddressRange(base=0x40005400, end=0x40005800, peripheral=i2c_svd),)
    amap = AddressMap(device_name="TEST", peripherals=(i2c_svd,), ranges=ranges)
    bus = PeripheralBus(amap)
    nvic = _FakeNvic()
    bus._interrupts = nvic

    i2c = I2cPeripheral(peripheral=i2c_svd, irq=31)
    bus.register_peripheral("I2C1", i2c)

    i2c_bus = I2cBus("i2c1")
    for dev in devices:
        i2c_bus.attach_device(dev)
    i2c.attach_i2c_bus(i2c_bus)

    return i2c, i2c_bus, nvic


def _cr2_write(addr7: int, nbytes: int, *, read: bool = False,
               start: bool = True, stop: bool = False, autoend: bool = False) -> int:
    val = (addr7 & 0x7F) << 1
    val |= (nbytes & 0xFF) << 16
    if read:
        val |= 1 << 10
    if start:
        val |= 1 << 13
    if stop:
        val |= 1 << 14
    if autoend:
        val |= 1 << 25
    return val


# ── I2C bus routing tests ─────────────────────────────────────────


class I2cBusTests(unittest.TestCase):
    def test_device_ack(self):
        bus = I2cBus()
        dev = RegisterI2cDevice(address=0x50)
        bus.attach_device(dev)
        self.assertTrue(bus.start(0x50, read=False))

    def test_no_device_nack(self):
        bus = I2cBus()
        self.assertFalse(bus.start(0x50, read=False))

    def test_multiple_devices(self):
        bus = I2cBus()
        dev1 = RegisterI2cDevice(address=0x50, name="eeprom")
        dev2 = ImuI2cDevice(address=0x68, name="imu")
        bus.attach_device(dev1)
        bus.attach_device(dev2)
        self.assertTrue(bus.start(0x50, read=False))
        bus.stop()
        self.assertTrue(bus.start(0x68, read=False))

    def test_detach(self):
        bus = I2cBus()
        dev = RegisterI2cDevice(address=0x50)
        bus.attach_device(dev)
        self.assertTrue(bus.detach_device(0x50))
        self.assertFalse(bus.start(0x50, read=False))

    def test_write_read_register(self):
        bus = I2cBus()
        dev = RegisterI2cDevice(address=0x50)
        dev.set_register(0x10, 0xAB)
        bus.attach_device(dev)

        bus.start(0x50, read=False)
        bus.write_byte(0x10)
        bus.stop()

        bus.start(0x50, read=True)
        val = bus.read_byte()
        bus.stop()
        self.assertEqual(val, 0xAB)

    def test_snapshot_restore(self):
        bus = I2cBus()
        dev = RegisterI2cDevice(address=0x50)
        dev.set_register(0x00, 0x42)
        bus.attach_device(dev)
        state = bus.snapshot_state()
        dev.set_register(0x00, 0x00)
        bus.restore_state(state)
        self.assertEqual(dev.get_register(0x00), 0x42)


# ── I2C peripheral state machine tests ────────────────────────────


class I2cPeripheralTests(unittest.TestCase):
    def test_write_transaction(self):
        eeprom = EepromI2cDevice(address=0x50)
        i2c, i2c_bus, nvic = _make_i2c_with_bus(eeprom)

        cr2 = _cr2_write(0x50, 2, read=False)
        i2c.write(i2c._CR2, 4, cr2)

        isr = i2c.read(i2c._ISR, 4)
        self.assertTrue(isr & i2c._ISR_TXIS, "TXIS should be set after START+ACK")

        i2c.write(i2c._TXDR, 4, 0x00)
        i2c.write(i2c._TXDR, 4, 0xAB)

        isr = i2c.read(i2c._ISR, 4)
        self.assertTrue(isr & i2c._ISR_TC, "TC should be set after all bytes sent")

        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 0, start=False, stop=True))
        isr = i2c.read(i2c._ISR, 4)
        self.assertTrue(isr & i2c._ISR_STOPF)

        self.assertEqual(eeprom.get_register(0x00), 0xAB)

    def test_read_transaction(self):
        eeprom = EepromI2cDevice(address=0x50)
        eeprom.set_register(0x10, 0xCD)
        i2c, i2c_bus, nvic = _make_i2c_with_bus(eeprom)

        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 1, read=False))
        i2c.write(i2c._TXDR, 4, 0x10)
        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 0, start=False, stop=True))

        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 1, read=True))
        isr = i2c.read(i2c._ISR, 4)
        self.assertTrue(isr & i2c._ISR_RXNE)

        data = i2c.read(i2c._RXDR, 4)
        self.assertEqual(data, 0xCD)

    def test_nack_on_wrong_address(self):
        i2c, i2c_bus, nvic = _make_i2c_with_bus()
        cr2 = _cr2_write(0x99, 1, read=False)
        i2c.write(i2c._CR2, 4, cr2)
        isr = i2c.read(i2c._ISR, 4)
        self.assertTrue(isr & i2c._ISR_NACKF)

    def test_autoend(self):
        eeprom = EepromI2cDevice(address=0x50)
        i2c, i2c_bus, nvic = _make_i2c_with_bus(eeprom)

        cr2 = _cr2_write(0x50, 2, read=False, autoend=True)
        i2c.write(i2c._CR2, 4, cr2)
        i2c.write(i2c._TXDR, 4, 0x00)
        i2c.write(i2c._TXDR, 4, 0xFF)

        isr = i2c.read(i2c._ISR, 4)
        self.assertTrue(isr & i2c._ISR_STOPF, "AUTOEND should generate STOP")

    def test_imu_whoami_read(self):
        imu = ImuI2cDevice(address=0x68, whoami_reg=0x75, whoami_value=0x71)
        i2c, i2c_bus, nvic = _make_i2c_with_bus(imu)

        i2c.write(i2c._CR2, 4, _cr2_write(0x68, 1, read=False))
        i2c.write(i2c._TXDR, 4, 0x75)
        i2c.write(i2c._CR2, 4, _cr2_write(0x68, 0, start=False, stop=True))

        i2c.write(i2c._CR2, 4, _cr2_write(0x68, 1, read=True))
        whoami = i2c.read(i2c._RXDR, 4)
        self.assertEqual(whoami, 0x71)

    def test_multi_byte_read(self):
        dev = RegisterI2cDevice(address=0x50)
        for i in range(4):
            dev.set_register(i, 0x10 + i)
        i2c, i2c_bus, nvic = _make_i2c_with_bus(dev)

        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 1, read=False))
        i2c.write(i2c._TXDR, 4, 0x00)
        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 0, start=False, stop=True))

        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 4, read=True))
        result = []
        for _ in range(4):
            result.append(i2c.read(i2c._RXDR, 4))
        self.assertEqual(result, [0x10, 0x11, 0x12, 0x13])


# ── IRQ tests ─────────────────────────────────────────────────────


class I2cIrqTests(unittest.TestCase):
    def test_nack_irq(self):
        i2c, i2c_bus, nvic = _make_i2c_with_bus()
        i2c.write(i2c._CR1, 4, i2c._CR1_PE | i2c._CR1_NACKIE)
        i2c.write(i2c._CR2, 4, _cr2_write(0x99, 1))
        self.assertTrue(nvic.pending.get(31, False))

    def test_rxie_irq(self):
        dev = RegisterI2cDevice(address=0x50)
        dev.set_register(0x00, 0xAA)
        i2c, i2c_bus, nvic = _make_i2c_with_bus(dev)

        i2c.write(i2c._CR1, 4, i2c._CR1_PE | i2c._CR1_RXIE)
        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 1, read=False))
        i2c.write(i2c._TXDR, 4, 0x00)
        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 0, start=False, stop=True))

        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 1, read=True))
        self.assertTrue(nvic.pending.get(31, False))

    def test_icr_clears_flags(self):
        i2c, i2c_bus, nvic = _make_i2c_with_bus()
        i2c.write(i2c._CR1, 4, i2c._CR1_PE | i2c._CR1_NACKIE)
        i2c.write(i2c._CR2, 4, _cr2_write(0x99, 1))
        self.assertTrue(nvic.pending.get(31, False))
        i2c.write(i2c._ICR, 4, i2c._ISR_NACKF)
        isr = i2c.read(i2c._ISR, 4)
        self.assertFalse(isr & i2c._ISR_NACKF)


# ── Snapshot tests ────────────────────────────────────────────────


class I2cSnapshotTests(unittest.TestCase):
    def test_peripheral_snapshot_restore(self):
        eeprom = EepromI2cDevice(address=0x50)
        eeprom.set_register(0x00, 0x42)
        i2c, i2c_bus, nvic = _make_i2c_with_bus(eeprom)

        i2c.write(i2c._CR2, 4, _cr2_write(0x50, 2, read=False))
        i2c.write(i2c._TXDR, 4, 0x01)

        state = i2c.snapshot_state()
        i2c.reset()
        i2c.restore_state(state)

        self.assertEqual(eeprom.get_register(0x00), 0x42)

    def test_device_state_in_snapshot(self):
        imu = ImuI2cDevice(address=0x68, whoami_value=0x71)
        i2c, i2c_bus, nvic = _make_i2c_with_bus(imu)
        state = i2c.snapshot_state()
        self.assertIn("i2c_bus_state", state)
        self.assertIsNotNone(state["i2c_bus_state"])


# ── Device-level tests ────────────────────────────────────────────


class I2cDeviceTests(unittest.TestCase):
    def test_register_device_write_read(self):
        dev = RegisterI2cDevice(address=0x50)
        dev.start(read=False)
        dev.write_byte(0x05)
        dev.write_byte(0xAB)
        dev.stop()

        dev.start(read=False)
        dev.write_byte(0x05)
        dev.stop()
        dev.start(read=True)
        val = dev.read_byte()
        dev.stop()
        self.assertEqual(val, 0xAB)

    def test_eeprom_sequential_write(self):
        dev = EepromI2cDevice(address=0x50)
        dev.start(read=False)
        dev.write_byte(0x00)
        for i in range(4):
            dev.write_byte(0x10 + i)
        dev.stop()
        self.assertEqual(dev.get_register(0x00), 0x10)
        self.assertEqual(dev.get_register(0x03), 0x13)

    def test_imu_whoami(self):
        imu = ImuI2cDevice(address=0x68, whoami_reg=0x75, whoami_value=0x6A)
        self.assertEqual(imu.get_register(0x75), 0x6A)

    def test_imu_reset_preserves_whoami(self):
        imu = ImuI2cDevice(address=0x68, whoami_reg=0x75, whoami_value=0x71)
        imu.set_register(0x00, 0xFF)
        imu.reset()
        self.assertEqual(imu.get_register(0x75), 0x71)
        self.assertEqual(imu.get_register(0x00), 0x00)

    def test_register_device_snapshot(self):
        dev = RegisterI2cDevice(address=0x50)
        dev.set_register(0x10, 0xBE)
        state = dev.snapshot_state()
        dev.reset()
        self.assertEqual(dev.get_register(0x10), 0x00)
        dev.restore_state(state)
        self.assertEqual(dev.get_register(0x10), 0xBE)


if __name__ == "__main__":
    unittest.main()
