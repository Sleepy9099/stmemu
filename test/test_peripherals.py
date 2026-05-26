from __future__ import annotations

import unittest

from stmemu.svd.model import SvdField, SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.peripherals.gpio import GpioPeripheral
from stmemu.peripherals.flash import FlashPeripheral
from stmemu.peripherals.spi import SpiPeripheral
from stmemu.peripherals.i2c import I2cPeripheral
from stmemu.peripherals.dma import DmaPeripheral


def _make_peripheral(name: str, registers: tuple[SvdRegister, ...] = (), interrupts=()) -> SvdPeripheral:
    return SvdPeripheral(
        name=name,
        base_address=0x40000000,
        size=0x400,
        registers=registers,
        interrupts=interrupts,
    )


# Standard GPIO registers
_GPIO_REGS = (
    SvdRegister(name="MODER", offset=0x00),
    SvdRegister(name="OTYPER", offset=0x04),
    SvdRegister(name="OSPEEDR", offset=0x08),
    SvdRegister(name="PUPDR", offset=0x0C),
    SvdRegister(name="IDR", offset=0x10, access="ro"),
    SvdRegister(name="ODR", offset=0x14),
    SvdRegister(name="BSRR", offset=0x18, access="wo"),
    SvdRegister(name="LCKR", offset=0x1C),
)

_SPI_REGS = (
    SvdRegister(name="CR1", offset=0x00),
    SvdRegister(name="CR2", offset=0x04),
    SvdRegister(name="SR", offset=0x08, reset_value=0x02),  # TXE=1 at reset
    SvdRegister(name="DR", offset=0x0C),
)

_I2C_REGS = (
    SvdRegister(name="CR1", offset=0x00),
    SvdRegister(name="CR2", offset=0x04),
    SvdRegister(name="TIMINGR", offset=0x10),
    SvdRegister(name="ISR", offset=0x18, reset_value=0x01),  # TXE=1 at reset
    SvdRegister(name="ICR", offset=0x1C),
    SvdRegister(name="RXDR", offset=0x24),
    SvdRegister(name="TXDR", offset=0x28),
)

_DMA_REGS = (
    SvdRegister(name="LISR", offset=0x00),
    SvdRegister(name="HISR", offset=0x04),
    SvdRegister(name="LIFCR", offset=0x08),
    SvdRegister(name="HIFCR", offset=0x0C),
    SvdRegister(name="S0CR", offset=0x10),
    SvdRegister(name="S0NDTR", offset=0x14),
    SvdRegister(name="S0PAR", offset=0x18),
    SvdRegister(name="S0M0AR", offset=0x1C),
)


class GpioTests(unittest.TestCase):

    def _make_gpio(self) -> GpioPeripheral:
        return GpioPeripheral(peripheral=_make_peripheral("GPIOA", _GPIO_REGS))

    def test_bsrr_sets_odr_bits(self) -> None:
        gpio = self._make_gpio()
        gpio.write(0x18, 4, 0x0003)  # Set bits 0 and 1
        odr = gpio.read(0x14, 4)
        self.assertEqual(odr & 0x0003, 0x0003)

    def test_bsrr_resets_odr_bits(self) -> None:
        gpio = self._make_gpio()
        gpio.write(0x14, 4, 0xFFFF)  # Set all ODR bits
        gpio.write(0x18, 4, 0x00050000)  # Reset bits 0 and 2
        odr = gpio.read(0x14, 4)
        self.assertEqual(odr & 0x0005, 0)
        self.assertEqual(odr & 0x0002, 0x0002)  # Bit 1 unchanged

    def test_idr_reflects_odr(self) -> None:
        gpio = self._make_gpio()
        gpio.write(0x14, 4, 0x00AA)  # Write ODR
        idr = gpio.read(0x10, 4)
        self.assertEqual(idr, 0x00AA)

    def test_bsrr_reset_takes_priority(self) -> None:
        gpio = self._make_gpio()
        # Set and reset bit 0 simultaneously - reset wins
        gpio.write(0x18, 4, 0x00010001)
        odr = gpio.read(0x14, 4)
        self.assertEqual(odr & 1, 0)


class FlashTests(unittest.TestCase):

    def _make_flash(self) -> FlashPeripheral:
        regs = (
            SvdRegister(name="ACR", offset=0x00, fields=(
                SvdField(name="LATENCY", bit_offset=0, bit_width=4),
            )),
            SvdRegister(name="KEYR", offset=0x04),
            SvdRegister(name="SR", offset=0x0C),
            SvdRegister(name="CR", offset=0x10),
        )
        return FlashPeripheral(peripheral=_make_peripheral("FLASH", regs))

    def test_sr_bsy_always_zero(self) -> None:
        flash = self._make_flash()
        sr = flash.read(0x0C, 4)
        self.assertEqual(sr & 1, 0)  # BSY = 0

    def test_unlock_sequence(self) -> None:
        flash = self._make_flash()
        cr = flash.read(0x10, 4)
        self.assertTrue(cr & (1 << 31))  # Initially locked

        flash.write(0x04, 4, 0x45670123)  # KEY1
        flash.write(0x04, 4, 0xCDEF89AB)  # KEY2
        cr = flash.read(0x10, 4)
        self.assertFalse(cr & (1 << 31))  # Now unlocked

    def test_wrong_unlock_stays_locked(self) -> None:
        flash = self._make_flash()
        flash.write(0x04, 4, 0xDEADBEEF)  # Wrong key
        flash.write(0x04, 4, 0xCDEF89AB)
        cr = flash.read(0x10, 4)
        self.assertTrue(cr & (1 << 31))  # Still locked


class SpiTests(unittest.TestCase):

    def _make_spi(self) -> SpiPeripheral:
        return SpiPeripheral(peripheral=_make_peripheral("SPI1", _SPI_REGS))

    def test_txe_always_set(self) -> None:
        spi = self._make_spi()
        sr = spi.read(0x08, 4)
        self.assertTrue(sr & (1 << 1))  # TXE = 1

    def test_bsy_always_clear(self) -> None:
        spi = self._make_spi()
        sr = spi.read(0x08, 4)
        self.assertFalse(sr & (1 << 7))  # BSY = 0

    def test_write_dr_captures_tx_and_loopback_rx(self) -> None:
        spi = self._make_spi()
        spi.write(0x0C, 4, 0x42)
        self.assertEqual(spi.drain_tx(), bytes([0x42]))
        # RX has loopback 0xFF
        sr = spi.read(0x08, 4)
        self.assertTrue(sr & (1 << 0))  # RXNE = 1
        rx = spi.read(0x0C, 4)
        self.assertEqual(rx, 0xFF)

    def test_inject_rx_data(self) -> None:
        spi = self._make_spi()
        spi.inject_rx(b"\xAB\xCD")
        self.assertEqual(spi.read(0x0C, 4), 0xAB)
        self.assertEqual(spi.read(0x0C, 4), 0xCD)

    def test_reset_clears_fifos(self) -> None:
        spi = self._make_spi()
        spi.write(0x0C, 4, 0x01)
        spi.inject_rx(b"\x02")
        spi.reset()
        self.assertEqual(spi.drain_tx(), b"")
        sr = spi.read(0x08, 4)
        self.assertFalse(sr & (1 << 0))  # RXNE = 0


class I2cTests(unittest.TestCase):

    def _make_i2c(self) -> I2cPeripheral:
        return I2cPeripheral(peripheral=_make_peripheral("I2C1", _I2C_REGS))

    def test_txe_set_at_idle(self) -> None:
        i2c = self._make_i2c()
        isr = i2c.read(0x18, 4)
        self.assertTrue(isr & (1 << 0))  # TXE = 1

    def test_busy_clear_at_idle(self) -> None:
        i2c = self._make_i2c()
        isr = i2c.read(0x18, 4)
        self.assertFalse(isr & (1 << 15))  # BUSY = 0

    def test_inject_rx_sets_rxne(self) -> None:
        i2c = self._make_i2c()
        i2c.inject_rx(b"\x55")
        isr = i2c.read(0x18, 4)
        self.assertTrue(isr & (1 << 2))  # RXNE = 1
        rx = i2c.read(0x24, 4)
        self.assertEqual(rx, 0x55)

    def test_write_txdr_captures_data(self) -> None:
        i2c = self._make_i2c()
        i2c.write(0x28, 4, 0xAB)
        self.assertEqual(i2c.drain_tx(), bytes([0xAB]))


class DmaTests(unittest.TestCase):

    def _make_dma(self) -> DmaPeripheral:
        return DmaPeripheral(peripheral=_make_peripheral("DMA1", _DMA_REGS))

    def test_enable_stream_sets_tcif(self) -> None:
        dma = self._make_dma()
        # Enable stream 0 (S0CR at offset 0x10, EN = bit 0)
        dma.write(0x10, 4, 0x01)
        lisr = dma.read(0x00, 4)
        self.assertTrue(lisr & (1 << 5))  # TCIF0 set

    def test_enable_stream_clears_en(self) -> None:
        dma = self._make_dma()
        dma.write(0x10, 4, 0x01)  # Enable
        cr = dma.read(0x10, 4)
        self.assertFalse(cr & 1)  # EN cleared after completion

    def test_enable_stream_zeros_ndtr(self) -> None:
        dma = self._make_dma()
        dma.write(0x14, 4, 100)   # Set NDTR = 100
        dma.write(0x10, 4, 0x01)  # Enable stream
        ndtr = dma.read(0x14, 4)
        self.assertEqual(ndtr, 0)  # All transferred

    def test_lifcr_clears_lisr(self) -> None:
        dma = self._make_dma()
        dma.write(0x10, 4, 0x01)  # Enable stream 0 -> sets TCIF0
        lisr = dma.read(0x00, 4)
        self.assertTrue(lisr & (1 << 5))
        dma.write(0x08, 4, 1 << 5)  # Clear TCIF0 via LIFCR
        lisr = dma.read(0x00, 4)
        self.assertFalse(lisr & (1 << 5))


if __name__ == "__main__":
    unittest.main()
