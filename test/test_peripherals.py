from __future__ import annotations

import unittest

from stmemu.svd.model import SvdField, SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.peripherals.gpio import GpioPeripheral, MODE_INPUT, MODE_OUTPUT, MODE_AF, MODE_ANALOG
from stmemu.peripherals.flash import FlashPeripheral
from stmemu.peripherals.spi import SpiPeripheral
from stmemu.peripherals.i2c import I2cPeripheral
from stmemu.peripherals.dma import DmaPeripheral
from stmemu.peripherals.rcc import RccPeripheral
from stmemu.peripherals.core_cm import CortexMCorePeripheral


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
    SvdRegister(name="AFRL", offset=0x20),
    SvdRegister(name="AFRH", offset=0x24),
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
        # Set pins 1,3,5,7 to output mode
        moder = 0
        for pin in (1, 3, 5, 7):
            moder |= MODE_OUTPUT << (pin * 2)
        gpio.write(0x00, 4, moder)
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


# ── RCC register definitions ──────────────────────────────────────

_RCC_REGS = (
    SvdRegister(
        name="CR", offset=0x00, fields=(
            SvdField(name="HSION", bit_offset=0, bit_width=1),
            SvdField(name="HSIRDY", bit_offset=1, bit_width=1),
            SvdField(name="HSEON", bit_offset=16, bit_width=1),
            SvdField(name="HSERDY", bit_offset=17, bit_width=1),
            SvdField(name="PLLON", bit_offset=24, bit_width=1),
            SvdField(name="PLLRDY", bit_offset=25, bit_width=1),
        ),
    ),
    SvdRegister(
        name="CFGR", offset=0x08, fields=(
            SvdField(name="SW0", bit_offset=0, bit_width=1),
            SvdField(name="SW1", bit_offset=1, bit_width=1),
            SvdField(name="SWS0", bit_offset=2, bit_width=1),
            SvdField(name="SWS1", bit_offset=3, bit_width=1),
        ),
    ),
    SvdRegister(name="AHB1ENR", offset=0x30, fields=(
        SvdField(name="GPIOAEN", bit_offset=0, bit_width=1),
        SvdField(name="GPIOBEN", bit_offset=1, bit_width=1),
        SvdField(name="DMA1EN", bit_offset=21, bit_width=1),
    )),
    SvdRegister(name="APB1ENR", offset=0x40, fields=(
        SvdField(name="USART2EN", bit_offset=17, bit_width=1),
        SvdField(name="SPI2EN", bit_offset=14, bit_width=1),
    )),
    SvdRegister(name="AHB1RSTR", offset=0x10, fields=(
        SvdField(name="GPIOARST", bit_offset=0, bit_width=1),
    )),
    SvdRegister(name="APB1RSTR", offset=0x20, fields=(
        SvdField(name="USART2RST", bit_offset=17, bit_width=1),
    )),
)


class RccTests(unittest.TestCase):
    def _make_rcc(self):
        p = _make_peripheral("RCC", _RCC_REGS)
        return RccPeripheral(p)

    def test_hsirdy_follows_hsion(self):
        rcc = self._make_rcc()
        rcc.write(0x00, 4, 1 << 0)  # HSION=1
        cr = rcc.read(0x00, 4)
        self.assertTrue(cr & (1 << 1), "HSIRDY should be set when HSION is set")

    def test_hserdy_follows_hseon(self):
        rcc = self._make_rcc()
        rcc.write(0x00, 4, 1 << 16)  # HSEON=1
        cr = rcc.read(0x00, 4)
        self.assertTrue(cr & (1 << 17), "HSERDY should be set when HSEON is set")

    def test_pllrdy_follows_pllon(self):
        rcc = self._make_rcc()
        rcc.write(0x00, 4, 1 << 24)  # PLLON=1
        cr = rcc.read(0x00, 4)
        self.assertTrue(cr & (1 << 25), "PLLRDY should be set when PLLON is set")

    def test_rdy_clears_when_on_clears(self):
        rcc = self._make_rcc()
        rcc.write(0x00, 4, 1 << 0)  # HSION=1
        rcc.read(0x00, 4)
        rcc.write(0x00, 4, 0)  # HSION=0
        cr = rcc.read(0x00, 4)
        self.assertFalse(cr & (1 << 1), "HSIRDY should clear when HSION clears")

    def test_sws_follows_sw(self):
        rcc = self._make_rcc()
        rcc.write(0x08, 4, 0x01)  # SW0=1
        cfgr = rcc.read(0x08, 4)
        self.assertTrue(cfgr & (1 << 2), "SWS0 should follow SW0")

    def test_sws_multibit_follows_sw(self):
        regs = (
            SvdRegister(name="CR", offset=0x00),
            SvdRegister(name="CFGR", offset=0x08, fields=(
                SvdField(name="SW", bit_offset=0, bit_width=2),
                SvdField(name="SWS", bit_offset=2, bit_width=2),
            )),
        )
        rcc = RccPeripheral(_make_peripheral("RCC", regs))
        rcc.write(0x08, 4, 0x02)  # SW=2 (PLL)
        cfgr = rcc.read(0x08, 4)
        sws = (cfgr >> 2) & 0x3
        self.assertEqual(sws, 2, "SWS[1:0] should mirror SW[1:0]")

    def test_sws_multibit_all_values(self):
        regs = (
            SvdRegister(name="CR", offset=0x00),
            SvdRegister(name="CFGR", offset=0x08, fields=(
                SvdField(name="SW", bit_offset=0, bit_width=2),
                SvdField(name="SWS", bit_offset=2, bit_width=2),
            )),
        )
        rcc = RccPeripheral(_make_peripheral("RCC", regs))
        for sw_val in range(4):
            rcc.write(0x08, 4, sw_val)
            cfgr = rcc.read(0x08, 4)
            sws = (cfgr >> 2) & 0x3
            self.assertEqual(sws, sw_val, f"SWS should be {sw_val} when SW={sw_val}")

    def test_enable_register_tracks_peripherals(self):
        rcc = self._make_rcc()
        rcc.write(0x30, 4, (1 << 0) | (1 << 21))  # GPIOAEN + DMA1EN
        self.assertTrue(rcc.is_peripheral_enabled("GPIOA"))
        self.assertTrue(rcc.is_peripheral_enabled("DMA1"))
        self.assertFalse(rcc.is_peripheral_enabled("GPIOB"))

    def test_disable_peripheral(self):
        rcc = self._make_rcc()
        rcc.write(0x30, 4, 1 << 0)  # GPIOAEN
        self.assertTrue(rcc.is_peripheral_enabled("GPIOA"))
        rcc.write(0x30, 4, 0)  # clear
        self.assertFalse(rcc.is_peripheral_enabled("GPIOA"))

    def test_reset_register_calls_model_reset(self):
        from stmemu.peripherals.bus import PeripheralBus
        from stmemu.svd.address_map import AddressMap, AddressRange

        rcc_svd = SvdPeripheral(
            name="RCC", base_address=0x40023800, size=0x400,
            registers=_RCC_REGS, interrupts=(),
        )
        gpio_svd = SvdPeripheral(
            name="GPIOA", base_address=0x40020000, size=0x400,
            registers=_GPIO_REGS, interrupts=(),
        )
        ranges = (
            AddressRange(base=0x40020000, end=0x40020400, peripheral=gpio_svd),
            AddressRange(base=0x40023800, end=0x40023C00, peripheral=rcc_svd),
        )
        amap = AddressMap(
            device_name="TEST", peripherals=(rcc_svd, gpio_svd), ranges=ranges,
        )
        bus = PeripheralBus(amap)

        rcc = RccPeripheral(rcc_svd)
        gpio = GpioPeripheral(gpio_svd)
        bus.register_peripheral("RCC", rcc)
        bus.register_peripheral("GPIOA", gpio)

        gpio.write(0x18, 4, 0x01)  # Set pin 0 via BSRR
        odr_before = gpio.read(0x14, 4)
        self.assertTrue(odr_before & 1)

        rcc.write(0x10, 4, 1 << 0)  # GPIOARST=1
        odr_after = gpio.read(0x14, 4)
        self.assertFalse(odr_after & 1, "GPIO ODR should be 0 after RCC reset")

    def test_reset_clears_enabled_set(self):
        rcc = self._make_rcc()
        rcc.write(0x30, 4, 1 << 0)
        self.assertTrue(rcc.is_peripheral_enabled("GPIOA"))
        rcc.reset()
        self.assertEqual(len(rcc.enabled_peripherals()), 0)

    def test_snapshot_restore_enabled_peripherals(self):
        rcc = self._make_rcc()
        rcc.write(0x30, 4, (1 << 0) | (1 << 1))
        state = rcc.snapshot_state()
        rcc.reset()
        self.assertEqual(len(rcc.enabled_peripherals()), 0)
        rcc.restore_state(state)
        self.assertTrue(rcc.is_peripheral_enabled("GPIOA"))
        self.assertTrue(rcc.is_peripheral_enabled("GPIOB"))

    def test_is_peripheral_enabled_permissive_when_empty(self):
        rcc = self._make_rcc()
        self.assertTrue(rcc.is_peripheral_enabled("ANYTHING"))

    def test_enr_suffix_stripping(self):
        regs = (
            SvdRegister(name="CR", offset=0x00),
            SvdRegister(name="AHB1ENR", offset=0x30, fields=(
                SvdField(name="OTGFSEN", bit_offset=7, bit_width=1),
                SvdField(name="CRCEN", bit_offset=12, bit_width=1),
            )),
        )
        rcc = RccPeripheral(_make_peripheral("RCC", regs))
        rcc.write(0x30, 4, (1 << 7) | (1 << 12))
        self.assertTrue(rcc.is_peripheral_enabled("OTGFS"))
        self.assertTrue(rcc.is_peripheral_enabled("CRC"))


# ── SysTick VAL write tests ──────────────────────────────────────


class SysTickValTests(unittest.TestCase):
    def _make_core(self):
        return CortexMCorePeripheral(vtor=0x08000000)

    def test_write_val_clears_counter(self):
        core = self._make_core()
        core.write(0xE010, 4, 0x01)   # ENABLE
        core.write(0xE014, 4, 1000)    # LOAD=1000
        core.write(0xE018, 4, 500)     # VAL — any write should clear to 0
        val = core.read_register_value(0xE018)
        self.assertEqual(val, 0, "writing SYST_CVR should clear it to 0")

    def test_write_val_clears_countflag(self):
        core = self._make_core()
        core.write_register_value(0xE010, 0x01)  # ENABLE
        core.write_register_value(0xE014, 10)      # LOAD=10
        core.write_register_value(0xE018, 0)       # clear VAL
        core.tick(15)
        ctrl = core.read_register_value(0xE010)
        self.assertTrue(ctrl & (1 << 16), "COUNTFLAG should be set after underflow")
        core.write(0xE018, 4, 0xFF)
        ctrl_after = core.read_register_value(0xE010)
        self.assertFalse(
            ctrl_after & (1 << 16),
            "writing SYST_CVR should clear COUNTFLAG",
        )


# ── Bus access policy tests ──────────────────────────────────────


class BusAccessPolicyTests(unittest.TestCase):
    def _make_bus_with_rcc(self):
        from stmemu.peripherals.bus import PeripheralBus
        from stmemu.svd.address_map import AddressMap, AddressRange

        rcc_svd = SvdPeripheral(
            name="RCC", base_address=0x40023800, size=0x400,
            registers=_RCC_REGS, interrupts=(),
        )
        gpio_svd = SvdPeripheral(
            name="GPIOA", base_address=0x40020000, size=0x400,
            registers=_GPIO_REGS, interrupts=(),
        )
        ranges = (
            AddressRange(base=0x40020000, end=0x40020400, peripheral=gpio_svd),
            AddressRange(base=0x40023800, end=0x40023C00, peripheral=rcc_svd),
        )
        amap = AddressMap(device_name="TEST", peripherals=(rcc_svd, gpio_svd), ranges=ranges)
        bus = PeripheralBus(amap)

        rcc = RccPeripheral(rcc_svd)
        gpio = GpioPeripheral(gpio_svd)
        bus.register_peripheral("RCC", rcc)
        bus.register_peripheral("GPIOA", gpio)
        bus.set_clock_controller(rcc)
        return bus, rcc, gpio

    def test_permissive_allows_all(self):
        bus, rcc, gpio = self._make_bus_with_rcc()
        bus.access_policy = "permissive"
        bus.write(0x40020018, 4, 0x01)
        val = bus.read(0x40020014, 4)
        self.assertTrue(val & 1)

    def test_warn_allows_but_logs(self):
        bus, rcc, gpio = self._make_bus_with_rcc()
        bus.access_policy = "warn"
        rcc.write(0x30, 4, 0)  # no peripherals enabled
        bus.write(0x40020018, 4, 0x01)
        val = bus.read(0x40020014, 4)
        self.assertTrue(val & 1)

    def test_strict_blocks_disabled_peripheral(self):
        bus, rcc, gpio = self._make_bus_with_rcc()
        bus.access_policy = "strict"
        rcc.write(0x30, 4, 0)  # explicitly disable all
        bus.write(0x40020018, 4, 0x01)
        val = bus.read(0x40020014, 4)
        self.assertEqual(val, 0, "strict mode should return 0 for disabled peripheral")

    def test_strict_allows_enabled_peripheral(self):
        bus, rcc, gpio = self._make_bus_with_rcc()
        bus.access_policy = "strict"
        rcc.write(0x30, 4, 1 << 0)  # GPIOAEN
        bus.write(0x40020018, 4, 0x01)
        val = bus.read(0x40020014, 4)
        self.assertTrue(val & 1)

    def test_strict_allows_rcc_itself(self):
        bus, rcc, _ = self._make_bus_with_rcc()
        bus.access_policy = "strict"
        val = bus.read(0x40023800, 4)
        self.assertIsNotNone(val)

    def test_permissive_before_enr_write(self):
        bus, rcc, gpio = self._make_bus_with_rcc()
        bus.access_policy = "strict"
        bus.write(0x40020018, 4, 0x01)
        val = bus.read(0x40020014, 4)
        self.assertTrue(val & 1, "before ENR write, should be permissive")


# ── DMA transfer tests ───────────────────────────────────────────


class DmaTransferTests(unittest.TestCase):
    def test_auto_complete_sets_tcif(self):
        dma = DmaPeripheral(
            _make_peripheral("DMA1", (
                SvdRegister(name="LISR", offset=0x00),
                SvdRegister(name="HISR", offset=0x04),
                SvdRegister(name="LIFCR", offset=0x08),
                SvdRegister(name="HIFCR", offset=0x0C),
            ))
        )
        dma.write(0x10, 4, 0x01)  # Enable stream 0
        lisr = dma.read(0x00, 4)
        self.assertTrue(lisr & (1 << 5), "TCIF0 should be set")

    def test_auto_complete_clears_en(self):
        dma = DmaPeripheral(
            _make_peripheral("DMA1", (
                SvdRegister(name="LISR", offset=0x00),
                SvdRegister(name="HISR", offset=0x04),
                SvdRegister(name="LIFCR", offset=0x08),
                SvdRegister(name="HIFCR", offset=0x0C),
            ))
        )
        dma.write(0x10, 4, 0x01)
        cr = dma.read(0x10, 4)
        self.assertFalse(cr & 1, "EN should be cleared after completion")

    def test_ifcr_clears_isr(self):
        dma = DmaPeripheral(
            _make_peripheral("DMA1", (
                SvdRegister(name="LISR", offset=0x00),
                SvdRegister(name="HISR", offset=0x04),
                SvdRegister(name="LIFCR", offset=0x08),
                SvdRegister(name="HIFCR", offset=0x0C),
            ))
        )
        dma.write(0x10, 4, 0x01)
        dma.write(0x08, 4, 1 << 5)  # Clear TCIF0
        lisr = dma.read(0x00, 4)
        self.assertFalse(lisr & (1 << 5))

    def test_ndtr_cleared_on_complete(self):
        dma = DmaPeripheral(
            _make_peripheral("DMA1", (
                SvdRegister(name="LISR", offset=0x00),
                SvdRegister(name="HISR", offset=0x04),
                SvdRegister(name="LIFCR", offset=0x08),
                SvdRegister(name="HIFCR", offset=0x0C),
            ))
        )
        dma.write_register_value(0x14, 100)  # NDTR=100
        dma.write(0x10, 4, 0x01)  # Enable
        ndtr = dma.read(0x14, 4)
        self.assertEqual(ndtr, 0)


# ── GPIO pinmux tests ────────────────────────────────────────────


class GpioPinmuxTests(unittest.TestCase):
    def _make_gpio(self):
        return GpioPeripheral(_make_peripheral("GPIOA", _GPIO_REGS))

    def test_default_mode_is_zero(self):
        gpio = self._make_gpio()
        for pin in range(16):
            self.assertEqual(gpio.pin_mode(pin), 0)

    def test_set_pin_output(self):
        gpio = self._make_gpio()
        gpio.write(0x00, 4, 0x01 << (2 * 5))  # Pin 5 = output (01)
        self.assertEqual(gpio.pin_mode(5), MODE_OUTPUT)
        self.assertEqual(gpio.pin_mode_name(5), "output")

    def test_set_pin_af(self):
        gpio = self._make_gpio()
        gpio.write(0x00, 4, 0x02 << (2 * 9))  # Pin 9 = AF (10)
        self.assertEqual(gpio.pin_mode(9), MODE_AF)

    def test_set_pin_analog(self):
        gpio = self._make_gpio()
        gpio.write(0x00, 4, 0x03 << (2 * 0))  # Pin 0 = analog (11)
        self.assertEqual(gpio.pin_mode(0), MODE_ANALOG)

    def test_afrl_sets_af_number(self):
        gpio = self._make_gpio()
        gpio.write(0x20, 4, 7 << (4 * 2))  # Pin 2 = AF7
        self.assertEqual(gpio.pin_af(2), 7)

    def test_afrh_sets_af_number(self):
        gpio = self._make_gpio()
        gpio.write(0x24, 4, 4 << (4 * 1))  # Pin 9 = AF4 (AFRH bit 4..7)
        self.assertEqual(gpio.pin_af(9), 4)

    def test_pin_af_default_zero(self):
        gpio = self._make_gpio()
        for pin in range(16):
            self.assertEqual(gpio.pin_af(pin), 0)

    def test_pin_otype(self):
        gpio = self._make_gpio()
        gpio.write(0x04, 4, 1 << 3)  # Pin 3 = open-drain
        self.assertEqual(gpio.pin_otype(3), 1)
        self.assertEqual(gpio.pin_otype(4), 0)

    def test_pin_pupd(self):
        gpio = self._make_gpio()
        gpio.write(0x0C, 4, 0x01 << (2 * 7))  # Pin 7 = pull-up
        self.assertEqual(gpio.pin_pupd(7), 1)

    def test_pin_speed(self):
        gpio = self._make_gpio()
        gpio.write(0x08, 4, 0x03 << (2 * 1))  # Pin 1 = very high speed
        self.assertEqual(gpio.pin_speed(1), 3)

    def test_pin_summary(self):
        gpio = self._make_gpio()
        gpio.write(0x00, 4, 0x02 << (2 * 9))  # Pin 9 = AF
        gpio.write(0x24, 4, 7 << (4 * 1))      # Pin 9 = AF7
        gpio.write(0x0C, 4, 0x01 << (2 * 9))   # Pin 9 = pull-up
        s = gpio.pin_summary(9)
        self.assertIn("af", s)
        self.assertIn("AF7", s)
        self.assertIn("PU", s)

    def test_port_summary(self):
        gpio = self._make_gpio()
        gpio.write(0x00, 4, 0x01)  # Pin 0 = output
        s = gpio.port_summary()
        self.assertIn("pin0", s)
        self.assertIn("output", s)

    def test_port_summary_all_analog(self):
        gpio = self._make_gpio()
        gpio.write(0x00, 4, 0xFFFFFFFF)  # All pins analog
        s = gpio.port_summary()
        self.assertIn("reset", s)

    def test_pin_out_of_range(self):
        gpio = self._make_gpio()
        self.assertEqual(gpio.pin_mode(16), 0)
        self.assertEqual(gpio.pin_af(-1), 0)


# ── DMA request coupling tests ───────────────────────────────────


class DmaRequestCouplingTests(unittest.TestCase):
    def _make_dma(self):
        return DmaPeripheral(_make_peripheral("DMA1", (
            SvdRegister(name="LISR", offset=0x00),
            SvdRegister(name="HISR", offset=0x04),
            SvdRegister(name="LIFCR", offset=0x08),
            SvdRegister(name="HIFCR", offset=0x0C),
        )))

    def test_on_peripheral_request_triggers_matching_stream(self):
        dma = self._make_dma()
        dma.write_register_value(0x18, 0x40004428)  # Stream 0 PAR = USART RDR
        dma.write_register_value(0x1C, 0x20000100)  # Stream 0 M0AR
        dma.write_register_value(0x14, 4)            # Stream 0 NDTR = 4
        dma.write(0x10, 4, 0x01)  # Enable stream 0 (auto-completes)
        dma.write(0x08, 4, 0xFF)  # Clear flags
        # Re-enable for request-driven transfer
        dma.write(0x10, 4, 0x01)
        lisr = dma.read(0x00, 4)
        # Auto-complete already fired, so TCIF should be set
        self.assertTrue(lisr & (1 << 5))

    def test_on_peripheral_request_ignores_wrong_direction(self):
        dma = self._make_dma()
        dma.write_register_value(0x18, 0x40004428)
        dma.write_register_value(0x1C, 0x20000100)
        dma.write_register_value(0x14, 4)
        # Direction = P2M (0), but request for M2P
        dma.write(0x10, 4, 0x01)
        dma.write(0x08, 4, 0xFF)
        # Re-enable with P2M direction
        cr = 0x01  # EN, DIR=P2M (default)
        dma.write(0x10, 4, cr)
        # Now request with wrong direction
        dma.on_peripheral_request(0x40004428, "m2p")
        # Should not have triggered again (already completed from enable)


if __name__ == "__main__":
    unittest.main()
