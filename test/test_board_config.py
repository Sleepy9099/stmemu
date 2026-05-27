"""Tests for board topology config loader."""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

# ── Stub external dependencies ─────────────────────────────────────

if "capstone" not in sys.modules:
    _cs = types.ModuleType("capstone")
    class _Cs:
        def __init__(self, *a, **k): self.detail = False
        def disasm(self, code, addr, count=0): return []
    _cs.Cs = _Cs
    _cs.CS_ARCH_ARM = 0
    _cs.CS_MODE_THUMB = 0
    sys.modules["capstone"] = _cs

if "unicorn" not in sys.modules:
    _uc = types.ModuleType("unicorn")
    _uc_const = types.ModuleType("unicorn.unicorn_const")
    _uc_const.UC_HOOK_CODE = 0
    _uc.unicorn_const = _uc_const
    sys.modules["unicorn"] = _uc
    sys.modules["unicorn.unicorn_const"] = _uc_const

if "stmemu.core.emulator" not in sys.modules:
    _emu_mod = types.ModuleType("stmemu.core.emulator")
    class _PcRegWrite: pass
    class _Emulator: pass
    _emu_mod.PcRegWrite = _PcRegWrite
    _emu_mod.Emulator = _Emulator
    sys.modules["stmemu.core.emulator"] = _emu_mod

from stmemu.svd.model import SvdPeripheral, SvdRegister, SvdInterrupt
from stmemu.svd.address_map import AddressMap, AddressRange
from stmemu.peripherals.bus import PeripheralBus
from stmemu.peripherals.usart import Stm32UsartPeripheral
from stmemu.peripherals.i2c import I2cPeripheral
from stmemu.peripherals.gpio import GpioPeripheral
from stmemu.peripherals.adc import Stm32AdcPeripheral
from stmemu.board_config import load_board_config, apply_board_config


_USART_REGS = (
    SvdRegister(name="CR1", offset=0x00),
    SvdRegister(name="CR2", offset=0x04),
    SvdRegister(name="CR3", offset=0x08),
    SvdRegister(name="BRR", offset=0x0C),
    SvdRegister(name="RQR", offset=0x18),
    SvdRegister(name="ISR", offset=0x1C),
    SvdRegister(name="ICR", offset=0x20),
    SvdRegister(name="RDR", offset=0x24),
    SvdRegister(name="TDR", offset=0x28),
)

_I2C_REGS = (
    SvdRegister(name="CR1", offset=0x00),
    SvdRegister(name="CR2", offset=0x04),
    SvdRegister(name="ISR", offset=0x18),
    SvdRegister(name="ICR", offset=0x1C),
    SvdRegister(name="RXDR", offset=0x24),
    SvdRegister(name="TXDR", offset=0x28),
)

_GPIO_REGS = (
    SvdRegister(name="MODER", offset=0x00),
    SvdRegister(name="IDR", offset=0x10, access="ro"),
    SvdRegister(name="ODR", offset=0x14),
    SvdRegister(name="BSRR", offset=0x18, access="wo"),
    SvdRegister(name="AFRL", offset=0x20),
    SvdRegister(name="AFRH", offset=0x24),
)

_ADC_REGS = (
    SvdRegister(name="ISR", offset=0x00),
    SvdRegister(name="IER", offset=0x04),
    SvdRegister(name="CR", offset=0x08),
    SvdRegister(name="CFGR", offset=0x0C),
    SvdRegister(name="DR", offset=0x40),
)


def _make_svd(name, base, regs=(), interrupts=()):
    return SvdPeripheral(name=name, base_address=base, size=0x400,
                         registers=regs, interrupts=interrupts)


def _make_bus():
    usart_svd = _make_svd("USART1", 0x40004400, _USART_REGS,
        interrupts=(SvdInterrupt(name="USART1", value=37),))
    i2c_svd = _make_svd("I2C1", 0x40005400, _I2C_REGS,
        interrupts=(SvdInterrupt(name="I2C1_EV", value=31),))
    gpio_svd = _make_svd("GPIOA", 0x40020000, _GPIO_REGS)
    adc_svd = _make_svd("ADC1", 0x40012000, _ADC_REGS,
        interrupts=(SvdInterrupt(name="ADC1_2", value=18),))

    ranges = (
        AddressRange(base=0x40004400, end=0x40004800, peripheral=usart_svd),
        AddressRange(base=0x40005400, end=0x40005800, peripheral=i2c_svd),
        AddressRange(base=0x40012000, end=0x40012400, peripheral=adc_svd),
        AddressRange(base=0x40020000, end=0x40020400, peripheral=gpio_svd),
    )
    amap = AddressMap(
        device_name="TEST",
        peripherals=(usart_svd, i2c_svd, adc_svd, gpio_svd),
        ranges=ranges,
    )
    bus = PeripheralBus(amap)

    uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=37)
    i2c = I2cPeripheral(peripheral=i2c_svd, irq=31)
    gpio = GpioPeripheral(gpio_svd)
    adc = Stm32AdcPeripheral(peripheral=adc_svd, irq=18)

    bus.register_peripheral("USART1", uart)
    bus.register_peripheral("I2C1", i2c)
    bus.register_peripheral("GPIOA", gpio)
    bus.register_peripheral("ADC1", adc)

    return bus, uart, i2c, gpio, adc


class BoardConfigLoadTests(unittest.TestCase):
    def test_load_json(self):
        cfg = {"bus_policy": "warn", "gpio_levels": {"GPIOA": {"0": "high"}}}
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(cfg, f)
            f.flush()
            result = load_board_config(Path(f.name))
        self.assertEqual(result["bus_policy"], "warn")

    def test_load_yaml(self):
        yaml_text = "bus_policy: permissive\n"
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(yaml_text)
            f.flush()
            result = load_board_config(Path(f.name))
        self.assertEqual(result["bus_policy"], "permissive")


class BoardConfigApplyTests(unittest.TestCase):
    def test_uart_device_attach(self):
        bus, uart, i2c, gpio, adc = _make_bus()
        cfg = {
            "uart_devices": [{
                "peripheral": "USART1",
                "device": "ublox",
                "mode": "nmea",
                "lat": 51.5,
            }],
        }
        msgs = apply_board_config(cfg, bus)
        self.assertTrue(any("attached" in m for m in msgs))
        self.assertEqual(len(bus.serial_lines()), 1)

    def test_i2c_device_attach(self):
        bus, uart, i2c, gpio, adc = _make_bus()
        cfg = {
            "i2c_devices": [{
                "peripheral": "I2C1",
                "devices": [
                    {"type": "imu", "address": "0x68", "whoami_reg": "0x75", "whoami_value": "0x71"},
                    {"type": "eeprom", "address": "0x50"},
                ],
            }],
        }
        msgs = apply_board_config(cfg, bus)
        self.assertTrue(any("imu" in m for m in msgs))
        self.assertTrue(any("eeprom" in m for m in msgs))

    def test_gpio_levels(self):
        bus, uart, i2c, gpio, adc = _make_bus()
        cfg = {
            "gpio_levels": {
                "GPIOA": {"0": "high", "3": "low"},
            },
        }
        msgs = apply_board_config(cfg, bus)
        idr = gpio.read(0x10, 4)
        self.assertTrue(idr & (1 << 0))
        self.assertFalse(idr & (1 << 3))
        self.assertTrue(any("2 pin" in m for m in msgs))

    def test_adc_config(self):
        bus, uart, i2c, gpio, adc = _make_bus()
        cfg = {
            "adc": {
                "ADC1": {
                    "default_sample": 3000,
                    "trigger": "TIM2",
                    "samples": [100, 200],
                },
            },
        }
        msgs = apply_board_config(cfg, bus)
        self.assertEqual(adc.default_sample, 3000)
        self.assertEqual(adc._trigger_source, "TIM2")
        self.assertEqual(len(adc._sample_queue), 2)

    def test_bus_policy(self):
        bus, uart, i2c, gpio, adc = _make_bus()
        cfg = {"bus_policy": "warn"}
        apply_board_config(cfg, bus)
        self.assertEqual(bus.access_policy, "warn")

    def test_unknown_peripheral_handled(self):
        bus, uart, i2c, gpio, adc = _make_bus()
        cfg = {
            "uart_devices": [{"peripheral": "USART99", "device": "ublox"}],
        }
        msgs = apply_board_config(cfg, bus)
        self.assertTrue(any("not found" in m for m in msgs))

    def test_full_board_config(self):
        bus, uart, i2c, gpio, adc = _make_bus()
        cfg = {
            "bus_policy": "permissive",
            "uart_devices": [{"peripheral": "USART1", "device": "ublox", "mode": "ubx"}],
            "i2c_devices": [{"peripheral": "I2C1", "devices": [
                {"type": "imu", "address": "0x68"},
            ]}],
            "gpio_levels": {"GPIOA": {"5": "high"}},
            "adc": {"ADC1": {"default_sample": 1024}},
        }
        msgs = apply_board_config(cfg, bus)
        self.assertGreater(len(msgs), 3)
        self.assertEqual(len(bus.serial_lines()), 1)
        self.assertTrue(gpio.read(0x10, 4) & (1 << 5))
        self.assertEqual(adc.default_sample, 1024)

    def test_i2c_register_device_with_initial_values(self):
        bus, uart, i2c, gpio, adc = _make_bus()
        cfg = {
            "i2c_devices": [{
                "peripheral": "I2C1",
                "devices": [{
                    "type": "register",
                    "address": "0x48",
                    "registers": {"0x00": "0x42", "0x01": "0xFF"},
                }],
            }],
        }
        msgs = apply_board_config(cfg, bus)
        self.assertTrue(any("register" in m or "reg" in m for m in msgs))


class BoardConfigShellTests(unittest.TestCase):
    def setUp(self):
        from stmemu.shell.commands import Commands
        from stmemu.core.symbols import SymbolTable
        from stmemu.core.semihosting import SemihostingHandler

        self.bus, self.uart, self.i2c, self.gpio, self.adc = _make_bus()

        class _FakeEmu:
            symbols = SymbolTable()
            semihosting = SemihostingHandler()
            coverage_enabled = False
            _coverage = set()
            _coverage_hits = {}
            flash_base = 0x08000000
            flash_end = 0x08010000
            pc = 0x08000100
        self.cmds = Commands(emu=_FakeEmu(), bus=self.bus)

    def test_board_load_json(self):
        cfg = {
            "gpio_levels": {"GPIOA": {"0": "high"}},
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(cfg, f)
            f.flush()
            out = self.cmds.cmd_board(["load", f.name])
        self.assertIn("gpio", out)

    def test_board_load_missing(self):
        out = self.cmds.cmd_board(["load", "/nonexistent/board.json"])
        self.assertIn("error", out)

    def test_board_usage(self):
        out = self.cmds.cmd_board([])
        self.assertIn("usage:", out)


if __name__ == "__main__":
    unittest.main()
