"""Tests for timed event execution during emulation."""
from __future__ import annotations

import sys
import types
import unittest

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
from stmemu.peripherals.bus import PeripheralBus, PeripheralEvent
from stmemu.peripherals.gpio import GpioPeripheral
from stmemu.peripherals.usart import Stm32UsartPeripheral
from stmemu.peripherals.adc import Stm32AdcPeripheral


_GPIO_REGS = (
    SvdRegister(name="MODER", offset=0x00),
    SvdRegister(name="IDR", offset=0x10, access="ro"),
    SvdRegister(name="ODR", offset=0x14),
    SvdRegister(name="BSRR", offset=0x18, access="wo"),
    SvdRegister(name="AFRL", offset=0x20),
    SvdRegister(name="AFRH", offset=0x24),
)

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


class _FakeUc:
    def emu_stop(self):
        pass


class _TimedEmu:
    """Minimal emulator with timed event support for testing."""

    def __init__(self, bus):
        self.bus = bus
        self.pc = 0x08000100
        self.uc = _FakeUc()
        self._running = False
        self._instruction_count = 0
        self._timed_events = []
        self._snapshots = {}
        self.last_event_break = None
        self._event_breakpoints = []
        self._event_bp_next_id = 1

        # Event breakpoint handler
        self._subscribed_kinds = set()

    @property
    def instruction_count(self):
        return self._instruction_count

    def add_timed_event(self, at, action, **params):
        evt = {"at": int(at), "action": str(action), "fired": False}
        evt.update(params)
        self._timed_events.append(evt)
        self._timed_events.sort(key=lambda e: e["at"])
        return evt

    def list_timed_events(self):
        return [dict(e) for e in self._timed_events]

    def clear_timed_events(self):
        count = len(self._timed_events)
        self._timed_events.clear()
        return count

    def simulate_instructions(self, count):
        """Simulate N instructions, checking timed events each step."""
        self._running = True
        for _ in range(count):
            self._instruction_count += 1
            self.bus.tick(1)
            self._check_timed_events()
        self._running = False

    def _check_timed_events(self):
        if not self._timed_events:
            return
        ic = self._instruction_count
        while self._timed_events and self._timed_events[0]["at"] <= ic:
            evt = self._timed_events[0]
            if evt["fired"]:
                self._timed_events.pop(0)
                continue
            evt["fired"] = True
            self._timed_events.pop(0)
            self._execute_timed_action(evt)

    def _execute_timed_action(self, evt):
        from stmemu.utils.logger import get_logger
        log = get_logger(__name__)
        action = evt.get("action", "")

        if action == "gpio_inject":
            port = str(evt.get("port", "")).upper()
            pin = int(evt.get("pin", 0))
            level = str(evt.get("level", "high")).lower()
            model = self.bus.model_for_name(port)
            if model is not None and hasattr(model, "set_input_level"):
                model.set_input_level(pin, level in ("high", "1", "true"))

        elif action == "uart_inject":
            periph = str(evt.get("peripheral", "")).upper()
            model = self.bus.model_for_name(periph)
            if model is not None and hasattr(model, "inject_rx_bytes"):
                hex_data = evt.get("hex", "")
                data = bytes.fromhex(str(hex_data)) if hex_data else b""
                if data:
                    model.inject_rx_bytes(data)

        elif action == "adc_sample":
            periph = str(evt.get("peripheral", "")).upper()
            model = self.bus.model_for_name(periph)
            if model is not None and hasattr(model, "inject_sample"):
                model.inject_sample(int(evt.get("value", 0)))

        elif action == "event_emit":
            kind = str(evt.get("kind", "custom"))
            source = str(evt.get("source", "timed"))
            self.bus.emit(PeripheralEvent(
                kind=kind, source=source, payload=evt.get("payload"),
            ))

        elif action == "snapshot":
            name = str(evt.get("name", f"timed_{evt['at']}"))
            self._snapshots[name] = {"ic": self._instruction_count}

    def save_snapshot(self, name):
        self._snapshots[name] = {"ic": self._instruction_count}


def _make_bus():
    gpio_svd = _make_svd("GPIOA", 0x40020000, _GPIO_REGS)
    usart_svd = _make_svd("USART1", 0x40004400, _USART_REGS,
        interrupts=(SvdInterrupt(name="USART1", value=37),))
    adc_svd = _make_svd("ADC1", 0x40012000, _ADC_REGS,
        interrupts=(SvdInterrupt(name="ADC1_2", value=18),))
    ranges = (
        AddressRange(base=0x40004400, end=0x40004800, peripheral=usart_svd),
        AddressRange(base=0x40012000, end=0x40012400, peripheral=adc_svd),
        AddressRange(base=0x40020000, end=0x40020400, peripheral=gpio_svd),
    )
    amap = AddressMap(device_name="TEST",
        peripherals=(usart_svd, adc_svd, gpio_svd), ranges=ranges)
    bus = PeripheralBus(amap)
    gpio = GpioPeripheral(gpio_svd)
    uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=37)
    adc = Stm32AdcPeripheral(peripheral=adc_svd, irq=18)
    bus.register_peripheral("GPIOA", gpio)
    bus.register_peripheral("USART1", uart)
    bus.register_peripheral("ADC1", adc)
    return bus, gpio, uart, adc


# ── Core timed event tests ───────────────────────────────────────


class TimedEventTests(unittest.TestCase):
    def test_gpio_inject_at_instruction(self):
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)
        emu.add_timed_event(10, "gpio_inject", port="GPIOA", pin=3, level="high")

        emu.simulate_instructions(9)
        self.assertFalse(gpio.read(0x10, 4) & (1 << 3))

        emu.simulate_instructions(1)
        self.assertTrue(gpio.read(0x10, 4) & (1 << 3))

    def test_uart_inject_at_instruction(self):
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)
        emu.add_timed_event(5, "uart_inject", peripheral="USART1", hex="48656C6C6F")

        emu.simulate_instructions(5)
        data = uart.drain_tx_bytes()
        rx = []
        while uart._rx_fifo:
            rx.append(uart._rx_fifo.popleft())
        self.assertEqual(bytes(rx), b"Hello")

    def test_adc_sample_at_instruction(self):
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)
        emu.add_timed_event(20, "adc_sample", peripheral="ADC1", value=3333)

        emu.simulate_instructions(20)
        self.assertEqual(len(adc._sample_queue), 1)
        self.assertEqual(adc._sample_queue[0], 3333)

    def test_event_emit_at_instruction(self):
        bus, gpio, uart, adc = _make_bus()
        bus.event_log_enabled = True
        emu = _TimedEmu(bus)
        emu.add_timed_event(15, "event_emit", kind="custom_event", source="test")

        emu.simulate_instructions(15)
        log = bus.drain_event_log()
        custom = [e for e in log if e.kind == "custom_event"]
        self.assertEqual(len(custom), 1)
        self.assertEqual(custom[0].source, "test")

    def test_snapshot_at_instruction(self):
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)
        emu.add_timed_event(25, "snapshot", name="checkpoint_25")

        emu.simulate_instructions(25)
        self.assertIn("checkpoint_25", emu._snapshots)

    def test_multiple_events_ordered(self):
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)
        emu.add_timed_event(20, "gpio_inject", port="GPIOA", pin=1, level="high")
        emu.add_timed_event(10, "gpio_inject", port="GPIOA", pin=0, level="high")

        emu.simulate_instructions(15)
        idr = gpio.read(0x10, 4)
        self.assertTrue(idr & (1 << 0), "pin 0 should be set at ic=10")
        self.assertFalse(idr & (1 << 1), "pin 1 not yet at ic=15")

        emu.simulate_instructions(5)
        idr = gpio.read(0x10, 4)
        self.assertTrue(idr & (1 << 1), "pin 1 should be set at ic=20")

    def test_events_fire_only_once(self):
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)
        emu.add_timed_event(5, "adc_sample", peripheral="ADC1", value=100)

        emu.simulate_instructions(10)
        self.assertEqual(len(adc._sample_queue), 1)

    def test_past_events_fire_immediately(self):
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)
        emu.simulate_instructions(50)
        emu.add_timed_event(10, "gpio_inject", port="GPIOA", pin=0, level="high")
        emu.simulate_instructions(1)
        self.assertTrue(gpio.read(0x10, 4) & 1)

    def test_add_list_clear(self):
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)
        emu.add_timed_event(10, "gpio_inject", port="GPIOA", pin=0)
        emu.add_timed_event(20, "adc_sample", peripheral="ADC1", value=1)

        events = emu.list_timed_events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["at"], 10)
        self.assertEqual(events[1]["at"], 20)

        count = emu.clear_timed_events()
        self.assertEqual(count, 2)
        self.assertEqual(len(emu.list_timed_events()), 0)


# ── Edge case and integration validation ─────────────────────────


class TimedEventEdgeCaseTests(unittest.TestCase):
    def test_multiple_overdue_events_all_fire(self):
        """Events at 100, 101, 102 all fire when run(10000) skips past them."""
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)
        emu.add_timed_event(100, "gpio_inject", port="GPIOA", pin=0, level="high")
        emu.add_timed_event(101, "gpio_inject", port="GPIOA", pin=1, level="high")
        emu.add_timed_event(102, "gpio_inject", port="GPIOA", pin=2, level="high")

        emu.simulate_instructions(200)
        idr = gpio.read(0x10, 4)
        self.assertTrue(idr & (1 << 0), "pin 0 should fire at ic=100")
        self.assertTrue(idr & (1 << 1), "pin 1 should fire at ic=101")
        self.assertTrue(idr & (1 << 2), "pin 2 should fire at ic=102")
        self.assertEqual(len(emu.list_timed_events()), 0, "all events consumed")

    def test_overdue_events_fire_in_order(self):
        """When multiple events become due at the same check, they fire in at-order."""
        bus, gpio, uart, adc = _make_bus()
        bus.event_log_enabled = True
        emu = _TimedEmu(bus)
        emu.add_timed_event(5, "event_emit", kind="first", source="t")
        emu.add_timed_event(5, "event_emit", kind="second", source="t")
        emu.add_timed_event(6, "event_emit", kind="third", source="t")

        emu.simulate_instructions(10)
        log = bus.drain_event_log()
        custom = [e.kind for e in log if e.source == "t"]
        self.assertEqual(custom, ["first", "second", "third"])

    def test_timed_gpio_triggers_exti(self):
        """Timed GPIO injection should fire EXTI if configured."""
        from stmemu.peripherals.exti import ExtiPeripheral

        bus, gpio, uart, adc = _make_bus()

        class _FakeNvic:
            pending = {}
            def set_irq_pending(self, irq, pending=True):
                self.pending[irq] = pending
            def set_system_pending(self, name, pending=True):
                pass
        nvic = _FakeNvic()
        bus._interrupts = nvic

        exti = ExtiPeripheral(irq_map={0: 6})
        bus.mount(name="EXTI", base=0x40013C00, size=0x400, model=exti)
        exti.write_register_value(exti._RTSR, 1 << 0)
        exti.write_register_value(exti._IMR, 1 << 0)

        emu = _TimedEmu(bus)
        emu.add_timed_event(50, "gpio_inject", port="GPIOA", pin=0, level="high")
        emu.simulate_instructions(50)

        pr = exti.read_register_value(exti._PR)
        self.assertTrue(pr & 1, "EXTI PR should be set from timed GPIO injection")
        self.assertTrue(nvic.pending.get(6, False), "EXTI IRQ should pend")

    def test_timed_uart_inject_feeds_dma(self):
        """Timed UART injection should trigger DMA if DMAR is enabled."""
        from stmemu.peripherals.dma import DmaPeripheral

        dma_svd = _make_svd("DMA1", 0x40026000, (
            SvdRegister(name="LISR", offset=0x00),
            SvdRegister(name="HISR", offset=0x04),
            SvdRegister(name="LIFCR", offset=0x08),
            SvdRegister(name="HIFCR", offset=0x0C),
        ), interrupts=(SvdInterrupt(name="DMA1_Stream0", value=11),))

        usart_svd = _make_svd("USART1", 0x40004400, _USART_REGS,
            interrupts=(SvdInterrupt(name="USART1", value=37),))

        ranges = (
            AddressRange(base=0x40004400, end=0x40004800, peripheral=usart_svd),
            AddressRange(base=0x40026000, end=0x40026400, peripheral=dma_svd),
        )
        amap = AddressMap(device_name="TEST",
            peripherals=(usart_svd, dma_svd), ranges=ranges)
        bus = PeripheralBus(amap)

        class _FakeMemEmu:
            _mem = bytearray(0x1000)
            def mem_write(self, addr, data):
                off = addr & 0xFFF
                self._mem[off:off+len(data)] = data
            def mem_read(self, addr, size):
                off = addr & 0xFFF
                return bytes(self._mem[off:off+size])
        mem_emu = _FakeMemEmu()
        bus._emulator = mem_emu

        uart = Stm32UsartPeripheral(peripheral=usart_svd, irq=37)
        dma = DmaPeripheral(peripheral=dma_svd)
        bus.register_peripheral("USART1", uart)
        bus.register_peripheral("DMA1", dma)

        # Enable USART with DMA
        uart.write(0x00, 4, (1 << 0) | (1 << 2))  # UE + RE
        uart.write(0x08, 4, 1 << 6)  # CR3.DMAR

        # Configure DMA circular on stream 0 for USART1 RDR
        rdr_addr = 0x40004400 + 0x24
        so = dma._STREAM_BASE
        dma.write_register_value(so + dma._SxNDTR, 8)
        dma.write_register_value(so + dma._SxPAR, rdr_addr)
        dma.write_register_value(so + dma._SxM0AR, 0x200)
        cr = dma._SxCR_EN | dma._SxCR_CIRC | dma._SxCR_MINC
        dma.write(so + dma._SxCR, 4, cr)

        emu = _TimedEmu(bus)
        emu.add_timed_event(100, "uart_inject", peripheral="USART1", hex="414243")

        emu.simulate_instructions(100)

        data = mem_emu.mem_read(0x200, 3)
        self.assertEqual(data, b"ABC", "timed UART inject should flow through DMA to memory")

    def test_event_breakpoint_from_timed_emit(self):
        """Event breakpoint should fire from a timed event_emit action."""
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)

        # Set up event breakpoint
        emu._event_breakpoints.append({
            "id": 1, "kind": "scenario_trigger", "source": None,
            "enabled": True, "hits": 0, "name": "test",
        })
        bus.subscribe("scenario_trigger", lambda e: _fake_bp_handler(emu, e))

        emu.add_timed_event(75, "event_emit", kind="scenario_trigger", source="scenario")
        emu.simulate_instructions(75)

        self.assertIsNotNone(emu.last_event_break)
        self.assertEqual(emu.last_event_break["kind"], "scenario_trigger")


def _fake_bp_handler(emu, event):
    if not emu._running:
        return
    for bp in emu._event_breakpoints:
        if bp["kind"] == event.kind and bp["enabled"]:
            bp["hits"] += 1
            emu.last_event_break = {
                "bp_id": bp["id"], "kind": event.kind,
                "source": getattr(event, "source", ""),
            }
            return


# ── Board config integration ─────────────────────────────────────


class TimedEventBoardConfigTests(unittest.TestCase):
    def test_board_config_schedules_events(self):
        from stmemu.board_config import apply_board_config
        bus, gpio, uart, adc = _make_bus()
        emu = _TimedEmu(bus)

        cfg = {
            "timed_events": [
                {"at": 100, "action": "gpio_inject", "port": "GPIOA", "pin": 5, "level": "high"},
                {"at": 200, "action": "adc_sample", "peripheral": "ADC1", "value": 4095},
            ],
        }
        msgs = apply_board_config(cfg, bus, emu)
        self.assertTrue(any("2 scheduled" in m for m in msgs))

        events = emu.list_timed_events()
        self.assertEqual(len(events), 2)

        emu.simulate_instructions(100)
        self.assertTrue(gpio.read(0x10, 4) & (1 << 5))

        emu.simulate_instructions(100)
        self.assertEqual(len(adc._sample_queue), 1)


# ── Shell command tests ───────────────────────────────────────────


class TimedEventShellTests(unittest.TestCase):
    def setUp(self):
        from stmemu.shell.commands import Commands
        from stmemu.core.symbols import SymbolTable
        from stmemu.core.semihosting import SemihostingHandler

        bus, gpio, uart, adc = _make_bus()
        self.bus = bus
        self.emu = _TimedEmu(bus)
        self.emu.symbols = SymbolTable()
        self.emu.semihosting = SemihostingHandler()
        self.emu.coverage_enabled = False
        self.emu._coverage = set()
        self.emu._coverage_hits = {}
        self.emu.flash_base = 0x08000000
        self.emu.flash_end = 0x08010000
        self.cmds = Commands(emu=self.emu, bus=self.bus)

    def test_timed_add(self):
        out = self.cmds.cmd_timed(["add", "100", "gpio_inject", "port=GPIOA", "pin=0", "level=high"])
        self.assertIn("@100", out)

    def test_timed_list(self):
        self.cmds.cmd_timed(["add", "50", "adc_sample", "peripheral=ADC1", "value=1000"])
        out = self.cmds.cmd_timed(["list"])
        self.assertIn("adc_sample", out)
        self.assertIn("50", out)

    def test_timed_list_empty(self):
        out = self.cmds.cmd_timed(["list"])
        self.assertIn("no timed events", out)

    def test_timed_clear(self):
        self.cmds.cmd_timed(["add", "10", "gpio_inject"])
        out = self.cmds.cmd_timed(["clear"])
        self.assertIn("cleared 1", out)

    def test_timed_count(self):
        self.emu._instruction_count = 42
        out = self.cmds.cmd_timed(["count"])
        self.assertIn("42", out)

    def test_timed_usage(self):
        out = self.cmds.cmd_timed([])
        self.assertIn("usage:", out)


if __name__ == "__main__":
    unittest.main()
