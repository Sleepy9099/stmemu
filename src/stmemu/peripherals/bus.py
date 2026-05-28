from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional, Protocol

from stmemu.svd.address_map import AddressMap
from stmemu.svd.model import SvdPeripheral
from stmemu.utils.logger import get_logger

log = get_logger(__name__)

AccessType = Literal["r", "w", "rw"]
AccessPolicy = Literal["permissive", "warn", "strict"]

EventHandler = Callable[["PeripheralEvent"], None]


class InterruptController(Protocol):
    def set_irq_pending(self, irq: int, pending: bool = True) -> None:
        ...

    def set_system_pending(self, name: str, pending: bool = True) -> None:
        ...


@dataclass(frozen=True)
class PeripheralEvent:
    """Lightweight event emitted by a peripheral on the bus.

    Common event kinds:
      dma_request   — peripheral has data ready for DMA
      dma_complete  — DMA transfer finished
      uart_rx_ready — USART received data
      uart_tx_empty — USART transmit buffer available
      timer_update  — timer update event
      adc_eoc       — ADC end-of-conversion
      gpio_edge     — GPIO pin edge detected
    """
    kind: str
    source: str = ""
    address: int = 0
    direction: str = ""
    size: int = 0
    payload: object = None


@dataclass
class MmioWatchpoint:
    wid: int
    label: str
    base: int
    size: int
    access: AccessType = "rw"
    reg_offset: Optional[int] = None  # if set, only match a specific register offset
    enabled: bool = True
    hits: int = 0


class PeripheralModel:
    def read(self, offset: int, size: int) -> int:  # noqa: D401
        """Read from an MMIO offset (size in bytes)."""
        raise NotImplementedError

    def write(self, offset: int, size: int, value: int) -> None:  # noqa: D401
        """Write to an MMIO offset (size in bytes)."""
        raise NotImplementedError

    def reset(self) -> None:
        pass

    def tick(self, cycles: int) -> None:
        del cycles

    def describe(self, offset: int) -> Optional[str]:
        del offset
        return None

    def attach(self, context: "PeripheralContext") -> None:
        del context

    def snapshot_state(self) -> object | None:
        return None

    def restore_state(self, state: object) -> None:
        del state


@dataclass(frozen=True)
class MountedPeripheral:
    name: str
    base: int
    end: int  # exclusive
    model: PeripheralModel
    peripheral: Optional[SvdPeripheral] = None


@dataclass(frozen=True)
class PeripheralContext:
    name: str
    base: int
    bus: "PeripheralBus"
    interrupts: Optional[InterruptController] = None
    peripheral: Optional[SvdPeripheral] = None


class PeripheralBus:
    def __init__(self, amap: AddressMap):
        self.amap = amap
        self._models: dict[str, PeripheralModel] = {}
        self._mounted: list[MountedPeripheral] = []
        self._interrupts: Optional[InterruptController] = None
        self.mmio_log_enabled = False
        self.access_policy: AccessPolicy = "permissive"
        self._rcc_model: object | None = None
        self._emulator: object | None = None
        self._serial_lines: dict[str, object] = {}
        self._dma_listeners: list[object] = []
        self._event_subscribers: dict[str, list[EventHandler]] = defaultdict(list)
        self._event_log: list[PeripheralEvent] = []
        self.event_log_enabled: bool = False

    def register_peripheral(self, name: str, model: PeripheralModel) -> None:
        p = self.amap.find_peripheral_by_name(name)
        if p is None:
            raise KeyError(f"unknown peripheral: {name}")
        self.mount(name=p.name, base=p.base_address, size=max(p.size, 4), model=model, peripheral=p)

    def mount(
        self,
        name: str,
        base: int,
        size: int,
        model: PeripheralModel,
        peripheral: Optional[SvdPeripheral] = None,
    ) -> None:
        mounted = MountedPeripheral(
            name=name,
            base=base,
            end=base + max(size, 4),
            model=model,
            peripheral=peripheral,
        )
        self._models[name.upper()] = model
        self._mounted.append(mounted)
        self._mounted.sort(key=lambda item: (item.base, item.end - item.base))
        model.attach(
            PeripheralContext(
                name=name,
                base=base,
                bus=self,
                interrupts=self._interrupts,
                peripheral=peripheral,
            )
        )

    def model_for_addr(self, addr: int) -> Optional[PeripheralModel]:
        mounted = self._mount_for_addr(addr)
        if mounted is None:
            return None
        return mounted.model

    def model_for_name(self, name: str) -> Optional[PeripheralModel]:
        return self._models.get(str(name).upper())

    def set_interrupt_controller(self, controller: InterruptController) -> None:
        self._interrupts = controller
        for mounted in self._mounted:
            mounted.model.attach(
                PeripheralContext(
                    name=mounted.name,
                    base=mounted.base,
                    bus=self,
                    interrupts=controller,
                    peripheral=mounted.peripheral,
                )
            )

    def set_clock_controller(self, model: PeripheralModel) -> None:
        """Register the RCC (or equivalent) model for clock-gating policy checks."""
        self._rcc_model = model

    def set_emulator(self, emu: object) -> None:
        """Attach the emulator instance so peripherals (e.g. DMA) can access memory."""
        self._emulator = emu

    def subscribe(self, event_kind: str, handler: EventHandler) -> None:
        """Subscribe to events of a given kind."""
        self._event_subscribers[event_kind].append(handler)

    def unsubscribe(self, event_kind: str, handler: EventHandler) -> None:
        """Remove a subscription."""
        subs = self._event_subscribers.get(event_kind)
        if subs:
            try:
                subs.remove(handler)
            except ValueError:
                pass

    def emit(self, event: PeripheralEvent) -> None:
        """Emit a peripheral event to all subscribers of its kind and wildcard."""
        if self.event_log_enabled:
            self._event_log.append(event)
        for handler in self._event_subscribers.get(event.kind, ()):
            handler(event)
        for handler in self._event_subscribers.get("*", ()):
            handler(event)

    def drain_event_log(self) -> list[PeripheralEvent]:
        """Return and clear the event log."""
        events = list(self._event_log)
        self._event_log.clear()
        return events

    def add_dma_listener(self, dma_model: PeripheralModel) -> None:
        """Register a DMA controller for peripheral DMA requests.

        .. deprecated::
            DMA controllers should migrate to ``bus.subscribe("dma_request", ...)``.
            This method is kept for backward compatibility during the transition.
        """
        self._dma_listeners.append(dma_model)

    def request_dma(
        self, peripheral_addr: int, direction: str, size: int = 1,
        *, source: str = "",
    ) -> None:
        """Signal a DMA-capable peripheral event.

        Emits a ``dma_request`` event and also dispatches directly to
        legacy DMA listeners for backward compatibility.
        """
        self.emit(PeripheralEvent(
            kind="dma_request",
            source=source,
            address=peripheral_addr,
            direction=direction,
            size=size,
        ))
        for dma in self._dma_listeners:
            if hasattr(dma, "on_peripheral_request"):
                dma.on_peripheral_request(peripheral_addr, direction, size)

    def mounted_ranges(self) -> tuple[MountedPeripheral, ...]:
        return tuple(self._mounted)

    def attach_serial_line(self, line: object) -> None:
        """Register a SerialLine so it ticks and snapshots with the bus."""
        self._serial_lines[line.name] = line

    def detach_serial_line(self, name: str) -> bool:
        return self._serial_lines.pop(name, None) is not None

    def serial_lines(self) -> dict[str, object]:
        return dict(self._serial_lines)

    def tick(self, cycles: int) -> None:
        seen: set[int] = set()
        for mounted in self._mounted:
            ident = id(mounted.model)
            if ident in seen:
                continue
            seen.add(ident)
            mounted.model.tick(cycles)
        for line in self._serial_lines.values():
            line.tick(cycles)

    def snapshot_models_state(self) -> dict[str, object]:
        states: dict[str, object] = {}
        seen: set[int] = set()
        for mounted in self._mounted:
            ident = id(mounted.model)
            if ident in seen:
                continue
            seen.add(ident)
            state = mounted.model.snapshot_state()
            if state is not None:
                states[mounted.name] = state
        for name, line in self._serial_lines.items():
            state = line.snapshot_state()
            if state is not None:
                states[f"__line__{name}"] = state
        return states

    def restore_models_state(self, states: dict[str, object]) -> None:
        seen: set[int] = set()
        for mounted in self._mounted:
            ident = id(mounted.model)
            if ident in seen:
                continue
            seen.add(ident)
            if mounted.name not in states:
                continue
            mounted.model.restore_state(states[mounted.name])
        for name, line in self._serial_lines.items():
            key = f"__line__{name}"
            if key in states:
                line.restore_state(states[key])

    def read(self, addr: int, size: int) -> int:
        mounted = self._mount_for_addr(addr)
        if mounted is None:
            raise KeyError(f"no peripheral for addr 0x{addr:08X}")
        blocked = self._check_clock_policy(mounted, "R")
        if blocked:
            return 0
        offset = addr - mounted.base
        val = mounted.model.read(offset, size)
        if self.mmio_log_enabled:
            rname = self._describe_access(mounted, addr)
            log.info("MMIO R  %s.%s [0x%08X size=%d] -> 0x%X", mounted.name, rname, addr, size, val)
        return val

    def write(self, addr: int, size: int, value: int) -> None:
        mounted = self._mount_for_addr(addr)
        if mounted is None:
            raise KeyError(f"no peripheral for addr 0x{addr:08X}")
        blocked = self._check_clock_policy(mounted, "W")
        if blocked:
            return
        offset = addr - mounted.base
        if self.mmio_log_enabled:
            rname = self._describe_access(mounted, addr)
            log.info("MMIO W  %s.%s [0x%08X size=%d] <- 0x%X", mounted.name, rname, addr, size, value)
        mounted.model.write(offset, size, value)

    def _check_clock_policy(self, mounted: MountedPeripheral, access: str) -> bool:
        """Return True if access should be blocked (strict mode only)."""
        if self.access_policy == "permissive":
            return False
        rcc = self._rcc_model
        if rcc is None:
            return False
        if not hasattr(rcc, "is_peripheral_enabled"):
            return False
        name = mounted.name.upper()
        if name in ("RCC", "PWR", "CORE", "SYSMEM", "FLASH"):
            return False
        if rcc.is_peripheral_enabled(name):
            return False
        if self.access_policy == "warn":
            log.warning(
                "MMIO %s %s [0x%08X] — peripheral clock not enabled",
                access, name, mounted.base,
            )
            return False
        log.error(
            "MMIO %s %s [0x%08X] BLOCKED — peripheral clock not enabled",
            access, name, mounted.base,
        )
        return True

    def _mount_for_addr(self, addr: int) -> Optional[MountedPeripheral]:
        for mounted in self._mounted:
            if mounted.base <= addr < mounted.end:
                return mounted
        return None

    def _describe_access(self, mounted: MountedPeripheral, addr: int) -> str:
        if mounted.peripheral is not None:
            reg = self.amap.find_register(mounted.peripheral, addr)
            if reg is not None:
                return reg.name
            return f"+0x{addr - mounted.base:X}"

        label = mounted.model.describe(addr - mounted.base)
        if label:
            return label
        return f"+0x{addr - mounted.base:X}"
