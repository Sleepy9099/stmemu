"""Serial line transport bridging a USART model to an external device."""
from __future__ import annotations

from stmemu.external.device import ExternalDevice
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


class SerialLine:
    """Bidirectional byte-stream bridge between a USART peripheral and a device.

    On each ``tick()``:
    1. Drain bytes the MCU wrote to the USART TX FIFO → device.on_rx_from_mcu()
    2. Tick the device (may produce output)
    3. Read bytes the device wants to send → USART inject_rx_bytes()
    4. Emit device_tx event if data was injected
    """

    def __init__(
        self,
        name: str = "serial0",
        *,
        uart: object | None = None,
        device: ExternalDevice | None = None,
        bus: object | None = None,
    ) -> None:
        self.name = name
        self._uart: object | None = uart
        self._device: ExternalDevice | None = device
        self._bus: object | None = bus
        self._total_rx_bytes: int = 0
        self._total_tx_bytes: int = 0

    def attach_uart(self, uart: object) -> None:
        self._uart = uart

    def attach_device(self, device: ExternalDevice) -> None:
        self._device = device

    def set_bus(self, bus: object) -> None:
        self._bus = bus

    @property
    def uart(self) -> object | None:
        return self._uart

    @property
    def device(self) -> ExternalDevice | None:
        return self._device

    def tick(self, cycles: int) -> None:
        if self._uart is None or self._device is None:
            return

        tx_data = self._uart.drain_tx_bytes()
        if tx_data:
            self._device.on_rx_from_mcu(tx_data)
            self._total_tx_bytes += len(tx_data)
            self._trace("tx", tx_data)

        self._device.tick(cycles)

        rx_data = self._device.read_tx_to_mcu()
        if rx_data:
            self._uart.inject_rx_bytes(rx_data)
            self._total_rx_bytes += len(rx_data)
            self._emit_device_tx(rx_data)
            self._trace("rx", rx_data)

    def _trace(self, direction: str, data: bytes) -> None:
        bus = self._bus
        if bus is not None and getattr(bus, "_trace_active", False):
            dev = self._device.name if self._device else self.name
            bus._trace({
                "proto": "uart", "bus": self.name, "device": dev,
                "dir": direction, "bytes": bytes(data),
            })

    def _emit_device_tx(self, data: bytes) -> None:
        if self._bus is None:
            return
        if not hasattr(self._bus, "emit"):
            return
        from stmemu.peripherals.bus import PeripheralEvent
        dev_name = self._device.name if self._device else self.name
        self._bus.emit(PeripheralEvent(
            kind="device_tx",
            source=dev_name,
            size=len(data),
            payload={"line": self.name, "bytes": len(data)},
        ))

    def reset(self) -> None:
        if self._device is not None:
            self._device.reset()
        self._total_rx_bytes = 0
        self._total_tx_bytes = 0

    def snapshot_state(self) -> object | None:
        if self._device is None:
            return None
        return {
            "name": self.name,
            "device_state": self._device.snapshot_state(),
            "total_rx_bytes": self._total_rx_bytes,
            "total_tx_bytes": self._total_tx_bytes,
        }

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict) or self._device is None:
            return
        ds = state.get("device_state")
        if ds is not None:
            self._device.restore_state(ds)
        self._total_rx_bytes = int(state.get("total_rx_bytes", 0))
        self._total_tx_bytes = int(state.get("total_tx_bytes", 0))
