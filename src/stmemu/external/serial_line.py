"""Serial line transport bridging a USART model to an external device."""
from __future__ import annotations

from stmemu.external.device import ExternalDevice
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


class SerialLine:
    """Bidirectional byte-stream bridge between a USART peripheral and a device.

    On each ``tick()``:
    1. Drain bytes the MCU wrote to the USART TX FIFO → device.on_rx_from_mcu()
    2. Read bytes the device wants to send → USART inject_rx_bytes()
    """

    def __init__(
        self,
        name: str = "serial0",
        *,
        uart: object | None = None,
        device: ExternalDevice | None = None,
    ) -> None:
        self.name = name
        self._uart: object | None = uart
        self._device: ExternalDevice | None = device

    def attach_uart(self, uart: object) -> None:
        self._uart = uart

    def attach_device(self, device: ExternalDevice) -> None:
        self._device = device

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

        self._device.tick(cycles)

        rx_data = self._device.read_tx_to_mcu()
        if rx_data:
            self._uart.inject_rx_bytes(rx_data)

    def reset(self) -> None:
        if self._device is not None:
            self._device.reset()

    def snapshot_state(self) -> object | None:
        if self._device is None:
            return None
        return {
            "name": self.name,
            "device_state": self._device.snapshot_state(),
        }

    def restore_state(self, state: object) -> None:
        if not isinstance(state, dict) or self._device is None:
            return
        ds = state.get("device_state")
        if ds is not None:
            self._device.restore_state(ds)
