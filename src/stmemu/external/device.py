"""Base class for external devices attached to peripheral endpoints."""
from __future__ import annotations


class ExternalDevice:
    """Protocol for devices connected to MCU peripherals via a transport."""

    name: str = "device"

    def reset(self) -> None:
        pass

    def tick(self, cycles: int) -> None:
        del cycles

    def on_rx_from_mcu(self, data: bytes) -> None:
        """Called when the MCU sends data to this device."""
        del data

    def read_tx_to_mcu(self, max_bytes: int = 4096) -> bytes:
        """Return pending data to send to the MCU. Non-blocking."""
        del max_bytes
        return b""

    def pending_tx_len(self) -> int:
        """Number of bytes queued for transmission to the MCU."""
        return 0

    def snapshot_state(self) -> object | None:
        return None

    def restore_state(self, state: object) -> None:
        del state
