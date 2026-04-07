from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class SpiPeripheral(GenericRegisterFilePeripheral):
    """SPI peripheral with TXE/RXNE/BSY flag simulation.

    Firmware expects TXE=1 (transmit buffer empty) after writing DR,
    and BSY=0 when no transfer is in progress. Without these flags,
    firmware polling loops will hang.
    """

    irq: int | None = None
    _context: PeripheralContext | None = field(default=None, init=False, repr=False)
    _tx_fifo: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _rx_fifo: deque[int] = field(default_factory=deque, init=False, repr=False)

    # Standard SPI register offsets
    _CR1 = 0x00
    _CR2 = 0x04
    _SR = 0x08
    _DR = 0x0C

    # SR flags
    _SR_RXNE = 1 << 0   # Receive buffer not empty
    _SR_TXE = 1 << 1    # Transmit buffer empty
    _SR_BSY = 1 << 7    # Busy flag

    # CR1 flags
    _CR1_SPE = 1 << 6   # SPI enable

    def __post_init__(self) -> None:
        super().__post_init__()
        for reg in self.peripheral.registers:
            rname = reg.name.upper()
            if rname == "CR1":
                self._CR1 = reg.offset
            elif rname == "CR2":
                self._CR2 = reg.offset
            elif rname == "SR":
                self._SR = reg.offset
            elif rname == "DR":
                self._DR = reg.offset
        self._refresh_status()

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def read(self, offset: int, size: int) -> int:
        if offset == self._DR:
            value = self._rx_fifo.popleft() if self._rx_fifo else 0
            self._refresh_status()
            return value
        if offset == self._SR:
            self._refresh_status()
        return super().read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        if size in (1, 2, 4) and offset == self._DR:
            # Capture transmitted byte; loopback into RX for reads
            byte = int(value) & 0xFF
            self._tx_fifo.append(byte)
            self._rx_fifo.append(0xFF)  # default MISO = 0xFF (no slave)
            self._refresh_status()
            return
        super().write(offset, size, value)
        if offset == self._CR1:
            self._refresh_status()

    def _refresh_status(self) -> None:
        sr = self.read_register_value(self._SR)
        sr &= ~(self._SR_TXE | self._SR_RXNE | self._SR_BSY)
        sr |= self._SR_TXE  # always ready to transmit
        if self._rx_fifo:
            sr |= self._SR_RXNE
        # BSY stays 0 (transfers complete instantly)
        self.write_register_value(self._SR, sr)

    def drain_tx(self) -> bytes:
        data = bytes(self._tx_fifo)
        self._tx_fifo.clear()
        return data

    def inject_rx(self, data: bytes) -> None:
        for b in data:
            self._rx_fifo.append(int(b) & 0xFF)
        self._refresh_status()

    def reset(self) -> None:
        super().reset()
        self._tx_fifo.clear()
        self._rx_fifo.clear()
        self._refresh_status()

    def snapshot_state(self) -> object | None:
        base = super().snapshot_state()
        if not isinstance(base, dict):
            base = {}
        base["tx_fifo"] = bytes(self._tx_fifo)
        base["rx_fifo"] = list(self._rx_fifo)
        return base

    def restore_state(self, state: object) -> None:
        super().restore_state(state)
        if not isinstance(state, dict):
            return
        tx = state.get("tx_fifo")
        if isinstance(tx, (bytes, bytearray)):
            self._tx_fifo = bytearray(tx)
        rx = state.get("rx_fifo")
        if isinstance(rx, list):
            self._rx_fifo = deque(int(b) & 0xFF for b in rx)
        self._refresh_status()


def _first_irq(peripheral: SvdPeripheral) -> Optional[int]:
    if peripheral.interrupts:
        return peripheral.interrupts[0].value
    return None


def build_spi(peripheral: SvdPeripheral) -> SpiPeripheral:
    return SpiPeripheral(peripheral=peripheral, irq=_first_irq(peripheral))
