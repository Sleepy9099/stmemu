from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class I2cPeripheral(GenericRegisterFilePeripheral):
    """I2C peripheral with status flag simulation.

    Firmware expects ISR.BUSY=0 when idle, ISR.TXE=1 when ready to
    transmit, and ISR.TXIS=1 when transmit buffer is empty.
    Without flag simulation, polling loops hang.
    """

    irq: int | None = None
    _context: PeripheralContext | None = field(default=None, init=False, repr=False)
    _tx_fifo: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _rx_fifo: deque[int] = field(default_factory=deque, init=False, repr=False)

    # Standard I2C register offsets (newer STM32 layout)
    _CR1 = 0x00
    _CR2 = 0x04
    _TIMINGR = 0x10
    _ISR = 0x18
    _ICR = 0x1C
    _RXDR = 0x24
    _TXDR = 0x28

    # ISR flags
    _ISR_TXE = 1 << 0     # Transmit data register empty
    _ISR_TXIS = 1 << 1    # Transmit interrupt status
    _ISR_RXNE = 1 << 2    # Receive data register not empty
    _ISR_TC = 1 << 6      # Transfer complete
    _ISR_TCR = 1 << 7     # Transfer complete reload
    _ISR_BUSY = 1 << 15   # Bus busy

    def __post_init__(self) -> None:
        super().__post_init__()
        for reg in self.peripheral.registers:
            rname = reg.name.upper()
            if rname == "CR1":
                self._CR1 = reg.offset
            elif rname == "CR2":
                self._CR2 = reg.offset
            elif rname == "ISR":
                self._ISR = reg.offset
            elif rname == "ICR":
                self._ICR = reg.offset
            elif rname == "RXDR":
                self._RXDR = reg.offset
            elif rname == "TXDR":
                self._TXDR = reg.offset
        self._refresh_status()

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def read(self, offset: int, size: int) -> int:
        if offset == self._RXDR:
            value = self._rx_fifo.popleft() if self._rx_fifo else 0
            self._refresh_status()
            return value
        if offset == self._ISR:
            self._refresh_status()
        return super().read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        if size == 4 and offset == self._TXDR:
            self._tx_fifo.append(int(value) & 0xFF)
            self._refresh_status()
            return

        if size == 4 and offset == self._ICR:
            # Clear status flags via ICR write
            isr = self.read_register_value(self._ISR)
            self.write_register_value(self._ISR, isr & ~int(value))
            self._refresh_status()
            return

        super().write(offset, size, value)
        if offset == self._CR2:
            # Starting a transfer auto-sets TC after completion
            cr2 = self.read_register_value(self._CR2)
            if cr2 & (1 << 25):  # START bit
                self._auto_complete_transfer()

    def _refresh_status(self) -> None:
        isr = self.read_register_value(self._ISR)
        # TXE: always ready (transmit buffer empty)
        isr |= self._ISR_TXE | self._ISR_TXIS
        # RXNE: set if data available
        if self._rx_fifo:
            isr |= self._ISR_RXNE
        else:
            isr &= ~self._ISR_RXNE
        # BUSY: always idle in emulation
        isr &= ~self._ISR_BUSY
        self.write_register_value(self._ISR, isr)

    def _auto_complete_transfer(self) -> None:
        """Auto-set transfer complete after START."""
        isr = self.read_register_value(self._ISR)
        isr |= self._ISR_TC
        isr &= ~self._ISR_BUSY
        self.write_register_value(self._ISR, isr)

    def inject_rx(self, data: bytes) -> None:
        for b in data:
            self._rx_fifo.append(int(b) & 0xFF)
        self._refresh_status()

    def drain_tx(self) -> bytes:
        data = bytes(self._tx_fifo)
        self._tx_fifo.clear()
        return data

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


def build_i2c(peripheral: SvdPeripheral) -> I2cPeripheral:
    return I2cPeripheral(peripheral=peripheral, irq=_first_irq(peripheral))
