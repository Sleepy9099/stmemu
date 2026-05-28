from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralContext, PeripheralEvent
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral
from stmemu.utils.logger import get_logger

log = get_logger(__name__)

_STATE_IDLE = 0
_STATE_ADDR = 1
_STATE_TX = 2
_STATE_RX = 3


@dataclass
class I2cPeripheral(GenericRegisterFilePeripheral):
    """I2C peripheral with transaction state machine and external device support.

    Transaction flow (write):
      firmware sets CR2: SADD, NBYTES, RD_WRN=0, START
        → peripheral sends START+address to I2cBus
        → if ACK: ISR.TXIS set, firmware writes TXDR bytes
        → on NBYTES reached: ISR.TC set
        → firmware sets CR2.STOP → ISR.STOPF set

    Transaction flow (read):
      firmware sets CR2: SADD, NBYTES, RD_WRN=1, START
        → peripheral sends START+address to I2cBus
        → if ACK: device data loaded into RXDR, ISR.RXNE set
        → firmware reads RXDR
        → on NBYTES reached: ISR.TC set
    """

    irq: int | None = None
    _context: PeripheralContext | None = field(default=None, init=False, repr=False)
    _i2c_bus: object | None = field(default=None, init=False, repr=False)
    _tx_fifo: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _rx_fifo: deque[int] = field(default_factory=deque, init=False, repr=False)
    _state: int = field(default=_STATE_IDLE, init=False, repr=False)
    _bytes_remaining: int = field(default=0, init=False, repr=False)
    _is_read: bool = field(default=False, init=False, repr=False)
    _nack: bool = field(default=False, init=False, repr=False)

    _CR1 = 0x00
    _CR2 = 0x04
    _TIMINGR = 0x10
    _ISR = 0x18
    _ICR = 0x1C
    _RXDR = 0x24
    _TXDR = 0x28

    _CR1_PE = 1 << 0
    _CR2_START = 1 << 13
    _CR2_STOP = 1 << 14
    _CR2_RD_WRN = 1 << 10
    _CR2_AUTOEND = 1 << 25

    _ISR_TXE = 1 << 0
    _ISR_TXIS = 1 << 1
    _ISR_RXNE = 1 << 2
    _ISR_NACKF = 1 << 4
    _ISR_STOPF = 1 << 5
    _ISR_TC = 1 << 6
    _ISR_TCR = 1 << 7
    _ISR_BUSY = 1 << 15

    _CR1_TXIE = 1 << 1
    _CR1_RXIE = 1 << 2
    _CR1_NACKIE = 1 << 4
    _CR1_STOPIE = 1 << 5
    _CR1_TCIE = 1 << 6

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
        self._refresh_idle_status()

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def attach_i2c_bus(self, bus: object) -> None:
        self._i2c_bus = bus

    def reset(self) -> None:
        super().reset()
        self._tx_fifo.clear()
        self._rx_fifo.clear()
        self._state = _STATE_IDLE
        self._bytes_remaining = 0
        self._is_read = False
        self._nack = False
        self._refresh_idle_status()

    def read(self, offset: int, size: int) -> int:
        if offset == self._RXDR:
            value = self._rx_fifo.popleft() if self._rx_fifo else 0
            self._bytes_remaining = max(0, self._bytes_remaining - 1)
            if self._bytes_remaining > 0 and self._i2c_bus is not None:
                next_byte = self._i2c_bus.read_byte()
                self._rx_fifo.append(next_byte)
            self._refresh_status()
            return value
        if offset == self._ISR:
            self._refresh_status()
        return super().read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        if self._access_targets(offset, size, self._TXDR):
            byte = int(value) & 0xFF
            if self._state == _STATE_TX and self._i2c_bus is not None:
                ack = self._i2c_bus.write_byte(byte)
                if not ack:
                    self._nack = True
                self._bytes_remaining = max(0, self._bytes_remaining - 1)
            else:
                self._tx_fifo.append(byte)
            self._refresh_status()
            self._update_irq()
            return

        if self._access_targets(offset, size, self._ICR):
            clear_mask = self._aligned_write_value(offset, size, self._ICR, value)
            isr = self.read_register_value(self._ISR)
            self.write_register_value(self._ISR, isr & ~clear_mask)
            if clear_mask & self._ISR_NACKF:
                self._nack = False
            self._update_irq()
            return

        super().write(offset, size, value)

        if self._access_targets(offset, size, self._CR2):
            self._handle_cr2_write()

    def _handle_cr2_write(self) -> None:
        cr2 = self.read_register_value(self._CR2)

        if cr2 & self._CR2_STOP:
            self._do_stop()
            self.write_register_value(self._CR2, cr2 & ~self._CR2_STOP)
            return

        if cr2 & self._CR2_START:
            self.write_register_value(self._CR2, cr2 & ~self._CR2_START)
            self._do_start(cr2)

    def _do_start(self, cr2: int) -> None:
        addr = (cr2 >> 1) & 0x7F
        nbytes = (cr2 >> 16) & 0xFF
        is_read = bool(cr2 & self._CR2_RD_WRN)
        autoend = bool(cr2 & self._CR2_AUTOEND)

        self._is_read = is_read
        self._bytes_remaining = nbytes
        self._nack = False
        self._rx_fifo.clear()

        ack = False
        if self._i2c_bus is not None:
            ack = self._i2c_bus.start(addr, is_read)
        else:
            ack = True

        isr = self.read_register_value(self._ISR)
        isr |= self._ISR_BUSY
        isr &= ~(self._ISR_TC | self._ISR_NACKF | self._ISR_STOPF | self._ISR_TXIS | self._ISR_RXNE)

        if not ack:
            self._nack = True
            self._state = _STATE_IDLE
            isr |= self._ISR_NACKF
            isr &= ~self._ISR_BUSY
            self.write_register_value(self._ISR, isr)
            self._update_irq()
            return

        if is_read:
            self._state = _STATE_RX
            if nbytes > 0 and self._i2c_bus is not None:
                first = self._i2c_bus.read_byte()
                self._rx_fifo.append(first)
                isr |= self._ISR_RXNE
            elif nbytes == 0:
                isr |= self._ISR_TC
                if autoend:
                    self._do_stop()
                    isr |= self._ISR_STOPF
                    isr &= ~self._ISR_BUSY
        else:
            self._state = _STATE_TX
            if nbytes > 0:
                isr |= self._ISR_TXE | self._ISR_TXIS
            else:
                isr |= self._ISR_TC
                if autoend:
                    self._do_stop()
                    isr |= self._ISR_STOPF
                    isr &= ~self._ISR_BUSY

        self.write_register_value(self._ISR, isr)
        self._update_irq()

    def _do_stop(self) -> None:
        if self._i2c_bus is not None:
            self._i2c_bus.stop()
        self._state = _STATE_IDLE
        isr = self.read_register_value(self._ISR)
        isr |= self._ISR_STOPF
        isr &= ~self._ISR_BUSY
        self.write_register_value(self._ISR, isr)
        self._update_irq()

    def _refresh_status(self) -> None:
        isr = self.read_register_value(self._ISR)

        if self._state == _STATE_IDLE:
            isr |= self._ISR_TXE
            isr &= ~(self._ISR_BUSY | self._ISR_TXIS)
            if self._rx_fifo:
                isr |= self._ISR_RXNE
            else:
                isr &= ~self._ISR_RXNE
        elif self._state == _STATE_TX:
            isr |= self._ISR_TXE
            if self._bytes_remaining > 0:
                isr |= self._ISR_TXIS
            else:
                isr &= ~self._ISR_TXIS
                isr |= self._ISR_TC
                cr2 = self.read_register_value(self._CR2)
                if cr2 & self._CR2_AUTOEND:
                    self._do_stop()
                    isr = self.read_register_value(self._ISR)
        elif self._state == _STATE_RX:
            if self._rx_fifo:
                isr |= self._ISR_RXNE
            else:
                isr &= ~self._ISR_RXNE
            if self._bytes_remaining <= 0 and not self._rx_fifo:
                isr |= self._ISR_TC
                cr2 = self.read_register_value(self._CR2)
                if cr2 & self._CR2_AUTOEND:
                    self._do_stop()
                    isr = self.read_register_value(self._ISR)

        if self._nack:
            isr |= self._ISR_NACKF

        self.write_register_value(self._ISR, isr)
        self._update_irq()

    def _refresh_idle_status(self) -> None:
        isr = self._ISR_TXE
        self.write_register_value(self._ISR, isr)

    def _update_irq(self) -> None:
        if self.irq is None or self._context is None or self._context.interrupts is None:
            return
        cr1 = self.read_register_value(self._CR1)
        isr = self.read_register_value(self._ISR)
        pending = bool(
            ((cr1 & self._CR1_TXIE) and (isr & self._ISR_TXIS))
            or ((cr1 & self._CR1_RXIE) and (isr & self._ISR_RXNE))
            or ((cr1 & self._CR1_NACKIE) and (isr & self._ISR_NACKF))
            or ((cr1 & self._CR1_STOPIE) and (isr & self._ISR_STOPF))
            or ((cr1 & self._CR1_TCIE) and (isr & self._ISR_TC))
        )
        self._context.interrupts.set_irq_pending(self.irq, pending)

    def inject_rx(self, data: bytes) -> None:
        for b in data:
            self._rx_fifo.append(int(b) & 0xFF)
        self._refresh_status()

    def drain_tx(self) -> bytes:
        data = bytes(self._tx_fifo)
        self._tx_fifo.clear()
        return data

    def snapshot_state(self) -> object | None:
        base = super().snapshot_state()
        if not isinstance(base, dict):
            base = {}
        base["tx_fifo"] = bytes(self._tx_fifo)
        base["rx_fifo"] = list(self._rx_fifo)
        base["state"] = self._state
        base["bytes_remaining"] = self._bytes_remaining
        base["is_read"] = self._is_read
        base["nack"] = self._nack
        i2c_state = None
        if self._i2c_bus is not None and hasattr(self._i2c_bus, "snapshot_state"):
            i2c_state = self._i2c_bus.snapshot_state()
        base["i2c_bus_state"] = i2c_state
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
        self._state = int(state.get("state", _STATE_IDLE))
        self._bytes_remaining = int(state.get("bytes_remaining", 0))
        self._is_read = bool(state.get("is_read", False))
        self._nack = bool(state.get("nack", False))
        bus_state = state.get("i2c_bus_state")
        if bus_state is not None and self._i2c_bus is not None and hasattr(self._i2c_bus, "restore_state"):
            self._i2c_bus.restore_state(bus_state)


def _first_irq(peripheral: SvdPeripheral) -> Optional[int]:
    if peripheral.interrupts:
        return peripheral.interrupts[0].value
    return None


def build_i2c(peripheral: SvdPeripheral) -> I2cPeripheral:
    return I2cPeripheral(peripheral=peripheral, irq=_first_irq(peripheral))
