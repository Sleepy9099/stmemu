from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class Stm32UsartPeripheral(GenericRegisterFilePeripheral):
    irq: int | None = None
    _context: PeripheralContext | None = field(default=None, init=False, repr=False)
    _rx_fifo: deque[int] = field(default_factory=deque, init=False, repr=False)
    _tx_fifo: bytearray = field(default_factory=bytearray, init=False, repr=False)

    _CR1 = 0x00
    _CR2 = 0x04
    _CR3 = 0x08
    _BRR = 0x0C
    _RQR = 0x18
    _ISR = 0x1C
    _ICR = 0x20
    _RDR = 0x24
    _TDR = 0x28

    _CR1_UE = 1 << 0
    _CR1_RE = 1 << 2
    _CR1_TE = 1 << 3
    _CR1_RXNEIE = 1 << 5
    _CR1_TCIE = 1 << 6
    _CR1_TXEIE = 1 << 7

    _RQR_RXFRQ = 1 << 3

    _ISR_RXFNE = 1 << 5
    _ISR_TC = 1 << 6
    _ISR_TXFNF = 1 << 7
    _ISR_TEACK = 1 << 21
    _ISR_REACK = 1 << 22

    def __post_init__(self) -> None:
        super().__post_init__()
        self._refresh_status()

    def attach(self, context: PeripheralContext) -> None:
        self._context = context
        self._update_irq()

    def read(self, offset: int, size: int) -> int:
        if size == 4 and offset == self._RDR:
            value = self._rx_fifo.popleft() if self._rx_fifo else 0
            self.write_register_value(self._RDR, value)
            self._refresh_status()
            self._update_irq()
            return value

        if size == 4 and offset == self._ISR:
            self._refresh_status()

        return super().read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        if size == 4 and offset == self._TDR:
            self._tx_fifo.append(int(value) & 0xFF)
            self.write_register_value(self._TDR, int(value) & 0xFF)
            self._refresh_status()
            self._update_irq()
            return

        if size == 4 and offset == self._RQR:
            if int(value) & self._RQR_RXFRQ:
                self._rx_fifo.clear()
            self.write_register_value(offset, int(value))
            self._refresh_status()
            self._update_irq()
            return

        if size == 4 and offset == self._ICR:
            self.write_register_value(offset, int(value))
            self._refresh_status()
            self._update_irq()
            return

        super().write(offset, size, value)
        if offset in {self._CR1, self._CR2, self._CR3, self._BRR}:
            self._refresh_status()
            self._update_irq()

    def inject_rx_bytes(self, data: bytes) -> None:
        for byte in data:
            self._rx_fifo.append(int(byte) & 0xFF)
        self._refresh_status()
        self._update_irq()

    def drain_tx_bytes(self) -> bytes:
        data = bytes(self._tx_fifo)
        self._tx_fifo.clear()
        self._refresh_status()
        self._update_irq()
        return data

    def peek_tx_bytes(self) -> bytes:
        return bytes(self._tx_fifo)

    def status_summary(self) -> str:
        self._refresh_status()
        return (
            f"rx={len(self._rx_fifo)} tx={len(self._tx_fifo)} "
            f"isr=0x{self.read_register_value(self._ISR):08X} "
            f"cr1=0x{self.read_register_value(self._CR1):08X}"
        )

    def _refresh_status(self) -> None:
        value = self.read_register_value(self._ISR)
        value &= ~(self._ISR_RXFNE | self._ISR_TC | self._ISR_TXFNF | self._ISR_TEACK | self._ISR_REACK)

        cr1 = self.read_register_value(self._CR1)
        ue = bool(cr1 & self._CR1_UE)
        te = bool(cr1 & self._CR1_TE)
        re = bool(cr1 & self._CR1_RE)

        value |= self._ISR_TC | self._ISR_TXFNF
        if self._rx_fifo:
            value |= self._ISR_RXFNE
        if ue and te:
            value |= self._ISR_TEACK
        if ue and re:
            value |= self._ISR_REACK

        self.write_register_value(self._ISR, value)
        if self._rx_fifo:
            self.write_register_value(self._RDR, self._rx_fifo[0])
        else:
            self.write_register_value(self._RDR, 0)

    def _update_irq(self) -> None:
        if self.irq is None or self._context is None or self._context.interrupts is None:
            return
        cr1 = self.read_register_value(self._CR1)
        isr = self.read_register_value(self._ISR)
        pending = False
        if (cr1 & self._CR1_RXNEIE) and (isr & self._ISR_RXFNE):
            pending = True
        if (cr1 & self._CR1_TCIE) and (isr & self._ISR_TC):
            pending = True
        if (cr1 & self._CR1_TXEIE) and (isr & self._ISR_TXFNF):
            pending = True
        self._context.interrupts.set_irq_pending(self.irq, pending)


USART_IRQS: dict[str, int] = {
    "USART1": 37,
    "USART2": 38,
    "USART3": 39,
    "UART4": 52,
    "UART5": 53,
    "USART6": 71,
    "UART7": 82,
    "UART8": 83,
    "LPUART1": 98,
}


def build_usart(peripheral: SvdPeripheral) -> Stm32UsartPeripheral:
    return Stm32UsartPeripheral(
        peripheral=peripheral,
        irq=USART_IRQS.get(peripheral.name.upper()),
    )
