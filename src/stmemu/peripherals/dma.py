from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral
from stmemu.utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class DmaPeripheral(GenericRegisterFilePeripheral):
    """DMA controller with transfer-complete flag simulation and memory transfer.

    When a stream/channel is enabled, the model:
    1. Performs the configured memory transfer (if an emulator is available)
    2. Sets the transfer-complete flag in the status register
    3. Clears the enable bit (hardware does this on completion)
    4. Optionally pends the transfer-complete interrupt
    """

    _context: PeripheralContext | None = field(default=None, init=False, repr=False)

    # Global status register offsets (STM32F4/F7/H7 DMA layout)
    _LISR = 0x00  # Low interrupt status register
    _HISR = 0x04  # High interrupt status register
    _LIFCR = 0x08  # Low interrupt flag clear register
    _HIFCR = 0x0C  # High interrupt flag clear register

    # Per-stream register stride (STM32F4/F7/H7)
    _STREAM_BASE = 0x10
    _STREAM_STRIDE = 0x18

    # Offsets within each stream block
    _SxCR = 0x00   # Stream config
    _SxNDTR = 0x04  # Number of data items
    _SxPAR = 0x08   # Peripheral address
    _SxM0AR = 0x0C  # Memory 0 address
    _SxM1AR = 0x10  # Memory 1 address
    _SxFCR = 0x14   # FIFO control

    _SxCR_EN = 1 << 0
    _SxCR_TCIE = 1 << 4
    _SxCR_DIR_SHIFT = 6
    _SxCR_DIR_MASK = 0x3
    _SxCR_MSIZE_SHIFT = 13
    _SxCR_PSIZE_SHIFT = 11

    _DIR_P2M = 0  # peripheral to memory
    _DIR_M2P = 1  # memory to peripheral
    _DIR_M2M = 2  # memory to memory

    _STREAM_TC_BITS = {
        0: (0, 5),
        1: (0, 11),
        2: (0, 21),
        3: (0, 27),
        4: (1, 5),
        5: (1, 11),
        6: (1, 21),
        7: (1, 27),
    }

    _irqs: dict[int, int] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        for reg in self.peripheral.registers:
            rname = reg.name.upper()
            if rname in ("LISR", "ISR"):
                self._LISR = reg.offset
            elif rname in ("HISR",):
                self._HISR = reg.offset
            elif rname in ("LIFCR", "IFCR"):
                self._LIFCR = reg.offset
            elif rname in ("HIFCR",):
                self._HIFCR = reg.offset
        for intr in self.peripheral.interrupts:
            name = intr.name.upper()
            for i in range(8):
                if f"STREAM{i}" in name or f"CH{i}" in name or f"CHANNEL{i}" in name:
                    self._irqs[i] = intr.value
                    break

    def attach(self, context: PeripheralContext) -> None:
        self._context = context
        if context.bus is not None:
            context.bus.add_dma_listener(self)

    def on_peripheral_request(self, periph_addr: int, direction: str, size: int = 1) -> None:
        """Handle a DMA request from a peripheral.

        Scans enabled streams to find one configured for this peripheral
        address and direction, then executes the transfer.
        """
        dir_map = {"p2m": self._DIR_P2M, "m2p": self._DIR_M2P}
        expected_dir = dir_map.get(direction.lower())
        if expected_dir is None:
            return
        for stream in range(8):
            stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
            cr = self.read_register_value(stream_offset + self._SxCR)
            if not (cr & self._SxCR_EN):
                continue
            par = self.read_register_value(stream_offset + self._SxPAR)
            actual_dir = (cr >> self._SxCR_DIR_SHIFT) & self._SxCR_DIR_MASK
            if par == periph_addr and actual_dir == expected_dir:
                self._execute_transfer(stream)
                break

    def write(self, offset: int, size: int, value: int) -> None:
        if size == 4 and offset == self._LIFCR:
            current = self.read_register_value(self._LISR)
            self.write_register_value(self._LISR, current & ~int(value))
            return
        if size == 4 and offset == self._HIFCR:
            current = self.read_register_value(self._HISR)
            self.write_register_value(self._HISR, current & ~int(value))
            return

        super().write(offset, size, value)

        for stream in range(8):
            stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
            cr_offset = stream_offset + self._SxCR
            if offset == cr_offset and (int(value) & self._SxCR_EN):
                self._execute_transfer(stream)

    def _execute_transfer(self, stream: int) -> None:
        stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
        cr = self.read_register_value(stream_offset + self._SxCR)
        ndtr = self.read_register_value(stream_offset + self._SxNDTR) & 0xFFFF
        par = self.read_register_value(stream_offset + self._SxPAR)
        mar = self.read_register_value(stream_offset + self._SxM0AR)
        direction = (cr >> self._SxCR_DIR_SHIFT) & self._SxCR_DIR_MASK

        emu = self._get_emulator()
        if emu is not None and ndtr > 0:
            item_size = 1 << ((cr >> self._SxCR_PSIZE_SHIFT) & 0x3)
            byte_count = ndtr * item_size
            try:
                self._do_transfer(emu, direction, par, mar, byte_count)
            except Exception:
                log.debug("DMA stream %d transfer failed", stream)

        tc_info = self._STREAM_TC_BITS.get(stream)
        if tc_info is not None:
            reg_idx, bit = tc_info
            isr_offset = self._LISR if reg_idx == 0 else self._HISR
            isr = self.read_register_value(isr_offset)
            self.write_register_value(isr_offset, isr | (1 << bit))

        self.write_register_value(
            stream_offset + self._SxCR, cr & ~self._SxCR_EN,
        )
        self.write_register_value(stream_offset + self._SxNDTR, 0)

        if (cr & self._SxCR_TCIE) and self._context and self._context.interrupts:
            irq = self._irqs.get(stream)
            if irq is not None:
                self._context.interrupts.set_irq_pending(irq)

    def _do_transfer(
        self, emu: object, direction: int, par: int, mar: int, byte_count: int,
    ) -> None:
        if direction == self._DIR_P2M:
            data = self._bus_read_bytes(par, byte_count)
            emu.mem_write(mar, data)
        elif direction == self._DIR_M2P:
            data = bytes(emu.mem_read(mar, byte_count))
            self._bus_write_bytes(par, data)
        elif direction == self._DIR_M2M:
            data = bytes(emu.mem_read(par, byte_count))
            emu.mem_write(mar, data)

    def _bus_read_bytes(self, addr: int, count: int) -> bytes:
        if not self._context:
            return b"\x00" * count
        result = bytearray()
        for i in range(count):
            try:
                val = self._context.bus.read(addr + i, 1)
                result.append(val & 0xFF)
            except Exception:
                result.append(0)
        return bytes(result)

    def _bus_write_bytes(self, addr: int, data: bytes) -> None:
        if not self._context:
            return
        for i, b in enumerate(data):
            try:
                self._context.bus.write(addr + i, 1, b)
            except Exception:
                pass

    def _get_emulator(self) -> object | None:
        if not self._context:
            return None
        return getattr(self._context.bus, "_emulator", None)

    def reset(self) -> None:
        super().reset()


def build_dma(peripheral: SvdPeripheral) -> DmaPeripheral:
    return DmaPeripheral(peripheral=peripheral)
