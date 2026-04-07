from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralContext
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral


@dataclass
class DmaPeripheral(GenericRegisterFilePeripheral):
    """DMA controller with transfer-complete flag simulation.

    Firmware configures DMA channels, enables them, then polls for
    transfer-complete or half-transfer flags. Without flag simulation,
    polling loops hang.

    This model auto-sets transfer-complete flags when a channel is
    enabled, simulating instant DMA completion.
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

    _SxCR_EN = 1 << 0   # Stream enable
    _SxCR_TCIE = 1 << 4  # Transfer complete interrupt enable

    # LISR/HISR bit layout: each stream has TCIF, HTIF, TEIF, DMEIF, FEIF
    # Stream 0: bits 5,4,3,2,0 in LISR
    # Stream 1: bits 11,10,9,8,6 in LISR
    # etc.
    _STREAM_TC_BITS = {
        0: (0, 5),   # (register_index, bit) - reg 0=LISR, 1=HISR
        1: (0, 11),
        2: (0, 21),
        3: (0, 27),
        4: (1, 5),
        5: (1, 11),
        6: (1, 21),
        7: (1, 27),
    }

    def __post_init__(self) -> None:
        super().__post_init__()
        # Resolve ISR/IFCR offsets from SVD if available
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

    def attach(self, context: PeripheralContext) -> None:
        self._context = context

    def write(self, offset: int, size: int, value: int) -> None:
        # Handle IFCR writes (write-1-to-clear status flags)
        if size == 4 and offset == self._LIFCR:
            current = self.read_register_value(self._LISR)
            self.write_register_value(self._LISR, current & ~int(value))
            return
        if size == 4 and offset == self._HIFCR:
            current = self.read_register_value(self._HISR)
            self.write_register_value(self._HISR, current & ~int(value))
            return

        super().write(offset, size, value)

        # Check if a stream was just enabled - auto-complete transfer
        for stream in range(8):
            stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
            cr_offset = stream_offset + self._SxCR
            if offset == cr_offset and (int(value) & self._SxCR_EN):
                self._auto_complete_stream(stream)

    def _auto_complete_stream(self, stream: int) -> None:
        """Set transfer-complete flag and clear EN bit for a stream."""
        tc_info = self._STREAM_TC_BITS.get(stream)
        if tc_info is None:
            return

        reg_idx, bit = tc_info
        isr_offset = self._LISR if reg_idx == 0 else self._HISR
        isr = self.read_register_value(isr_offset)
        isr |= (1 << bit)  # Set TCIF
        self.write_register_value(isr_offset, isr)

        # Clear EN bit (hardware clears it when transfer completes)
        stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
        cr = self.read_register_value(stream_offset + self._SxCR)
        self.write_register_value(stream_offset + self._SxCR, cr & ~self._SxCR_EN)

        # Set NDTR to 0 (all items transferred)
        self.write_register_value(stream_offset + self._SxNDTR, 0)

    def reset(self) -> None:
        super().reset()


def build_dma(peripheral: SvdPeripheral) -> DmaPeripheral:
    return DmaPeripheral(peripheral=peripheral)
