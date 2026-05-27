from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from stmemu.peripherals.bus import PeripheralContext, PeripheralEvent
from stmemu.peripherals.generic import GenericRegisterFilePeripheral
from stmemu.svd.model import SvdPeripheral
from stmemu.utils.logger import get_logger

log = get_logger(__name__)

_STREAM_FLAG_BITS: dict[int, tuple[int, int, int]] = {
    0: (0, 5, 4),
    1: (0, 11, 10),
    2: (0, 21, 20),
    3: (0, 27, 26),
    4: (1, 5, 4),
    5: (1, 11, 10),
    6: (1, 21, 20),
    7: (1, 27, 26),
}


@dataclass
class DmaPeripheral(GenericRegisterFilePeripheral):
    """DMA controller with normal and circular transfer modes.

    Normal mode: bulk transfer on enable, then EN clears.
    Circular mode: incremental per-request transfers that wrap the
    memory pointer and reload NDTR at each cycle boundary.
    """

    _context: PeripheralContext | None = field(default=None, init=False, repr=False)

    _LISR = 0x00
    _HISR = 0x04
    _LIFCR = 0x08
    _HIFCR = 0x0C

    _STREAM_BASE = 0x10
    _STREAM_STRIDE = 0x18

    _SxCR = 0x00
    _SxNDTR = 0x04
    _SxPAR = 0x08
    _SxM0AR = 0x0C
    _SxM1AR = 0x10
    _SxFCR = 0x14

    _SxCR_EN = 1 << 0
    _SxCR_TCIE = 1 << 4
    _SxCR_HTIE = 1 << 3
    _SxCR_CIRC = 1 << 8
    _SxCR_DIR_SHIFT = 6
    _SxCR_DIR_MASK = 0x3
    _SxCR_MSIZE_SHIFT = 13
    _SxCR_PSIZE_SHIFT = 11
    _SxCR_MINC = 1 << 10

    _DIR_P2M = 0
    _DIR_M2P = 1
    _DIR_M2M = 2

    _irqs: dict[int, int] = field(default_factory=dict, init=False, repr=False)
    _stream_ndtr_reload: dict[int, int] = field(default_factory=dict, init=False, repr=False)
    _stream_mar_base: dict[int, int] = field(default_factory=dict, init=False, repr=False)
    _stream_pos: dict[int, int] = field(default_factory=dict, init=False, repr=False)

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
                if cr & self._SxCR_CIRC:
                    self._transfer_one_item(stream)
                else:
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
                self._on_stream_enable(stream)

    def _on_stream_enable(self, stream: int) -> None:
        stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
        cr = self.read_register_value(stream_offset + self._SxCR)
        ndtr = self.read_register_value(stream_offset + self._SxNDTR) & 0xFFFF
        mar = self.read_register_value(stream_offset + self._SxM0AR)
        self._stream_ndtr_reload[stream] = ndtr
        self._stream_mar_base[stream] = mar
        self._stream_pos[stream] = 0

        if cr & self._SxCR_CIRC:
            pass
        else:
            self._execute_transfer(stream)

    def _transfer_one_item(self, stream: int) -> None:
        stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
        cr = self.read_register_value(stream_offset + self._SxCR)
        par = self.read_register_value(stream_offset + self._SxPAR)
        direction = (cr >> self._SxCR_DIR_SHIFT) & self._SxCR_DIR_MASK
        item_size = 1 << ((cr >> self._SxCR_PSIZE_SHIFT) & 0x3)

        reload = self._stream_ndtr_reload.get(stream, 0)
        if reload == 0:
            return
        pos = self._stream_pos.get(stream, 0)
        mar_base = self._stream_mar_base.get(stream, 0)

        if cr & self._SxCR_MINC:
            mar = mar_base + pos * item_size
        else:
            mar = mar_base

        emu = self._get_emulator()
        if emu is not None:
            try:
                self._do_transfer(emu, direction, par, mar, item_size)
            except Exception:
                log.debug("DMA stream %d item transfer failed", stream)

        pos += 1
        ndtr = reload - pos

        half = reload // 2
        if pos == half and half > 0:
            self._set_htif(stream, cr)

        if ndtr <= 0:
            self._set_tcif(stream, cr)
            pos = 0
            ndtr = reload
            self._emit_dma_event("dma_complete", stream, cr, par, reload * item_size)

        self._stream_pos[stream] = pos
        self.write_register_value(stream_offset + self._SxNDTR, ndtr)

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

        self._set_tcif(stream, cr)
        self.write_register_value(stream_offset + self._SxCR, cr & ~self._SxCR_EN)
        self.write_register_value(stream_offset + self._SxNDTR, 0)
        self._emit_dma_event("dma_complete", stream, cr, par,
                             ndtr * max(1, 1 << ((cr >> self._SxCR_PSIZE_SHIFT) & 0x3)))

    def _set_tcif(self, stream: int, cr: int) -> None:
        info = _STREAM_FLAG_BITS.get(stream)
        if info is None:
            return
        reg_idx, tc_bit, _ = info
        isr_offset = self._LISR if reg_idx == 0 else self._HISR
        isr = self.read_register_value(isr_offset)
        self.write_register_value(isr_offset, isr | (1 << tc_bit))
        if (cr & self._SxCR_TCIE) and self._context and self._context.interrupts:
            irq = self._irqs.get(stream)
            if irq is not None:
                self._context.interrupts.set_irq_pending(irq)

    def _set_htif(self, stream: int, cr: int) -> None:
        info = _STREAM_FLAG_BITS.get(stream)
        if info is None:
            return
        reg_idx, _, ht_bit = info
        isr_offset = self._LISR if reg_idx == 0 else self._HISR
        isr = self.read_register_value(isr_offset)
        self.write_register_value(isr_offset, isr | (1 << ht_bit))
        if (cr & self._SxCR_HTIE) and self._context and self._context.interrupts:
            irq = self._irqs.get(stream)
            if irq is not None:
                self._context.interrupts.set_irq_pending(irq)

    def _emit_dma_event(
        self, kind: str, stream: int, cr: int, par: int, byte_count: int,
    ) -> None:
        if self._context and self._context.bus:
            direction = (cr >> self._SxCR_DIR_SHIFT) & self._SxCR_DIR_MASK
            self._context.bus.emit(PeripheralEvent(
                kind=kind,
                source=self._context.name,
                address=par,
                payload={"stream": stream, "direction": direction, "bytes": byte_count},
            ))

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
        self._stream_ndtr_reload.clear()
        self._stream_mar_base.clear()
        self._stream_pos.clear()


def build_dma(peripheral: SvdPeripheral) -> DmaPeripheral:
    return DmaPeripheral(peripheral=peripheral)
