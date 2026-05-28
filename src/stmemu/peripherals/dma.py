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
    _SxCR_PINC = 1 << 9
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
    _stream_busy: dict[int, bool] = field(default_factory=dict, init=False, repr=False)
    _pending_requests: list[tuple[int, str, int]] = field(
        default_factory=list, init=False, repr=False,
    )
    _dispatching: bool = field(default=False, init=False, repr=False)

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
        # Re-entrant requests (e.g. an SPI exchange triggered by a
        # transferred byte emits another request mid-loop) are queued
        # and drained after the current dispatch returns.
        if self._dispatching:
            self._pending_requests.append((periph_addr, direction, size))
            return
        self._dispatching = True
        try:
            self._dispatch_request(periph_addr, direction, size)
            while self._pending_requests:
                a, d, s = self._pending_requests.pop(0)
                self._dispatch_request(a, d, s)
        finally:
            self._dispatching = False

    def _dispatch_request(
        self, periph_addr: int, direction: str, size: int = 1,
    ) -> None:
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
                if self._stream_busy.get(stream):
                    continue
                self._stream_busy[stream] = True
                try:
                    self._transfer_one_item(stream)
                finally:
                    self._stream_busy[stream] = False
                break

    def write(self, offset: int, size: int, value: int) -> None:
        if self._access_targets(offset, size, self._LIFCR):
            clear_mask = self._aligned_write_value(offset, size, self._LIFCR, value)
            current = self.read_register_value(self._LISR)
            self.write_register_value(self._LISR, current & ~clear_mask)
            return
        if self._access_targets(offset, size, self._HIFCR):
            clear_mask = self._aligned_write_value(offset, size, self._HIFCR, value)
            current = self.read_register_value(self._HISR)
            self.write_register_value(self._HISR, current & ~clear_mask)
            return

        super().write(offset, size, value)

        for stream in range(8):
            stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
            cr_offset = stream_offset + self._SxCR
            if self._access_targets(offset, size, cr_offset):
                aligned = self._aligned_write_value(offset, size, cr_offset, value)
                if aligned & self._SxCR_EN:
                    self._on_stream_enable(stream)

    def _on_stream_enable(self, stream: int) -> None:
        stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
        cr = self.read_register_value(stream_offset + self._SxCR)
        ndtr = self.read_register_value(stream_offset + self._SxNDTR) & 0xFFFF
        mar = self.read_register_value(stream_offset + self._SxM0AR)
        par = self.read_register_value(stream_offset + self._SxPAR)
        direction = (cr >> self._SxCR_DIR_SHIFT) & self._SxCR_DIR_MASK
        self._stream_ndtr_reload[stream] = ndtr
        self._stream_mar_base[stream] = mar
        self._stream_pos[stream] = 0

        if cr & self._SxCR_CIRC:
            self._notify_peripheral_armed(par, direction)
            return
        # Peripheral DMA (P2M/M2P with PAR inside a mounted peripheral)
        # waits for the peripheral to assert dma_request; no bulk-on-enable.
        # M2M and "anonymous" PAR addresses fall through to the existing
        # bulk-completion path so legacy tests (and pure memcpy DMA) still
        # auto-complete.
        if self._is_peripheral_driven(par, direction):
            self._notify_peripheral_armed(par, direction)
            return
        self._execute_transfer(stream)

    def _notify_peripheral_armed(self, par: int, direction: int) -> None:
        """Tell the peripheral at ``par`` that a stream is now ready.

        Lets a peripheral whose DMA request fired before the stream was
        enabled (firmware order: configure SPI + DMAEN, then arm streams)
        re-emit so the transfer actually starts.
        """
        if not self._context or not getattr(self._context, "bus", None):
            return
        bus = self._context.bus
        mount_for = getattr(bus, "_mount_for_addr", None)
        if mount_for is None:
            return
        mounted = mount_for(par)
        if mounted is None or mounted.model is self:
            return
        hook = getattr(mounted.model, "on_dma_armed", None)
        if hook is None:
            return
        dir_str = "m2p" if direction == self._DIR_M2P else "p2m"
        try:
            hook(par - mounted.base, dir_str)
        except Exception:
            log.debug("on_dma_armed hook failed")

    def _is_peripheral_driven(self, par: int, direction: int) -> bool:
        if direction == self._DIR_M2M:
            return False
        if not self._context or not getattr(self._context, "bus", None):
            return False
        bus = self._context.bus
        mount_for = getattr(bus, "_mount_for_addr", None)
        if mount_for is None:
            return False
        mounted = mount_for(par)
        if mounted is None:
            return False
        # Don't treat our own DMA controller registers as peripheral DMA.
        return mounted.model is not self

    def _transfer_one_item(self, stream: int) -> None:
        stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
        cr = self.read_register_value(stream_offset + self._SxCR)
        par = self.read_register_value(stream_offset + self._SxPAR)
        direction = (cr >> self._SxCR_DIR_SHIFT) & self._SxCR_DIR_MASK
        psize = 1 << ((cr >> self._SxCR_PSIZE_SHIFT) & 0x3)

        reload = self._stream_ndtr_reload.get(stream, 0)
        if reload == 0:
            return
        pos = self._stream_pos.get(stream, 0)
        mar_base = self._stream_mar_base.get(stream, 0)

        # NDTR counts peripheral data items of PSIZE bytes each. Memory is
        # always laid out contiguously (the hardware packs/unpacks when MSIZE
        # differs from PSIZE), so item ``pos`` lands at a PSIZE-strided offset.
        if cr & self._SxCR_MINC:
            mar = mar_base + pos * psize
        else:
            mar = mar_base

        emu = self._get_emulator()
        if emu is not None:
            try:
                self._do_transfer(
                    emu, direction, par, mar, n_items=1, psize=psize, cr=cr,
                )
            except Exception:
                log.debug("DMA stream %d item transfer failed", stream)

        pos += 1
        ndtr = reload - pos
        circular = bool(cr & self._SxCR_CIRC)

        half = reload // 2
        if pos == half and half > 0:
            self._set_htif(stream, cr, half * psize)

        if ndtr <= 0:
            self._set_tcif(stream, cr)
            if circular:
                pos = 0
                ndtr = reload
            else:
                # Non-circular: stream completes and clears EN. NDTR stays
                # at 0 so firmware can observe completion.
                ndtr = 0
                self.write_register_value(
                    stream_offset + self._SxCR, cr & ~self._SxCR_EN,
                )
            self._emit_dma_event("dma_complete", stream, cr, par, reload * psize)

        self._stream_pos[stream] = pos
        self.write_register_value(stream_offset + self._SxNDTR, ndtr)

    def _execute_transfer(self, stream: int) -> None:
        stream_offset = self._STREAM_BASE + stream * self._STREAM_STRIDE
        cr = self.read_register_value(stream_offset + self._SxCR)
        ndtr = self.read_register_value(stream_offset + self._SxNDTR) & 0xFFFF
        par = self.read_register_value(stream_offset + self._SxPAR)
        mar = self.read_register_value(stream_offset + self._SxM0AR)
        direction = (cr >> self._SxCR_DIR_SHIFT) & self._SxCR_DIR_MASK
        psize = 1 << ((cr >> self._SxCR_PSIZE_SHIFT) & 0x3)

        emu = self._get_emulator()
        if emu is not None and ndtr > 0:
            try:
                self._do_transfer(
                    emu, direction, par, mar, n_items=ndtr, psize=psize, cr=cr,
                )
            except Exception:
                log.debug("DMA stream %d transfer failed", stream)

        self._set_tcif(stream, cr)
        self.write_register_value(stream_offset + self._SxCR, cr & ~self._SxCR_EN)
        self.write_register_value(stream_offset + self._SxNDTR, 0)
        self._emit_dma_event("dma_complete", stream, cr, par, ndtr * psize)

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

    def _set_htif(self, stream: int, cr: int, byte_count: int = 0) -> None:
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
        par = self.read_register_value(
            self._STREAM_BASE + stream * self._STREAM_STRIDE + self._SxPAR,
        )
        self._emit_dma_event("dma_half", stream, cr, par, byte_count)

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
        self, emu: object, direction: int, par: int, mar: int, *,
        n_items: int, psize: int, cr: int = 0,
    ) -> None:
        """Move ``n_items`` data items between ``par`` and ``mar``.

        The peripheral side is accessed in PSIZE-wide transactions (so a 16-bit
        data register is read/written as one halfword, not two bytes) and the
        peripheral pointer advances by PSIZE when PINC is set. The memory side
        is byte-contiguous when MINC is set, which matches the hardware packing
        behaviour when MSIZE differs from PSIZE (MSIZE only changes the memory
        bus access width, which is not observable against a byte-addressed RAM).
        """
        pinc = bool(cr & self._SxCR_PINC)
        minc = bool(cr & self._SxCR_MINC)
        if direction == self._DIR_P2M:
            buf = bytearray()
            for k in range(n_items):
                addr = par + (k * psize if pinc else 0)
                buf += self._bus_read_item(addr, psize)
            if minc:
                emu.mem_write(mar, bytes(buf))
            else:
                # No memory increment: every item lands at the same address.
                for k in range(n_items):
                    emu.mem_write(mar, bytes(buf[k * psize:(k + 1) * psize]))
        elif direction == self._DIR_M2P:
            for k in range(n_items):
                src = mar + (k * psize if minc else 0)
                chunk = bytes(emu.mem_read(src, psize))
                value = int.from_bytes(chunk.ljust(psize, b"\x00"), "little")
                addr = par + (k * psize if pinc else 0)
                self._bus_write_item(addr, psize, value)
        elif direction == self._DIR_M2M:
            total = n_items * psize
            emu.mem_write(mar, bytes(emu.mem_read(par, total)))

    def _bus_read_item(self, addr: int, size: int) -> bytes:
        if not self._context:
            return b"\x00" * size
        try:
            val = self._context.bus.read(addr, size)
        except Exception:
            val = 0
        return (int(val) & ((1 << (size * 8)) - 1)).to_bytes(size, "little")

    def _bus_write_item(self, addr: int, size: int, value: int) -> None:
        if not self._context:
            return
        try:
            self._context.bus.write(addr, size, int(value) & ((1 << (size * 8)) - 1))
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
        self._stream_busy.clear()
        self._pending_requests.clear()
        self._dispatching = False

    def snapshot_state(self) -> object | None:
        base = super().snapshot_state()
        if not isinstance(base, dict):
            base = {}
        base["stream_ndtr_reload"] = dict(self._stream_ndtr_reload)
        base["stream_mar_base"] = dict(self._stream_mar_base)
        base["stream_pos"] = dict(self._stream_pos)
        return base

    def restore_state(self, state: object) -> None:
        super().restore_state(state)
        if not isinstance(state, dict):
            return
        reload = state.get("stream_ndtr_reload")
        if isinstance(reload, dict):
            self._stream_ndtr_reload = {int(k): int(v) for k, v in reload.items()}
        mar = state.get("stream_mar_base")
        if isinstance(mar, dict):
            self._stream_mar_base = {int(k): int(v) for k, v in mar.items()}
        pos = state.get("stream_pos")
        if isinstance(pos, dict):
            self._stream_pos = {int(k): int(v) for k, v in pos.items()}


def build_dma(peripheral: SvdPeripheral) -> DmaPeripheral:
    return DmaPeripheral(peripheral=peripheral)
