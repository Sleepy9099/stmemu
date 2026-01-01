from __future__ import annotations

from dataclasses import dataclass

from stmemu.svd.model import SvdPeripheral
from stmemu.utils.bits import mask_for_size


@dataclass
class GenericRegisterFilePeripheral:
    peripheral: SvdPeripheral

    def __post_init__(self) -> None:
        # offset->value
        self._regs: dict[int, int] = {}
        # preload reset values from SVD where available
        for r in self.peripheral.registers:
            if r.reset_value is not None:
                self._regs[r.offset] = int(r.reset_value) & 0xFFFFFFFF
        self._read_counts: dict[int, int] = {}
        self._force_bits_after_reads: dict[int, tuple[int, int]] = {}

    def _offset(self, addr: int) -> int:
        return addr - self.peripheral.base_address

    def read(self, addr: int, size: int) -> int:
        off = self._offset(addr)

        # count reads
        self._read_counts[off] = self._read_counts.get(off, 0) + 1

        val = self._regs.get(off, 0)

        # apply "force bit" rules to break spin loops
        rule = self._force_bits_after_reads.get(off)
        if rule:
            bit_index, nreads = rule
            if self._read_counts[off] >= nreads:
                val |= (1 << bit_index)
                self._regs[off] = val & 0xFFFFFFFF

        return val & mask_for_size(size)

    def write(self, addr: int, size: int, value: int) -> None:
        off = self._offset(addr)
        # store full 32-bit by default, but respect size mask
        m = mask_for_size(size)
        prev = self._regs.get(off, 0)
        new_val = (prev & ~m) | (value & m)
        self._regs[off] = new_val & 0xFFFFFFFF

    def force_bit_after_reads(self, reg_offset: int, bit_index: int, reads_before_set: int = 5) -> None:
        self._force_bits_after_reads[reg_offset] = (bit_index, reads_before_set)