from __future__ import annotations

from dataclasses import dataclass, field

from stmemu.peripherals.registers import RegisterPeripheral, RegisterSpec
from stmemu.svd.model import SvdPeripheral


@dataclass
class GenericRegisterFilePeripheral(RegisterPeripheral):
    peripheral: SvdPeripheral
    _read_counts: dict[int, int] = field(init=False, repr=False)
    _force_bits_after_reads: dict[int, list[tuple[int, int]]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        super().__init__(self.peripheral.name)
        for r in self.peripheral.registers:
            self.add_register(
                RegisterSpec(
                    name=r.name,
                    offset=r.offset,
                    size_bits=r.size_bits,
                    reset_value=0 if r.reset_value is None else int(r.reset_value),
                    access=r.access if r.access in ("rw", "ro", "wo") else "rw",
                )
            )
        self._read_counts = {}
        self._force_bits_after_reads = {}

    def read(self, offset: int, size: int) -> int:
        spec = self._find_register(offset, size)
        if spec is not None:
            self._read_counts[spec.offset] = self._read_counts.get(spec.offset, 0) + 1
            rules = self._force_bits_after_reads.get(spec.offset, ())
            if rules:
                value = self.read_register_value(spec.offset)
                changed = False
                for bit_index, nreads in rules:
                    if self._read_counts[spec.offset] >= nreads:
                        value |= (1 << bit_index)
                        changed = True
                if changed:
                    self.write_register_value(spec.offset, value)
        return super().read(offset, size)

    def force_bit_after_reads(self, reg_offset: int, bit_index: int, reads_before_set: int = 5) -> None:
        rules = self._force_bits_after_reads.setdefault(reg_offset, [])
        rules.append((bit_index, reads_before_set))
