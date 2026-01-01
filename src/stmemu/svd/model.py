from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class SvdField:
    name: str
    bit_offset: int
    bit_width: int


@dataclass(frozen=True)
class SvdRegister:
    name: str
    offset: int
    size_bits: int = 32
    reset_value: Optional[int] = None
    fields: tuple[SvdField, ...] = ()


@dataclass(frozen=True)
class SvdPeripheral:
    name: str
    base_address: int
    size: int  # bytes (from addressBlock.size if present; else heuristic)
    registers: tuple[SvdRegister, ...] = ()


@dataclass(frozen=True)
class SvdDevice:
    name: str
    peripherals: tuple[SvdPeripheral, ...] = ()
