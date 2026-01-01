from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB


@dataclass(frozen=True)
class Insn:
    address: int
    size: int
    mnemonic: str
    op_str: str
    bytes_hex: str


class ThumbDisassembler:
    def __init__(self) -> None:
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        md.detail = False
        self._md = md

    def disasm(self, code: bytes, addr: int, count: int = 0) -> List[Insn]:
        out: List[Insn] = []
        for ins in self._md.disasm(code, addr, count=count or 0):
            out.append(
                Insn(
                    address=ins.address,
                    size=ins.size,
                    mnemonic=ins.mnemonic,
                    op_str=ins.op_str,
                    bytes_hex=ins.bytes.hex(),
                )
            )
        return out
