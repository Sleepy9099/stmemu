from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Symbol:
    name: str
    address: int
    size: int
    sym_type: str  # "func", "object", "other"


SHT_SYMTAB = 2
SHT_STRTAB = 3
STT_FUNC = 2
STT_OBJECT = 1


@dataclass
class SymbolTable:
    """ELF symbol table for mapping addresses to function/variable names."""

    _by_name: dict[str, Symbol] = field(default_factory=dict)
    _by_addr: dict[int, Symbol] = field(default_factory=dict)
    _func_addrs: list[int] = field(default_factory=list)  # sorted for bisect

    @property
    def count(self) -> int:
        return len(self._by_name)

    def lookup_name(self, name: str) -> Optional[Symbol]:
        return self._by_name.get(name)

    def lookup_addr(self, addr: int) -> Optional[Symbol]:
        """Find symbol at exact address."""
        return self._by_addr.get(addr & ~1)

    def find_containing(self, addr: int) -> Optional[Symbol]:
        """Find the function containing the given address."""
        import bisect
        addr = addr & ~1
        idx = bisect.bisect_right(self._func_addrs, addr) - 1
        if idx < 0:
            return None
        func_addr = self._func_addrs[idx]
        sym = self._by_addr.get(func_addr)
        if sym is None:
            return None
        if sym.size > 0 and addr >= sym.address + sym.size:
            return None
        # If size is 0 (common in ARM), accept if within reasonable range
        if sym.size == 0 and addr - sym.address > 0x10000:
            return None
        return sym

    def format_addr(self, addr: int) -> str:
        """Format address with symbol name if known."""
        sym = self.lookup_addr(addr & ~1)
        if sym is not None:
            return f"0x{addr & ~1:08X} <{sym.name}>"
        containing = self.find_containing(addr)
        if containing is not None:
            offset = (addr & ~1) - containing.address
            return f"0x{addr & ~1:08X} <{containing.name}+0x{offset:X}>"
        return f"0x{addr & ~1:08X}"

    def search(self, pattern: str) -> list[Symbol]:
        """Search symbols by substring match."""
        pattern_lower = pattern.lower()
        return [s for s in self._by_name.values() if pattern_lower in s.name.lower()]


def load_symbols(path: Path) -> SymbolTable:
    """Load symbol table from an ELF file."""
    blob = path.read_bytes()
    if not blob.startswith(b"\x7fELF") or len(blob) < 52:
        return SymbolTable()

    elf_class = blob[4]
    if elf_class != 1:  # ELF32 only
        return SymbolTable()

    (
        _ident, _etype, _machine, _version, _entry,
        _phoff, shoff, _flags, _ehsize, _phentsize,
        _phnum, shentsize, shnum, shstrndx,
    ) = struct.unpack_from("<16sHHIIIIIHHHHHH", blob, 0)

    if shoff == 0 or shnum == 0:
        return SymbolTable()

    # Read section headers
    sections: list[dict] = []
    for i in range(shnum):
        off = shoff + i * shentsize
        if off + 40 > len(blob):
            break
        sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, sh_link, _sh_info, _sh_addralign, sh_entsize = \
            struct.unpack_from("<IIIIIIIIII", blob, off)
        sections.append({
            "name_off": sh_name,
            "type": sh_type,
            "offset": sh_offset,
            "size": sh_size,
            "link": sh_link,
            "entsize": sh_entsize,
        })

    # Find symtab and its strtab
    table = SymbolTable()
    for sec in sections:
        if sec["type"] != SHT_SYMTAB:
            continue
        strtab_idx = sec["link"]
        if strtab_idx >= len(sections):
            continue
        strtab = sections[strtab_idx]
        if strtab["type"] != SHT_STRTAB:
            continue

        strtab_data = blob[strtab["offset"]:strtab["offset"] + strtab["size"]]
        entsize = sec["entsize"] or 16
        sym_data = blob[sec["offset"]:sec["offset"] + sec["size"]]

        for i in range(0, len(sym_data), entsize):
            if i + 16 > len(sym_data):
                break
            st_name, st_value, st_size, st_info, _st_other, _st_shndx = \
                struct.unpack_from("<IIIBBH", sym_data, i)

            st_type = st_info & 0xF
            if st_type == STT_FUNC:
                sym_type = "func"
            elif st_type == STT_OBJECT:
                sym_type = "object"
            else:
                continue  # Skip non-func/non-object symbols

            # Read name from strtab
            if st_name >= len(strtab_data):
                continue
            name_end = strtab_data.index(0, st_name) if 0 in strtab_data[st_name:] else len(strtab_data)
            name = strtab_data[st_name:name_end].decode("utf-8", errors="replace")
            if not name or name.startswith("$"):
                continue  # Skip ARM mapping symbols ($t, $a, $d)

            addr = st_value & ~1  # Strip Thumb bit
            sym = Symbol(name=name, address=addr, size=st_size, sym_type=sym_type)
            table._by_name[name] = sym
            # Prefer function symbols over object symbols at the same address
            existing = table._by_addr.get(addr)
            if existing is None or (existing.sym_type != "func" and sym_type == "func"):
                table._by_addr[addr] = sym

    # Build sorted function address list for bisect lookup
    table._func_addrs = sorted(
        sym.address for sym in table._by_addr.values() if sym.sym_type == "func"
    )

    return table
