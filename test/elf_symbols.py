"""Print symbols around given PC values, using arducopter.elf for resolution."""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def parse_elf_symbols(elf_path: Path) -> list[tuple[int, int, str]]:
    blob = elf_path.read_bytes()
    if not blob.startswith(b"\x7fELF") or blob[4] != 1:
        raise SystemExit("not an ELF32")

    (
        _ident, _etype, _machine, _version, _entry, _phoff, shoff, _flags,
        _ehsize, _phentsize, _phnum, shentsize, shnum, shstrndx,
    ) = struct.unpack_from("<16sHHIIIIIHHHHHH", blob, 0)

    # Read section headers
    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        sh = struct.unpack_from("<IIIIIIIIII", blob, off)
        sections.append(sh)  # (name, type, flags, addr, off, size, link, info, align, entsize)

    def read_str(table_off: int, idx: int) -> str:
        end = blob.index(b"\x00", table_off + idx)
        return blob[table_off + idx : end].decode("utf-8", errors="replace")

    # Find shstrtab
    shstr = sections[shstrndx]
    sh_names = [read_str(shstr[4], s[0]) for s in sections]

    # Find symtab + linked strtab
    syms: list[tuple[int, int, str]] = []
    for i, s in enumerate(sections):
        if sh_names[i] != ".symtab":
            continue
        symtab_off = s[4]
        symtab_size = s[5]
        link = s[6]
        strtab_off = sections[link][4]
        for off in range(symtab_off, symtab_off + symtab_size, 16):
            (st_name, st_value, st_size, st_info, st_other, st_shndx) = struct.unpack_from(
                "<IIIBBH", blob, off
            )
            sym_type = st_info & 0xF
            if sym_type != 2 and sym_type != 0:  # FUNC or NOTYPE only
                continue
            name = read_str(strtab_off, st_name)
            if not name:
                continue
            # Skip ARM mapping symbols ($a, $t, $d) — they mark instruction-set
            # boundaries and aren't useful for function lookup.
            if name.startswith("$") and len(name) <= 3:
                continue
            syms.append((int(st_value), int(st_size), name))
        break

    syms.sort(key=lambda x: x[0])
    return syms


def resolve(syms: list[tuple[int, int, str]], pc: int) -> str:
    pc &= ~1  # strip thumb bit
    # binary search
    lo, hi = 0, len(syms)
    while lo < hi:
        mid = (lo + hi) // 2
        if syms[mid][0] <= pc:
            lo = mid + 1
        else:
            hi = mid
    idx = lo - 1
    if idx < 0:
        return "(unknown)"
    base, size, name = syms[idx]
    offset = pc - base
    if size > 0 and offset >= size:
        return f"(after {name}+0x{size:X}, +0x{offset:X})"
    return f"{name} + 0x{offset:X}"


def main(argv: list[str]) -> int:
    elf_path = Path(__file__).with_name("arducopter.elf")
    if not elf_path.exists():
        raise SystemExit(f"elf not found: {elf_path}")
    syms = parse_elf_symbols(elf_path)
    pcs = [int(arg, 0) for arg in argv[1:]]
    if not pcs:
        # default set from earlier runs
        pcs = [0x08020F1C, 0x08182D1E, 0x0817CF1D, 0x08185771, 0x0818166C, 0x08020F0C, 0x08182952]
    for pc in pcs:
        print(f"0x{pc:08X}  {resolve(syms, pc)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
