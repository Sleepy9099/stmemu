from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct


ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFDATA2LSB = 1
PT_LOAD = 1


@dataclass(frozen=True)
class FirmwareSegment:
    address: int
    data: bytes


@dataclass(frozen=True)
class FirmwareImage:
    format: str
    vector_base: int
    segments: tuple[FirmwareSegment, ...]
    entry_point: int | None = None


def load_firmware(path: Path, base_addr: int | None = None) -> FirmwareImage:
    blob = path.read_bytes()
    if blob.startswith(ELF_MAGIC):
        return _load_elf(path, blob)
    if base_addr is None:
        raise ValueError("raw firmware images require a base address")
    return FirmwareImage(
        format="bin",
        vector_base=int(base_addr),
        segments=(FirmwareSegment(address=int(base_addr), data=blob),),
    )


def _load_elf(path: Path, blob: bytes) -> FirmwareImage:
    if len(blob) < 52:
        raise ValueError(f"ELF file too small: {path}")

    elf_class = blob[4]
    elf_data = blob[5]
    if elf_class != ELFCLASS32:
        raise ValueError(f"unsupported ELF class {elf_class} in {path}; only ELF32 is supported")
    if elf_data != ELFDATA2LSB:
        raise ValueError(f"unsupported ELF endianness {elf_data} in {path}; only little-endian is supported")

    (
        _ident,
        _etype,
        _machine,
        _version,
        entry_point,
        phoff,
        _shoff,
        _flags,
        _ehsize,
        phentsize,
        phnum,
        _shentsize,
        _shnum,
        _shstrndx,
    ) = struct.unpack_from("<16sHHIIIIIHHHHHH", blob, 0)

    if phoff == 0 or phnum == 0:
        raise ValueError(f"ELF has no program headers: {path}")
    if phentsize < 32:
        raise ValueError(f"unexpected ELF program header size {phentsize} in {path}")

    segments: list[FirmwareSegment] = []
    for index in range(phnum):
        off = phoff + (index * phentsize)
        if off + 32 > len(blob):
            raise ValueError(f"truncated ELF program header {index} in {path}")

        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, _p_flags, _p_align = struct.unpack_from(
            "<IIIIIIII", blob, off
        )
        if p_type != PT_LOAD or p_memsz == 0:
            continue
        if p_offset + p_filesz > len(blob):
            raise ValueError(f"truncated ELF segment {index} in {path}")

        file_data = blob[p_offset : p_offset + p_filesz]

        # Use the runtime VMA as the primary placement so initialized RAM data
        # is immediately visible to the emulator.
        addr = p_vaddr or p_paddr
        data = file_data
        if p_memsz > p_filesz:
            data += b"\x00" * (p_memsz - p_filesz)
        segments.append(FirmwareSegment(address=addr, data=data))

        # Also materialize the file image at its physical/LMA address when it
        # differs from the VMA. STM32 startup code often copies .data from this
        # flash image into RAM during reset.
        if p_filesz > 0 and p_paddr not in (0, addr):
            segments.append(FirmwareSegment(address=p_paddr, data=file_data))

    if not segments:
        raise ValueError(f"ELF has no PT_LOAD segments: {path}")

    segments.sort(key=lambda seg: seg.address)
    entry_addr = int(entry_point) & ~1
    vector_base = segments[0].address
    for segment in segments:
        if segment.address <= entry_addr < segment.address + len(segment.data):
            vector_base = segment.address
            break

    return FirmwareImage(
        format="elf",
        vector_base=vector_base,
        segments=tuple(segments),
        entry_point=int(entry_point),
    )
