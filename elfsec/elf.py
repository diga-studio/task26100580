"""ELF 头与程序头解析。只依赖程序头，不读取节表。"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List

from .errors import ElfFormatError
from .reader import Reader

ET_EXEC = 2
ET_DYN = 3

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551

_EHDR_SIZE_32 = 52
_EHDR_SIZE_64 = 64
_PHDR_SIZE_32 = 32
_PHDR_SIZE_64 = 56
_PN_XNUM = 0xFFFF


@dataclass(frozen=True)
class ProgramHeader:
    p_type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass(frozen=True)
class ElfInfo:
    is_64: bool
    little_endian: bool
    e_type: int
    phdrs: List[ProgramHeader]

    @property
    def phdr_size(self) -> int:
        return _PHDR_SIZE_64 if self.is_64 else _PHDR_SIZE_32


def parse_elf(reader: Reader) -> ElfInfo:
    ident = reader.read_at(0, 16)
    if ident[:4] != b"\x7fELF":
        raise ElfFormatError("不是 ELF 文件")
    ei_class, ei_data = ident[4], ident[5]
    if ei_class == 1:
        is_64 = False
    elif ei_class == 2:
        is_64 = True
    else:
        raise ElfFormatError(f"不支持的 ELF 类别: {ei_class}")
    if ei_data == 1:
        little = True
    elif ei_data == 2:
        little = False
    else:
        raise ElfFormatError(f"不支持的 ELF 编码: {ei_data}")

    ehdr_size = _EHDR_SIZE_64 if is_64 else _EHDR_SIZE_32
    ehdr = reader.read_at(0, ehdr_size)
    en = "<" if little else ">"
    e_type = struct.unpack_from(en + "H", ehdr, 16)[0]
    if e_type not in (ET_EXEC, ET_DYN):
        raise ElfFormatError(f"不支持的 ELF 类型: {e_type}")
    if is_64:
        e_phoff = struct.unpack_from(en + "Q", ehdr, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from(en + "HH", ehdr, 54)
    else:
        e_phoff = struct.unpack_from(en + "I", ehdr, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from(en + "HH", ehdr, 42)

    if e_phnum == _PN_XNUM:
        raise ElfFormatError("不支持扩展程序头编号")
    phdr_size = _PHDR_SIZE_64 if is_64 else _PHDR_SIZE_32
    if e_phnum > 0 and e_phentsize < phdr_size:
        raise ElfFormatError(f"程序头表项宽度过小: {e_phentsize}")

    phdrs: List[ProgramHeader] = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        raw = reader.read_at(off, phdr_size)
        if is_64:
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = (
                struct.unpack(en + "IIQQQQQQ", raw)
            )
        else:
            p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = (
                struct.unpack(en + "IIIIIIII", raw)
            )
        phdrs.append(
            ProgramHeader(
                p_type=p_type,
                flags=p_flags,
                offset=p_offset,
                vaddr=p_vaddr,
                filesz=p_filesz,
                memsz=p_memsz,
            )
        )
    return ElfInfo(is_64=is_64, little_endian=little, e_type=e_type, phdrs=phdrs)
