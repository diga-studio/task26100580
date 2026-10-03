"""ELF 头与程序头解析。节表不参与任何判定。"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List

from .constants import (
    EI_CLASS,
    EI_DATA,
    ELFCLASS32,
    ELFCLASS64,
    ELFDATA2LSB,
    ELFDATA2MSB,
)
from .errors import ELFError
from .reader import FileReader

_ELF_MAGIC = b"\x7fELF"
_EHDR32_SIZE = 52
_EHDR64_SIZE = 64
_PHDR32_SIZE = 32
_PHDR64_SIZE = 56


@dataclass(frozen=True)
class ELFHeader:
    is_64: bool
    little_endian: bool
    e_type: int
    phoff: int
    phentsize: int
    phnum: int


@dataclass(frozen=True)
class ProgramHeader:
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_filesz: int
    p_memsz: int


def parse_elf_header(reader: FileReader) -> ELFHeader:
    ident = reader.read(0, 16)
    if ident[:4] != _ELF_MAGIC:
        raise ELFError("不是 ELF 文件")
    ei_class = ident[EI_CLASS]
    if ei_class == ELFCLASS32:
        is_64 = False
    elif ei_class == ELFCLASS64:
        is_64 = True
    else:
        raise ELFError(f"未知 ELFCLASS: {ei_class}")
    ei_data = ident[EI_DATA]
    if ei_data == ELFDATA2LSB:
        little = True
    elif ei_data == ELFDATA2MSB:
        little = False
    else:
        raise ELFError(f"未知 ELFDATA: {ei_data}")

    e = "<" if little else ">"
    if is_64:
        raw = reader.read(0, _EHDR64_SIZE)
        (e_type, _machine, _version, _entry, phoff, _shoff, _flags,
         _ehsize, phentsize, phnum) = struct.unpack_from(
            e + "HHIQQQIHHH", raw, 16)
    else:
        raw = reader.read(0, _EHDR32_SIZE)
        (e_type, _machine, _version, _entry, phoff, _shoff, _flags,
         _ehsize, phentsize, phnum) = struct.unpack_from(
            e + "HHIIIIIHHH", raw, 16)
    return ELFHeader(
        is_64=is_64, little_endian=little, e_type=e_type,
        phoff=phoff, phentsize=phentsize, phnum=phnum,
    )


def parse_program_headers(reader: FileReader, eh: ELFHeader) -> List[ProgramHeader]:
    need = _PHDR64_SIZE if eh.is_64 else _PHDR32_SIZE
    if eh.phnum == 0:
        return []
    if eh.phentsize < need:
        raise ELFError(
            f"e_phentsize={eh.phentsize} 小于所需 {need}"
        )
    # 普通计数，不处理扩展编号；总大小受文件大小约束，读取越界由 reader 拦截
    total = eh.phentsize * eh.phnum
    raw = reader.read(eh.phoff, total)
    e = "<" if eh.little_endian else ">"
    phdrs: List[ProgramHeader] = []
    for i in range(eh.phnum):
        base = i * eh.phentsize
        if eh.is_64:
            (p_type, p_flags, p_offset, p_vaddr, _paddr,
             p_filesz, p_memsz, _align) = struct.unpack_from(
                e + "IIQQQQQQ", raw, base)
        else:
            (p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz,
             p_flags, _align) = struct.unpack_from(
                e + "IIIIIIII", raw, base)
        phdrs.append(ProgramHeader(
            p_type=p_type, p_flags=p_flags, p_offset=p_offset,
            p_vaddr=p_vaddr, p_filesz=p_filesz, p_memsz=p_memsz,
        ))
    return phdrs
