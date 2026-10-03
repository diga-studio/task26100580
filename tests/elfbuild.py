"""测试用 ELF 样本构造器：显式布局，可构造无节表、跨段、重叠段等样本。"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

ET_EXEC = 2
ET_DYN = 3

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

DT_NULL = 0
DT_PLTRELSZ = 2
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_JMPREL = 23
DT_FLAGS_1 = 0x6FFFFFFB

DF_1_PIE = 0x08000000


class ElfBuilder:
    """按显式文件布局拼装 ELF。默认不含节表。"""

    def __init__(self, is_64: bool = True, little: bool = True, e_type: int = ET_DYN):
        self.is_64 = is_64
        self.little = little
        self.e_type = e_type
        self.phdrs: List[Tuple[int, int, int, int, int, int]] = []
        self.regions: Dict[int, bytes] = {}
        self.shdr_table: Optional[bytes] = None

    @property
    def en(self) -> str:
        return "<" if self.little else ">"

    @property
    def ehdr_size(self) -> int:
        return 64 if self.is_64 else 52

    @property
    def phdr_size(self) -> int:
        return 56 if self.is_64 else 32

    @property
    def phoff(self) -> int:
        return self.ehdr_size

    @property
    def phdrs_end(self) -> int:
        return self.phoff + len(self.phdrs) * self.phdr_size

    def add_phdr(
        self,
        p_type: int,
        flags: int,
        offset: int,
        vaddr: int,
        filesz: int,
        memsz: int,
    ) -> None:
        self.phdrs.append((p_type, flags, offset, vaddr, filesz, memsz))

    def add_load(self, offset: int, vaddr: int, filesz: int, memsz: int) -> None:
        self.add_phdr(PT_LOAD, PF_R | PF_X, offset, vaddr, filesz, memsz)

    def set_data(self, offset: int, data: bytes) -> None:
        self.regions[offset] = data

    def pack_sym(self, st_name: int, st_shndx: int, st_value: int = 0) -> bytes:
        if self.is_64:
            return struct.pack(
                self.en + "IBBHQQ", st_name, 0, 0, st_shndx, st_value, 0
            )
        return struct.pack(
            self.en + "IIIBBH", st_name, st_value, 0, 0, 0, st_shndx
        )

    def pack_rel(self, r_offset: int, r_info: int) -> bytes:
        if self.is_64:
            return struct.pack(self.en + "QQ", r_offset, r_info)
        return struct.pack(self.en + "II", r_offset, r_info)

    def pack_rela(self, r_offset: int, r_info: int, r_addend: int = 0) -> bytes:
        if self.is_64:
            return struct.pack(self.en + "QQq", r_offset, r_info, r_addend)
        return struct.pack(self.en + "IIi", r_offset, r_info, r_addend)

    def r_info(self, sym_index: int, r_type: int = 0) -> int:
        if self.is_64:
            return (sym_index << 32) | r_type
        return (sym_index << 8) | r_type

    def pack_dyn(self, entries: List[Tuple[int, int]]) -> bytes:
        if self.is_64:
            return b"".join(struct.pack(self.en + "QQ", t, v) for t, v in entries)
        return b"".join(struct.pack(self.en + "II", t, v) for t, v in entries)

    def build(self) -> bytes:
        eh = bytearray(self.ehdr_size)
        eh[:4] = b"\x7fELF"
        eh[4] = 2 if self.is_64 else 1
        eh[5] = 1 if self.little else 2
        eh[6] = 1
        struct.pack_into(self.en + "H", eh, 16, self.e_type)
        phoff = self.phoff
        shoff = 0
        if self.is_64:
            struct.pack_into(self.en + "Q", eh, 32, phoff)
            struct.pack_into(self.en + "HH", eh, 54, self.phdr_size, len(self.phdrs))
        else:
            struct.pack_into(self.en + "I", eh, 28, phoff)
            struct.pack_into(self.en + "HH", eh, 42, self.phdr_size, len(self.phdrs))

        ph = bytearray()
        for p_type, flags, offset, vaddr, filesz, memsz in self.phdrs:
            if self.is_64:
                ph += struct.pack(
                    self.en + "IIQQQQQQ",
                    p_type, flags, offset, vaddr, 0, filesz, memsz, 0x1000,
                )
            else:
                ph += struct.pack(
                    self.en + "IIIIIIII",
                    p_type, offset, vaddr, 0, filesz, memsz, flags, 0x1000,
                )

        size = self.phdrs_end
        for p_type, _flags, offset, _vaddr, filesz, _memsz in self.phdrs:
            if p_type == PT_LOAD:
                size = max(size, offset + filesz)
        for off, data in self.regions.items():
            size = max(size, off + len(data))
        if self.shdr_table is not None:
            shoff = size
            size += len(self.shdr_table)
            if self.is_64:
                struct.pack_into(self.en + "Q", eh, 40, shoff)
            else:
                struct.pack_into(self.en + "I", eh, 32, shoff)

        buf = bytearray(size)
        buf[: len(eh)] = eh
        buf[self.phoff : self.phoff + len(ph)] = ph
        for off, data in self.regions.items():
            buf[off : off + len(data)] = data
        if self.shdr_table is not None:
            buf[shoff : shoff + len(self.shdr_table)] = self.shdr_table
        return bytes(buf)


def make_shdr_table(is_64: bool, little: bool, count: int = 3) -> bytes:
    """生成一张内容任意但格式合法的节表，用于验证节表不影响结论。"""
    en = "<" if little else ">"
    out = bytearray()
    for i in range(count):
        if is_64:
            out += struct.pack(en + "IIQQQQIIQQ", i, 1, 0, 0, 0, 0, 0, 0, 1, 0)
        else:
            out += struct.pack(en + "IIIIIIIIII", i, 1, 0, 0, 0, 0, 0, 0, 1, 0)
    return bytes(out)
