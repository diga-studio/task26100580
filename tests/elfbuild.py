"""测试用 ELF 样本构造器：直接拼装字节，不依赖外部工具链。"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PF_X, PF_W, PF_R = 1, 2, 4

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

ET_EXEC = 2
ET_DYN = 3
SHN_UNDEF = 0


@dataclass
class Phdr:
    p_type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


class ELFBuilder:
    """按类别/端序构造 ELF；程序头表在 build 时追加到内容之后。"""

    def __init__(self, is_64: bool = True, little: bool = True,
                 e_type: int = ET_DYN) -> None:
        self.is_64 = is_64
        self.little = little
        self.e_type = e_type
        self.ehdr_size = 64 if is_64 else 52
        self.buf = bytearray(self.ehdr_size)
        self.phdrs: List[Phdr] = []
        self._sections: Optional[bytes] = None

    @property
    def e(self) -> str:
        return "<" if self.little else ">"

    def add_phdr(self, p_type: int, flags: int, offset: int, vaddr: int,
                 filesz: int, memsz: int) -> None:
        self.phdrs.append(Phdr(p_type, flags, offset, vaddr, filesz, memsz))

    def place(self, offset: int, data: bytes) -> None:
        end = offset + len(data)
        if end > len(self.buf):
            self.buf += b"\x00" * (end - len(self.buf))
        self.buf[offset:end] = data

    def alloc(self, data: bytes, align: int = 0x10) -> int:
        off = (len(self.buf) + align - 1) // align * align
        self.place(off, data)
        return off

    def add_dummy_sections(self) -> None:
        """补入节表（内容为无关数据），用于验证结论不受节表影响。"""
        shentsize = 64 if self.is_64 else 40
        shoff = (len(self.buf) + 7) // 8 * 8
        shstr = b"\x00.text\x00.shstrtab\x00"
        self.place(shoff, b"\x00" * shentsize * 3)
        str_off = shoff + shentsize * 3
        self.place(str_off, shstr)
        # 仅填充让结构“看起来像”节表；分析器不得读取
        self._sections = self.buf[shoff:str_off + len(shstr)]
        self._shoff = shoff
        self._shentsize = shentsize
        self._shnum = 3

    def build(self) -> bytes:
        phentsize = 56 if self.is_64 else 32
        phoff = (len(self.buf) + 7) // 8 * 8
        table = bytearray()
        for ph in self.phdrs:
            if self.is_64:
                table += struct.pack(
                    self.e + "IIQQQQQQ", ph.p_type, ph.flags, ph.offset,
                    ph.vaddr, ph.vaddr, ph.filesz, ph.memsz, 0x1000)
            else:
                table += struct.pack(
                    self.e + "IIIIIIII", ph.p_type, ph.offset, ph.vaddr,
                    ph.vaddr, ph.filesz, ph.memsz, ph.flags, 0x1000)
        self.place(phoff, bytes(table))

        ident = b"\x7fELF" + bytes([
            2 if self.is_64 else 1,
            1 if self.little else 2,
            1, 0,
        ]) + bytes(8)
        shoff = getattr(self, "_shoff", 0)
        shentsize = getattr(self, "_shentsize", 0)
        shnum = getattr(self, "_shnum", 0)
        if self.is_64:
            rest = struct.pack(
                self.e + "HHIQQQIHHHHHH", self.e_type, 0x3E, 1, 0,
                phoff, shoff, 0, self.ehdr_size, phentsize,
                len(self.phdrs), shentsize, shnum, 2 if shnum else 0)
        else:
            rest = struct.pack(
                self.e + "HHIIIIIHHHHHH", self.e_type, 3, 1, 0,
                phoff, shoff, 0, self.ehdr_size, phentsize,
                len(self.phdrs), shentsize, shnum, 2 if shnum else 0)
        self.place(0, ident + rest)
        return bytes(self.buf)

    # ---- 结构打包辅助 ----

    def pack_dyn(self, entries: List[Tuple[int, int]]) -> bytes:
        fmt = self.e + ("qQ" if self.is_64 else "iI")
        return b"".join(struct.pack(fmt, t, v) for t, v in entries)

    def pack_sym(self, st_name: int, st_shndx: int, st_value: int = 0,
                 st_size: int = 0, st_info: int = 0) -> bytes:
        if self.is_64:
            return struct.pack(self.e + "IBBHQQ", st_name, st_info, 0,
                               st_shndx, st_value, st_size)
        return struct.pack(self.e + "IIIBBH", st_name, st_value, st_size,
                           st_info, 0, st_shndx)

    def pack_rel(self, r_offset: int, sym_index: int, r_type: int = 0) -> bytes:
        if self.is_64:
            return struct.pack(self.e + "QQ", r_offset,
                               (sym_index << 32) | r_type)
        return struct.pack(self.e + "II", r_offset,
                           (sym_index << 8) | (r_type & 0xFF))

    def pack_rela(self, r_offset: int, sym_index: int, r_type: int = 0,
                  addend: int = 0) -> bytes:
        if self.is_64:
            return struct.pack(self.e + "QQq", r_offset,
                               (sym_index << 32) | r_type, addend)
        return struct.pack(self.e + "IIi", r_offset,
                           (sym_index << 8) | (r_type & 0xFF), addend)


def make_strtab(strings: List[bytes]) -> Tuple[bytes, Dict[bytes, int]]:
    """构造字符串表，返回 (内容, 各字符串偏移)。"""
    blob = bytearray(b"\x00")
    offsets: Dict[bytes, int] = {}
    for s in strings:
        offsets[s] = len(blob)
        blob += s + b"\x00"
    return bytes(blob), offsets
