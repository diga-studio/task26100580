"""重定位与符号扫描：仅从 DT_REL / DT_RELA / DT_JMPREL 声明的重定位中提取栈保护证据。"""
from __future__ import annotations

import struct
from typing import Dict, List, Optional, Tuple

from .dynamic import (
    DT_JMPREL,
    DT_PLTREL,
    DT_PLTRELSZ,
    DT_REL,
    DT_RELA,
    DT_RELAENT,
    DT_RELASZ,
    DT_RELENT,
    DT_RELSZ,
    DT_STRSZ,
    DT_STRTAB,
    DT_SYMENT,
    DT_SYMTAB,
)
from .elf import ElfInfo
from .errors import ElfFormatError
from .reader import Reader
from .types import StackChkEvidence
from .vmap import VMap

SHN_UNDEF = 0
_ADDR_LIMIT = 1 << 64
_TARGET_NAMES = (b"__stack_chk_fail", b"__stack_chk_fail_local")
# 目标名最长 21 字节，扫描符号名时只需有界地读前若干字节。
_NAME_SCAN_MAX = 64


def _checked_addr(base: int, offset: int) -> int:
    value = base + offset
    if value < 0 or value >= _ADDR_LIMIT:
        raise ElfFormatError("地址溢出")
    return value


def _need(dyn: Dict[int, int], tag: int) -> int:
    if tag not in dyn:
        raise ElfFormatError(f"缺少配套动态标签: tag={tag:#x}")
    return dyn[tag]


def _read_vaddr(
    reader: Reader, vmap: VMap, vaddr: int, length: int
) -> Tuple[bytes, Optional[int]]:
    """读取虚拟地址区间；返回 (数据, 单一文件偏移或 None)。"""
    pieces = vmap.translate(vaddr, length)
    data = b"".join(reader.read_at(off, size) for off, size in pieces)
    file_off = pieces[0][0] if len(pieces) == 1 else None
    return data, file_off


class _SymbolReader:
    """按需读取动态符号与符号名，状态只在内存中。"""

    def __init__(self, reader: Reader, info: ElfInfo, vmap: VMap, dyn: Dict[int, int]):
        self._reader = reader
        self._info = info
        self._vmap = vmap
        self._dyn = dyn
        self._checked_layout = False

    def _check_layout(self) -> None:
        expected = 24 if self._info.is_64 else 16
        if _need(self._dyn, DT_SYMENT) != expected:
            raise ElfFormatError("DT_SYMENT 与 ELF 类别不符")
        _need(self._dyn, DT_SYMTAB)
        self._checked_layout = True

    def read_symbol(self, index: int) -> Tuple[int, int]:
        """返回 (st_name, st_shndx)。"""
        if not self._checked_layout:
            self._check_layout()
        symtab = self._dyn[DT_SYMTAB]
        syment = self._dyn[DT_SYMENT]
        addr = _checked_addr(symtab, index * syment)
        data, _ = _read_vaddr(self._reader, self._vmap, addr, syment)
        en = "<" if self._info.little_endian else ">"
        st_name = struct.unpack_from(en + "I", data, 0)[0]
        shndx_off = 6 if self._info.is_64 else 14
        st_shndx = struct.unpack_from(en + "H", data, shndx_off)[0]
        return st_name, st_shndx

    def read_name(self, st_name: int) -> Optional[bytes]:
        """读取符号名；名字过长不可能是目标时返回 None。"""
        strtab = _need(self._dyn, DT_STRTAB)
        strsz = _need(self._dyn, DT_STRSZ)
        if st_name >= strsz:
            raise ElfFormatError("符号名偏移超出 DT_STRSZ")
        avail = strsz - st_name
        addr = _checked_addr(strtab, st_name)
        data, _ = _read_vaddr(self._reader, self._vmap, addr, min(avail, _NAME_SCAN_MAX))
        nul = data.find(b"\x00")
        if nul < 0:
            if avail <= _NAME_SCAN_MAX:
                raise ElfFormatError("符号名未在 DT_STRSZ 内以零字节终止")
            return None
        return data[:nul]


def _collect_tables(dyn: Dict[int, int], info: ElfInfo) -> List[Tuple[int, int, int]]:
    """收集 (表虚拟地址, 表字节长, 表项宽度) 并校验配套标签。"""
    rel_ent = 16 if info.is_64 else 8
    rela_ent = 24 if info.is_64 else 12
    tables: List[Tuple[int, int, int]] = []

    def add(addr_tag: int, size_tag: int, ent: int) -> None:
        if addr_tag not in dyn:
            return
        size = _need(dyn, size_tag)
        if ent <= 0 or size % ent != 0:
            raise ElfFormatError("重定位表长不是表项宽度的整数倍")
        tables.append((dyn[addr_tag], size, ent))

    if DT_REL in dyn:
        add(DT_REL, DT_RELSZ, _need(dyn, DT_RELENT))
        if dyn[DT_RELENT] != rel_ent:
            raise ElfFormatError("DT_RELENT 与 ELF 类别不符")
    if DT_RELA in dyn:
        add(DT_RELA, DT_RELASZ, _need(dyn, DT_RELAENT))
        if dyn[DT_RELAENT] != rela_ent:
            raise ElfFormatError("DT_RELAENT 与 ELF 类别不符")
    if DT_JMPREL in dyn:
        kind = _need(dyn, DT_PLTREL)
        if kind == DT_REL:
            ent = rel_ent
        elif kind == DT_RELA:
            ent = rela_ent
        else:
            raise ElfFormatError("DT_PLTREL 取值非法")
        add(DT_JMPREL, DT_PLTRELSZ, ent)
    return tables


def scan_stack_chk(
    reader: Reader, info: ElfInfo, vmap: VMap, dyn: Dict[int, int]
) -> List[StackChkEvidence]:
    """扫描全部声明的重定位表，返回栈保护证据列表。"""
    tables = _collect_tables(dyn, info)
    if not tables:
        return []
    en = "<" if info.little_endian else ">"
    symbols = _SymbolReader(reader, info, vmap, dyn)
    evidence: List[StackChkEvidence] = []

    for table_addr, table_size, ent in tables:
        count = table_size // ent
        for i in range(count):
            entry_addr = _checked_addr(table_addr, i * ent)
            data, file_off = _read_vaddr(reader, vmap, entry_addr, ent)
            if info.is_64:
                r_info = struct.unpack_from(en + "Q", data, 8)[0]
                sym_index = r_info >> 32
            else:
                r_info = struct.unpack_from(en + "I", data, 4)[0]
                sym_index = r_info >> 8
            if sym_index == 0:
                continue
            st_name, st_shndx = symbols.read_symbol(sym_index)
            if st_shndx != SHN_UNDEF:
                continue
            name = symbols.read_name(st_name)
            if name is None or name not in _TARGET_NAMES:
                continue
            if file_off is None:
                raise ElfFormatError("命中重定位无单一文件偏移")
            evidence.append(
                StackChkEvidence(reloc_offset=file_off, symbol_name=name.decode("ascii"))
            )
    return evidence
