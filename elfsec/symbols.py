"""动态符号与字符串解析：仅解析被重定位引用的符号。"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .constants import DT_STRSZ, DT_STRTAB, DT_SYMENT, DT_SYMTAB
from .dynamic import DynamicInfo
from .errors import InvalidReport
from .reader import FileReader
from .segments import SegmentMapper

_CHUNK = 1 << 12
# 目标名最长 "__stack_chk_fail_local"(22)，超过此长度的名字不可能匹配
_MAX_NAME = 64


@dataclass(frozen=True)
class Symbol:
    st_name: int
    st_shndx: int


def _syment(is_64: bool) -> int:
    return 24 if is_64 else 16


def read_symbol(reader: FileReader, mapper: SegmentMapper, dyn: DynamicInfo,
                is_64: bool, little_endian: bool, index: int) -> Symbol:
    symtab = dyn.single(DT_SYMTAB)
    syment = dyn.single(DT_SYMENT)
    if symtab is None or syment is None:
        raise InvalidReport("重定位引用符号但缺少 DT_SYMTAB/DT_SYMENT")
    if syment != _syment(is_64):
        raise InvalidReport(
            f"DT_SYMENT={syment} 与 ELF 类别要求 {_syment(is_64)} 不符"
        )
    addr = symtab + index * syment
    raw = mapper.read_vaddr(reader, addr, syment)
    e = "<" if little_endian else ">"
    if is_64:
        st_name, _info, _other, st_shndx = struct.unpack_from(e + "IBBH", raw, 0)
    else:
        st_name, _value, _size, _info, _other, st_shndx = struct.unpack_from(
            e + "IIIBBH", raw, 0)
    return Symbol(st_name=st_name, st_shndx=st_shndx)


def read_symbol_name(reader: FileReader, mapper: SegmentMapper,
                     dyn: DynamicInfo, st_name: int) -> Optional[bytes]:
    """名称须在 DT_STRSZ 范围内以零字节终止，否则报告无效。

    分块扫描控制内存；超过 _MAX_NAME 的名字不可能是目标名，
    返回 None 表示"合法但不匹配"。
    """
    strtab = dyn.single(DT_STRTAB)
    strsz = dyn.single(DT_STRSZ)
    if strtab is None or strsz is None:
        raise InvalidReport("重定位引用符号但缺少 DT_STRTAB/DT_STRSZ")
    if st_name >= strsz:
        raise InvalidReport(
            f"符号名偏移 {st_name:#x} 超出 DT_STRSZ {strsz:#x}"
        )
    remaining = strsz - st_name
    addr = strtab + st_name
    name = bytearray()
    too_long = False
    while remaining > 0:
        step = min(_CHUNK, remaining)
        raw = mapper.read_vaddr(reader, addr, step)
        end = raw.find(b"\x00")
        if end >= 0:
            if too_long or len(name) + end > _MAX_NAME:
                return None
            name += raw[:end]
            return bytes(name)
        if not too_long:
            name += raw
            if len(name) > _MAX_NAME:
                too_long = True
                name = bytearray()
        remaining -= step
        addr += step
    raise InvalidReport("符号名在 DT_STRSZ 范围内未以零字节终止")
