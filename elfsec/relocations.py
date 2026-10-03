"""重定位表解析（DT_REL / DT_RELA / DT_JMPREL），流式处理避免常驻内存。"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, List, Tuple

from .constants import (
    DT_JMPREL,
    DT_PLTREL,
    DT_PLTRELSZ,
    DT_REL,
    DT_RELA,
    DT_RELAENT,
    DT_RELASZ,
    DT_RELENT,
    DT_RELSZ,
)
from .dynamic import DynamicInfo
from .errors import InvalidReport
from .reader import FileReader
from .segments import SegmentMapper

_CHUNK = 1 << 16


@dataclass(frozen=True)
class RelocRef:
    """一条重定位对动态符号的引用。"""

    reloc_offset: int  # 表项文件偏移
    sym_index: int


def _class_ent(is_64: bool, is_rela: bool) -> int:
    if is_64:
        return 24 if is_rela else 16
    return 12 if is_rela else 8


def _tables(dyn: DynamicInfo, is_64: bool) -> List[Tuple[int, int, bool]]:
    """汇总需检查的重定位表：(vaddr, size, is_rela)。

    配套标签缺失、表项宽度不符、表长非整数倍均抛 InvalidReport。
    """
    out: List[Tuple[int, int, bool]] = []

    def add(ptr_tag: int, sz_tag: int, ent_tag: int, is_rela: bool) -> None:
        ptr = dyn.single(ptr_tag)
        if ptr is None:
            return
        size = dyn.single(sz_tag)
        ent = dyn.single(ent_tag)
        if size is None or ent is None:
            raise InvalidReport(f"重定位表 {ptr_tag:#x} 配套标签缺失")
        want = _class_ent(is_64, is_rela)
        if ent != want:
            raise InvalidReport(
                f"重定位表项宽度 {ent} 与 ELF 类别要求 {want} 不符"
            )
        if size % ent != 0:
            raise InvalidReport(
                f"重定位表长 {size:#x} 不是表项宽度 {ent} 的整数倍"
            )
        if size:
            out.append((ptr, size, is_rela))

    add(DT_REL, DT_RELSZ, DT_RELENT, False)
    add(DT_RELA, DT_RELASZ, DT_RELAENT, True)

    jmp = dyn.single(DT_JMPREL)
    if jmp is not None:
        size = dyn.single(DT_PLTRELSZ)
        kind = dyn.single(DT_PLTREL)
        if size is None or kind is None:
            raise InvalidReport("DT_JMPREL 配套标签缺失")
        if kind == DT_REL:
            is_rela = False
        elif kind == DT_RELA:
            is_rela = True
        else:
            raise InvalidReport(f"DT_PLTREL 取值非法: {kind:#x}")
        ent = _class_ent(is_64, is_rela)
        if size % ent != 0:
            raise InvalidReport(
                f"JMPREL 表长 {size:#x} 不是表项宽度 {ent} 的整数倍"
            )
        if size:
            out.append((jmp, size, is_rela))
    return out


def iter_reloc_refs(reader: FileReader, mapper: SegmentMapper,
                    dyn: DynamicInfo, is_64: bool,
                    little_endian: bool) -> Iterator[RelocRef]:
    """产出所有引用符号的重定位；表损坏抛 InvalidReport。

    调用方必须完整消费迭代器：先发现证据后发现损坏，整份报告仍无效。
    """
    e = "<" if little_endian else ">"
    for tbl_vaddr, tbl_size, is_rela in _tables(dyn, is_64):
        ent = _class_ent(is_64, is_rela)
        chunk = (_CHUNK // ent) * ent  # 保证 chunk 为表项宽度的整数倍
        pos = 0
        while pos < tbl_size:
            step = min(chunk, tbl_size - pos)
            raw = mapper.read_vaddr(reader, tbl_vaddr + pos, step)
            for i in range(0, step, ent):
                if is_64:
                    _r_off, r_info = struct.unpack_from(e + "QQ", raw, i)
                    sym_index = r_info >> 32
                else:
                    _r_off, r_info = struct.unpack_from(e + "II", raw, i)
                    sym_index = r_info >> 8
                if sym_index:
                    yield RelocRef(
                        reloc_offset=mapper.translate(tbl_vaddr + pos + i),
                        sym_index=sym_index,
                    )
            pos += step
