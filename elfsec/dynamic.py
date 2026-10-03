"""动态表解析：按 PT_LOAD 映射解释 PT_DYNAMIC 虚拟地址，须在声明范围内以 DT_NULL 终止。"""
from __future__ import annotations

import struct
from typing import Dict

from .elf import PT_DYNAMIC, ElfInfo
from .errors import ElfFormatError
from .reader import Reader
from .vmap import VMap

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

# 判定所需的单值标签；同一标签取值冲突即整份报告无效。
_SINGLE_VALUE_TAGS = frozenset(
    {
        DT_PLTRELSZ,
        DT_STRTAB,
        DT_SYMTAB,
        DT_RELA,
        DT_RELASZ,
        DT_RELAENT,
        DT_STRSZ,
        DT_SYMENT,
        DT_REL,
        DT_RELSZ,
        DT_RELENT,
        DT_PLTREL,
        DT_JMPREL,
        DT_FLAGS_1,
    }
)


def parse_dynamic(reader: Reader, info: ElfInfo, vmap: VMap) -> Dict[int, int]:
    """解析动态表，返回 标签 -> 值。无 PT_DYNAMIC 时返回空表。"""
    segments = [p for p in info.phdrs if p.p_type == PT_DYNAMIC]
    if len(segments) > 1:
        raise ElfFormatError("重复的 PT_DYNAMIC")
    if not segments:
        return {}
    seg = segments[0]
    ent = 16 if info.is_64 else 8
    en = "<" if info.little_endian else ">"
    fmt = en + ("QQ" if info.is_64 else "II")

    result: Dict[int, int] = {}
    terminated = False
    buf = b""

    def feed(data: bytes) -> None:
        nonlocal buf, terminated
        buf += data
        while len(buf) >= ent and not terminated:
            entry, buf = buf[:ent], buf[ent:]
            tag, val = struct.unpack(fmt, entry)
            if tag == DT_NULL:
                terminated = True
            elif tag in _SINGLE_VALUE_TAGS:
                old = result.get(tag)
                if old is not None and old != val:
                    raise ElfFormatError(f"动态标签取值冲突: tag={tag:#x}")
                result[tag] = val

    # 动态表可跨越虚拟地址连续、文件位置不连续的多个加载段。
    for file_off, size in vmap.translate(seg.vaddr, seg.filesz):
        if terminated:
            break
        for _chunk_off, chunk in reader.iter_chunks(file_off, size):
            feed(chunk)
            if terminated:
                break
    if not terminated:
        raise ElfFormatError("动态表未在声明范围内以 DT_NULL 终止")
    return result
