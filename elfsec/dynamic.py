"""动态表解析：须在声明范围内以 DT_NULL 终止。

为满足内存上限，不为全部表项建列表：仅留存分析所需的单值标签，
重复出现且取值冲突时判定整份报告无效。
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .constants import DT_NULL, PT_DYNAMIC, SINGLE_VALUE_TAGS
from .errors import InvalidReport
from .headers import ProgramHeader
from .reader import FileReader

_CHUNK = 1 << 16  # 单次读取上限，控制峰值内存


@dataclass(frozen=True)
class DynamicInfo:
    """动态表解析结果：仅含分析所需的单值标签。"""

    values: Dict[int, int]

    def single(self, tag: int) -> Optional[int]:
        return self.values.get(tag)


def parse_dynamic(reader: FileReader, phdrs: List[ProgramHeader],
                  is_64: bool, little_endian: bool) -> Optional[DynamicInfo]:
    """无 PT_DYNAMIC 返回 None；重复或损坏抛 InvalidReport。"""
    dyn_phdrs = [ph for ph in phdrs if ph.p_type == PT_DYNAMIC]
    if not dyn_phdrs:
        return None
    if len(dyn_phdrs) > 1:
        raise InvalidReport("重复的 PT_DYNAMIC")
    ph = dyn_phdrs[0]
    ent_size = 16 if is_64 else 8
    if ph.p_filesz % ent_size != 0:
        raise InvalidReport(
            f"PT_DYNAMIC 大小 {ph.p_filesz:#x} 不是表项宽度 {ent_size} 的整数倍"
        )
    if ph.p_offset > reader.size or ph.p_filesz > reader.size - ph.p_offset:
        raise InvalidReport("PT_DYNAMIC 文件范围越界")

    e = "<" if little_endian else ">"
    fmt = e + ("qQ" if is_64 else "iI")
    wanted = set(SINGLE_VALUE_TAGS)
    values: Dict[int, int] = {}
    terminated = False
    offset = ph.p_offset
    remaining = ph.p_filesz
    while remaining > 0:
        step = min(_CHUNK, remaining)
        raw = reader.read(offset, step)
        for i in range(0, step, ent_size):
            tag, val = struct.unpack_from(fmt, raw, i)
            if tag == DT_NULL:
                terminated = True
                break
            if tag in wanted:
                if tag in values and values[tag] != val:
                    raise InvalidReport(
                        f"动态标签 {tag:#x} 取值冲突: "
                        f"{values[tag]:#x} vs {val:#x}"
                    )
                values[tag] = val
        if terminated:
            break
        offset += step
        remaining -= step
    if not terminated:
        raise InvalidReport("动态表在声明范围内未以 DT_NULL 终止")
    return DynamicInfo(values=values)
