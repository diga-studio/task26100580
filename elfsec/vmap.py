"""PT_LOAD 虚拟地址到文件偏移的映射。"""
from __future__ import annotations

from typing import List, Tuple

from .errors import ElfFormatError

_ADDR_LIMIT = 1 << 64


class VMap:
    """按 PT_LOAD 文件覆盖范围解释虚拟地址。

    仅 p_filesz 覆盖的部分算文件数据；p_memsz 多出的零填充区不算。
    重叠段必须对同一虚拟地址给出同一文件偏移，否则判定有歧义。
    """

    def __init__(self) -> None:
        # (vaddr, filesz, offset)
        self._segments: List[Tuple[int, int, int]] = []

    def add_segment(self, vaddr: int, filesz: int, memsz: int, offset: int) -> None:
        if filesz > memsz:
            raise ElfFormatError("加载段 p_filesz 大于 p_memsz")
        if vaddr >= _ADDR_LIMIT or memsz >= _ADDR_LIMIT - vaddr:
            raise ElfFormatError("加载段虚拟地址溢出")
        if offset < 0 or filesz < 0:
            raise ElfFormatError("加载段文件范围非法")
        if filesz > 0:
            self._segments.append((vaddr, filesz, offset))

    def translate(self, vaddr: int, length: int) -> List[Tuple[int, int]]:
        """把 [vaddr, vaddr+length) 翻译为若干 (文件偏移, 长度) 片段。

        遇到映射空洞、零填充区、地址溢出或重叠歧义时抛 ElfFormatError。
        """
        if length < 0 or vaddr < 0:
            raise ElfFormatError("映射请求非法")
        if length == 0:
            return []
        if vaddr >= _ADDR_LIMIT or length > _ADDR_LIMIT - vaddr:
            raise ElfFormatError("映射地址溢出")
        end = vaddr + length

        # 收集切分点：请求区间端点 + 各段在区间内的端点。
        points = {vaddr, end}
        for seg_vaddr, seg_filesz, _ in self._segments:
            seg_end = seg_vaddr + seg_filesz
            if seg_end <= vaddr or seg_vaddr >= end:
                continue
            points.add(max(seg_vaddr, vaddr))
            points.add(min(seg_end, end))
        ordered = sorted(points)

        pieces: List[Tuple[int, int]] = []
        for start, stop in zip(ordered, ordered[1:]):
            if start >= stop:
                continue
            mapped = None
            for seg_vaddr, seg_filesz, seg_offset in self._segments:
                seg_end = seg_vaddr + seg_filesz
                if start < seg_vaddr or stop > seg_end:
                    continue
                file_off = seg_offset + (start - seg_vaddr)
                if mapped is None:
                    mapped = file_off
                elif mapped != file_off:
                    raise ElfFormatError(
                        f"重叠加载段映射歧义: vaddr={start:#x}"
                    )
            if mapped is None:
                raise ElfFormatError(f"虚拟地址无文件映射: vaddr={start:#x}")
            if pieces and pieces[-1][0] + pieces[-1][1] == mapped:
                prev_off, prev_len = pieces[-1]
                pieces[-1] = (prev_off, prev_len + stop - start)
            else:
                pieces.append((mapped, stop - start))
        return pieces
