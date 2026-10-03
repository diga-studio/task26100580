"""PT_LOAD 虚拟地址 -> 文件偏移 映射。

- 一项数据可跨越虚拟地址连续、文件位置不连续的多个加载段。
- 重叠覆盖指向同一文件字节则接受，指向不同字节则歧义（InvalidReport）。
- 仅位于 p_memsz 而不在 p_filesz 内的零填充区不算文件数据。
"""

from __future__ import annotations

from typing import List, Tuple

from .errors import InvalidReport
from .headers import ProgramHeader
from .constants import PT_LOAD
from .reader import FileReader


class SegmentMapper:
    def __init__(self, phdrs: List[ProgramHeader], file_size: int,
                 addr_bits: int) -> None:
        self._addr_limit = 1 << addr_bits
        self._segments: List[Tuple[int, int, int]] = []  # (vaddr, offset, filesz)
        for ph in phdrs:
            if ph.p_type != PT_LOAD:
                continue
            if ph.p_filesz > ph.p_memsz:
                raise InvalidReport(
                    f"PT_LOAD p_filesz({ph.p_filesz:#x}) > p_memsz({ph.p_memsz:#x})"
                )
            if ph.p_vaddr >= self._addr_limit or (
                ph.p_filesz > self._addr_limit - ph.p_vaddr
            ):
                raise InvalidReport(
                    f"PT_LOAD 虚拟地址范围溢出: vaddr={ph.p_vaddr:#x} "
                    f"filesz={ph.p_filesz:#x}"
                )
            if ph.p_filesz == 0:
                continue
            if ph.p_offset > file_size or ph.p_filesz > file_size - ph.p_offset:
                raise InvalidReport(
                    f"PT_LOAD 文件范围越界: offset={ph.p_offset:#x} "
                    f"filesz={ph.p_filesz:#x} size={file_size:#x}"
                )
            self._segments.append((ph.p_vaddr, ph.p_offset, ph.p_filesz))
        self._segments.sort()

    def read_vaddr(self, reader: FileReader, vaddr: int, length: int) -> bytes:
        """按虚拟地址读取 length 字节；空洞/歧义/溢出抛 InvalidReport。"""
        if length < 0 or vaddr < 0:
            raise InvalidReport("负的虚拟地址读取范围")
        if vaddr >= self._addr_limit or length > self._addr_limit - vaddr:
            raise InvalidReport(
                f"虚拟地址读取溢出: vaddr={vaddr:#x} length={length:#x}"
            )
        out = bytearray()
        cursor = vaddr
        end = vaddr + length
        while cursor < end:
            file_off = -1
            chunk_end = end
            for seg_vaddr, seg_off, seg_filesz in self._segments:
                seg_end = seg_vaddr + seg_filesz
                if seg_vaddr <= cursor < seg_end:
                    implied = seg_off + (cursor - seg_vaddr)
                    if file_off < 0:
                        file_off = implied
                    elif implied != file_off:
                        raise InvalidReport(
                            f"重叠加载段映射歧义: vaddr={cursor:#x}"
                        )
                    if seg_end < chunk_end:
                        chunk_end = seg_end
                elif cursor < seg_vaddr < chunk_end:
                    # 新区间在 chunk 中间开始，须截断以便下一轮检查重叠
                    chunk_end = seg_vaddr
            if file_off < 0:
                raise InvalidReport(f"虚拟地址映射空洞: vaddr={cursor:#x}")
            out += reader.read(file_off, chunk_end - cursor)
            cursor = chunk_end
        return bytes(out)

    def translate(self, vaddr: int) -> int:
        """将单个虚拟地址翻译为文件偏移；空洞/歧义/溢出抛 InvalidReport。"""
        if vaddr < 0 or vaddr >= self._addr_limit:
            raise InvalidReport(f"虚拟地址越界: vaddr={vaddr:#x}")
        file_off = -1
        for seg_vaddr, seg_off, seg_filesz in self._segments:
            if seg_vaddr <= vaddr < seg_vaddr + seg_filesz:
                implied = seg_off + (vaddr - seg_vaddr)
                if file_off < 0:
                    file_off = implied
                elif implied != file_off:
                    raise InvalidReport(
                        f"重叠加载段映射歧义: vaddr={vaddr:#x}"
                    )
        if file_off < 0:
            raise InvalidReport(f"虚拟地址映射空洞: vaddr={vaddr:#x}")
        return file_off
