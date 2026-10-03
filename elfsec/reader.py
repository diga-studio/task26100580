"""有界文件读取器：所有读取都带边界检查，绝不按伪造长度分配内存。"""
from __future__ import annotations

import io
from typing import Iterator, Tuple

from .errors import ElfFormatError

# 单次读取块上限，保证新增内存有界。
_CHUNK_SIZE = 1 << 20


class Reader:
    """对本地文件做带边界检查的定点读取。"""

    def __init__(self, fp: io.BufferedIOBase, size: int) -> None:
        self._fp = fp
        self.size = size

    def _check_range(self, offset: int, length: int) -> None:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ElfFormatError(
                f"文件范围越界: offset={offset} length={length} size={self.size}"
            )

    def read_at(self, offset: int, length: int) -> bytes:
        """读取完整区间；越界即抛错。调用方须保证 length 已有界。"""
        if length > _CHUNK_SIZE:
            raise ElfFormatError(f"单次读取过大: {length}")
        self._check_range(offset, length)
        self._fp.seek(offset)
        data = self._fp.read(length)
        if len(data) != length:
            raise ElfFormatError("文件读取不足")
        return data

    def iter_chunks(
        self, offset: int, length: int, chunk_size: int = _CHUNK_SIZE
    ) -> Iterator[Tuple[int, bytes]]:
        """按块产出 (块文件偏移, 块数据)，用于扫描可能很长的表。"""
        self._check_range(offset, length)
        pos = offset
        remaining = length
        while remaining > 0:
            n = min(chunk_size, remaining)
            yield pos, self.read_at(pos, n)
            pos += n
            remaining -= n
