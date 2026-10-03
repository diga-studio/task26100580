"""基于 mmap 的有界只读访问，保证伪造长度不会导致越界或耗尽内存。"""

from __future__ import annotations

import mmap
import os

from .errors import ELFError


class FileReader:
    """对本地文件提供有界的只读视图。

    使用 mmap 惰性分页：500 MiB 文件不会整体读入内存，
    分析期间新增常驻内存只取决于实际触碰的页。
    """

    def __init__(self, path: str) -> None:
        self._fd = os.open(path, os.O_RDONLY)
        try:
            self._size = os.fstat(self._fd).st_size
            if self._size == 0:
                self._mmap = None
            else:
                self._mmap = mmap.mmap(self._fd, 0, access=mmap.ACCESS_READ)
        except Exception:
            os.close(self._fd)
            raise

    @property
    def size(self) -> int:
        return self._size

    def read(self, offset: int, length: int) -> bytes:
        """读取 [offset, offset+length)；越界抛 ELFError。"""
        if offset < 0 or length < 0:
            raise ELFError(f"负的读取范围: offset={offset} length={length}")
        if offset > self._size or length > self._size - offset:
            raise ELFError(
                f"读取越界: offset={offset} length={length} size={self._size}"
            )
        if self._mmap is None:
            return b""
        return self._mmap[offset:offset + length]

    def close(self) -> None:
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        os.close(self._fd)

    def __enter__(self) -> "FileReader":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
