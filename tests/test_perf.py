"""规模与资源：10 万条重定位、500 MiB 稀疏文件，内存有界。"""
import os
import sys
import tracemalloc

sys.path.insert(0, os.path.dirname(__file__))

import pytest  # noqa: E402

from elfbuild import (  # noqa: E402
    DT_NULL,
    DT_RELA,
    DT_RELAENT,
    DT_RELASZ,
    DT_STRSZ,
    DT_STRTAB,
    DT_SYMENT,
    DT_SYMTAB,
    PT_DYNAMIC,
    PT_GNU_STACK,
    PF_R,
    PF_W,
    ElfBuilder,
)
from elfsec import EvidenceState, analyze  # noqa: E402

RELOC_COUNT = 100_000
MEM_LIMIT = 32 * 1024 * 1024


def make_big_sample(count=RELOC_COUNT):
    """count 条重定位，最后一条命中目标符号。"""
    b = ElfBuilder(is_64=True, little=True)
    relaent = 24
    table_size = count * relaent
    b.add_load(0x200, 0x1000, 0x200, 0x200)          # 动态表、符号、字符串
    b.add_load(0x1000, 0x2000, table_size, table_size)  # 重定位表
    b.add_phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0)
    dyn = b.pack_dyn(
        [
            (DT_STRTAB, 0x1100),
            (DT_STRSZ, 0x40),
            (DT_SYMTAB, 0x1180),
            (DT_SYMENT, 24),
            (DT_RELA, 0x2000),
            (DT_RELASZ, table_size),
            (DT_RELAENT, relaent),
            (DT_NULL, 0),
        ]
    )
    b.add_phdr(PT_DYNAMIC, 6, 0x200, 0x1000, len(dyn), len(dyn))
    b.set_data(0x200, dyn)
    b.set_data(0x300, b"\x00__stack_chk_fail\x00")
    b.set_data(0x380, b.pack_sym(0, 0) + b.pack_sym(1, 0))
    # 前 count-1 条不引用符号，最后一条引用符号 1。
    rela = bytearray()
    rela += b.pack_rela(0x4000, b.r_info(0)) * (count - 1)
    rela += b.pack_rela(0x4000, b.r_info(1))
    b.set_data(0x1000, bytes(rela))
    return b, 0x1000 + (count - 1) * relaent


@pytest.mark.slow
def test_many_relocations_bounded_memory(write_sample):
    b, hit_offset = make_big_sample()
    path = write_sample(b)
    tracemalloc.start()
    try:
        report = analyze(path)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.FOUND
    assert report.stack_chk_evidence[0].reloc_offset == hit_offset
    assert peak < MEM_LIMIT, f"峰值内存 {peak} 超过 32 MiB"


@pytest.mark.slow
def test_sparse_500mib_file(write_sample):
    """500 MiB 稀疏文件：只按声明范围读取，有界结束。"""
    b, hit_offset = make_big_sample(count=1000)
    path = write_sample(b)
    with open(path, "r+b") as fp:
        fp.truncate(500 * 1024 * 1024)
    tracemalloc.start()
    try:
        report = analyze(path)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.FOUND
    assert peak < MEM_LIMIT, f"峰值内存 {peak} 超过 32 MiB"
