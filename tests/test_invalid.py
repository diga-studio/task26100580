"""无效样本：任何损坏都让整份报告无效，不返回部分结论。"""
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

import pytest  # noqa: E402

from elfbuild import (  # noqa: E402
    DT_FLAGS_1,
    DT_NULL,
    DT_RELA,
    DT_RELAENT,
    DT_RELASZ,
    DT_STRSZ,
    DT_STRTAB,
    DT_SYMENT,
    DT_SYMTAB,
    ET_EXEC,
    PT_DYNAMIC,
    PT_GNU_STACK,
    PF_R,
    PF_W,
    ElfBuilder,
)
from elfsec import EvidenceState, analyze  # noqa: E402

CHK = b"__stack_chk_fail"


def make_simple(is_64=True, little=True):
    """单段简单样本：返回 (builder, 地址字典)，便于各用例改造。"""
    b = ElfBuilder(is_64=is_64, little=little)
    b.add_load(0x200, 0x1000, 0x400, 0x400)
    b.add_phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0)
    syment = 24 if is_64 else 16
    relaent = 24 if is_64 else 12
    addrs = {
        "dyn": 0x1000,
        "strtab": 0x1100,
        "symtab": 0x1180,
        "rela": 0x11C0,
        "syment": syment,
        "relaent": relaent,
    }
    dyn = b.pack_dyn(
        [
            (DT_STRTAB, addrs["strtab"]),
            (DT_STRSZ, 0x40),
            (DT_SYMTAB, addrs["symtab"]),
            (DT_SYMENT, syment),
            (DT_RELA, addrs["rela"]),
            (DT_RELASZ, relaent),
            (DT_RELAENT, relaent),
            (DT_NULL, 0),
        ]
    )
    b.add_phdr(PT_DYNAMIC, 6, 0x200, addrs["dyn"], len(dyn), len(dyn))
    b.set_data(0x200, dyn)
    b.set_data(0x200 + (addrs["strtab"] - 0x1000), b"\x00" + CHK + b"\x00")
    b.set_data(
        0x200 + (addrs["symtab"] - 0x1000),
        b.pack_sym(0, 0) + b.pack_sym(1, 0),
    )
    b.set_data(
        0x200 + (addrs["rela"] - 0x1000),
        b.pack_rela(0x2000, b.r_info(1)),
    )
    return b, addrs


def test_valid_baseline(write_sample):
    b, _ = make_simple()
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.FOUND


def test_overlap_same_mapping_ok(write_sample):
    """相同映射的重叠段：正常通过。"""
    b, addrs = make_simple()
    # 与主段尾部完全相同的映射。
    b.add_load(0x400, 0x1200, 0x100, 0x100)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.FOUND


def test_overlap_different_mapping_invalid(write_sample):
    """不同映射的重叠段覆盖判定所需数据：无效。"""
    b, addrs = make_simple()
    # rela 表在 0x11C0..0x11D8；加一个映射不同的重叠段覆盖它。
    b.add_load(0x800, 0x11C0, 0x20, 0x20)
    b.set_data(0x800, b"\x00" * 0x20)
    report = analyze(write_sample(b))
    assert not report.valid
    assert report.nx is None and report.pie is None and report.stack_chk is None


def test_zerofill_reference_invalid(write_sample):
    """动态指针指向仅 p_memsz 覆盖的零填充区：无效。"""
    b = ElfBuilder(is_64=True, little=True)
    b.add_load(0x200, 0x1000, 0x100, 0x400)  # 0x1100 起只有零填充
    dyn = b.pack_dyn(
        [
            (DT_STRTAB, 0x1200),  # 指向零填充区
            (DT_STRSZ, 0x40),
            (DT_SYMTAB, 0x1080),
            (DT_SYMENT, 24),
            (DT_RELA, 0x1090),
            (DT_RELASZ, 24),
            (DT_RELAENT, 24),
            (DT_NULL, 0),
        ]
    )
    b.add_phdr(PT_DYNAMIC, 6, 0x200, 0x1000, len(dyn), len(dyn))
    b.set_data(0x200, dyn)
    b.set_data(0x280, b.pack_sym(0, 0) + b.pack_sym(1, 0))
    b.set_data(0x290, b.pack_rela(0x2000, b.r_info(1)))
    report = analyze(write_sample(b))
    assert not report.valid


def test_dynamic_not_terminated_invalid(write_sample):
    """声明范围内没有 DT_NULL：无效。"""
    b = ElfBuilder(is_64=True, little=True)
    b.add_load(0x200, 0x1000, 0x100, 0x100)
    dyn = b.pack_dyn([(DT_STRTAB, 0x1010), (DT_STRSZ, 0x10)])
    b.add_phdr(PT_DYNAMIC, 6, 0x200, 0x1000, len(dyn), len(dyn))
    b.set_data(0x200, dyn)
    report = analyze(write_sample(b))
    assert not report.valid


def test_reloc_size_not_multiple_invalid(write_sample):
    """表长不是表项宽度整数倍：无效。"""
    b, addrs = make_simple()
    dyn = b.pack_dyn(
        [
            (DT_STRTAB, addrs["strtab"]),
            (DT_STRSZ, 0x40),
            (DT_SYMTAB, addrs["symtab"]),
            (DT_SYMENT, addrs["syment"]),
            (DT_RELA, addrs["rela"]),
            (DT_RELASZ, addrs["relaent"] + 1),
            (DT_RELAENT, addrs["relaent"]),
            (DT_NULL, 0),
        ]
    )
    b.set_data(0x200, dyn)
    report = analyze(write_sample(b))
    assert not report.valid


def test_huge_reloc_size_invalid_bounded(write_sample):
    """伪造的巨大表长：有界结束且整体无效。"""
    b, addrs = make_simple()
    dyn = b.pack_dyn(
        [
            (DT_STRTAB, addrs["strtab"]),
            (DT_STRSZ, 0x40),
            (DT_SYMTAB, addrs["symtab"]),
            (DT_SYMENT, addrs["syment"]),
            (DT_RELA, addrs["rela"]),
            (DT_RELASZ, 0xFFFFFFFFFFFFFFF8),
            (DT_RELAENT, addrs["relaent"]),
            (DT_NULL, 0),
        ]
    )
    b.set_data(0x200, dyn)
    report = analyze(write_sample(b))
    assert not report.valid


def test_huge_symbol_index_invalid_bounded(write_sample):
    """伪造的巨大符号下标：地址溢出，整体无效。"""
    b, addrs = make_simple()
    b.set_data(
        0x200 + (addrs["rela"] - 0x1000),
        b.pack_rela(0x2000, b.r_info(0xFFFFFFFF)),
    )
    report = analyze(write_sample(b))
    assert not report.valid


def test_huge_strsz_bounded(write_sample):
    """伪造的巨大 DT_STRSZ：名称读取有界，不耗尽内存。"""
    b, addrs = make_simple()
    dyn = b.pack_dyn(
        [
            (DT_STRTAB, addrs["strtab"]),
            (DT_STRSZ, 0xFFFFFFFFFFFFFFFF),
            (DT_SYMTAB, addrs["symtab"]),
            (DT_SYMENT, addrs["syment"]),
            (DT_RELA, addrs["rela"]),
            (DT_RELASZ, addrs["relaent"]),
            (DT_RELAENT, addrs["relaent"]),
            (DT_NULL, 0),
        ]
    )
    b.set_data(0x200, dyn)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.FOUND


def test_evidence_then_corrupt_invalid(write_sample):
    """先命中有效证据、后遇损坏引用：整份报告无效。"""
    b, addrs = make_simple()
    relaent = addrs["relaent"]
    dyn = b.pack_dyn(
        [
            (DT_STRTAB, addrs["strtab"]),
            (DT_STRSZ, 0x40),
            (DT_SYMTAB, addrs["symtab"]),
            (DT_SYMENT, addrs["syment"]),
            (DT_RELA, addrs["rela"]),
            (DT_RELASZ, relaent * 2),
            (DT_RELAENT, relaent),
            (DT_NULL, 0),
        ]
    )
    b.set_data(0x200, dyn)
    good = b.pack_rela(0x2000, b.r_info(1))
    bad = b.pack_rela(0x2000, b.r_info(0x100000))  # 符号落在映射空洞
    b.set_data(0x200 + (addrs["rela"] - 0x1000), good + bad)
    report = analyze(write_sample(b))
    assert not report.valid
    assert report.stack_chk is None
    assert report.stack_chk_evidence == []


def test_duplicate_gnu_stack_invalid(write_sample):
    b, _ = make_simple()
    b.add_phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0)
    report = analyze(write_sample(b))
    assert not report.valid


def test_duplicate_dynamic_invalid(write_sample):
    b, addrs = make_simple()
    b.add_phdr(PT_DYNAMIC, 6, 0x200, addrs["dyn"], 0x10, 0x10)
    report = analyze(write_sample(b))
    assert not report.valid


def test_filesz_gt_memsz_invalid(write_sample):
    b, _ = make_simple()
    b.add_load(0x600, 0x2000, 0x200, 0x100)
    report = analyze(write_sample(b))
    assert not report.valid


def test_conflicting_dynamic_tags_invalid(write_sample):
    b, addrs = make_simple()
    dyn = b.pack_dyn(
        [
            (DT_STRTAB, addrs["strtab"]),
            (DT_STRSZ, 0x40),
            (DT_STRSZ, 0x50),
            (DT_NULL, 0),
        ]
    )
    b.set_data(0x200, dyn)
    report = analyze(write_sample(b))
    assert not report.valid


def test_load_beyond_eof_invalid(write_sample):
    """加载段声明的文件范围超出实际文件大小：无效。"""
    b, _ = make_simple()
    path = write_sample(b)
    with open(path, "r+b") as fp:
        fp.truncate(0x300)  # 主段声明到 0x600
    report = analyze(path)
    assert not report.valid


def test_missing_companion_tag_invalid(write_sample):
    """有 DT_RELA 但缺 DT_RELAENT：无效。"""
    b, addrs = make_simple()
    dyn = b.pack_dyn(
        [
            (DT_STRTAB, addrs["strtab"]),
            (DT_STRSZ, 0x40),
            (DT_SYMTAB, addrs["symtab"]),
            (DT_SYMENT, addrs["syment"]),
            (DT_RELA, addrs["rela"]),
            (DT_RELASZ, addrs["relaent"]),
            (DT_NULL, 0),
        ]
    )
    b.set_data(0x200, dyn)
    report = analyze(write_sample(b))
    assert not report.valid


def test_wrong_entry_size_invalid(write_sample):
    """表项宽度与 ELF 类别不符：无效。"""
    b, addrs = make_simple()
    dyn = b.pack_dyn(
        [
            (DT_STRTAB, addrs["strtab"]),
            (DT_STRSZ, 0x40),
            (DT_SYMTAB, addrs["symtab"]),
            (DT_SYMENT, addrs["syment"]),
            (DT_RELA, addrs["rela"]),
            (DT_RELASZ, addrs["relaent"]),
            (DT_RELAENT, 16),
            (DT_NULL, 0),
        ]
    )
    b.set_data(0x200, dyn)
    report = analyze(write_sample(b))
    assert not report.valid


def test_not_elf_invalid(write_sample):
    b = ElfBuilder(is_64=True, little=True)
    b.set_data(0, b"NOTELF")
    b.phdrs.clear()
    path = write_sample(b)
    with open(path, "rb") as fp:
        data = fp.read()
    with open(path, "wb") as fp:
        fp.write(data[:16])
    report = analyze(path)
    assert not report.valid


def test_unsupported_type_invalid(write_sample):
    b, _ = make_simple()
    b.e_type = 1  # ET_REL
    report = analyze(write_sample(b))
    assert not report.valid
