"""PT_LOAD 映射语义：跨段数据、重叠段、零填充区。"""

from elfbuild import (
    DT_NULL,
    DT_RELA,
    DT_RELAENT,
    DT_RELASZ,
    DT_STRSZ,
    DT_STRTAB,
    DT_SYMENT,
    DT_SYMTAB,
    ET_DYN,
    ELFBuilder,
    PF_R,
    PT_DYNAMIC,
    PT_LOAD,
    SHN_UNDEF,
    make_strtab,
)
from elfsec import StackChkStatus

CHK = b"__stack_chk_fail"


def _cross_segment_sample(analyze):
    """动态表与符号名横跨两个虚拟连续、文件不连续的加载段。"""
    b = ELFBuilder(is_64=True, little=True, e_type=ET_DYN)
    strtab, stroff = make_strtab([CHK])
    # 名称从 0x10F1 开始，跨越 0x1100 段边界：
    # 段边界前的字节在文件 0x10F0，边界后的字节在第二段 backing 0x2000
    b.place(0x10F0, strtab[:0x10])
    b.place(0x2000, strtab[0x10:])
    # 符号表整体位于第二段（vaddr 0x1110 -> 文件 0x2010）
    sym = b.pack_sym(0, 0) + b.pack_sym(stroff[CHK], SHN_UNDEF)
    b.place(0x2010, sym)
    rela = b.pack_rela(0, 1)
    b.place(0x2040, rela)  # vaddr 0x1140 -> 文件 0x2040
    dyn_entries = [
        (DT_STRTAB, 0x10F0), (DT_STRSZ, len(strtab)),
        (DT_SYMTAB, 0x1110), (DT_SYMENT, 24),
        (DT_RELA, 0x1140), (DT_RELASZ, len(rela)), (DT_RELAENT, 24),
        (DT_NULL, 0),
    ]
    dyn = b.pack_dyn(dyn_entries)  # 8*16=128 字节，从 0x10F8 跨边界
    b.place(0x10F8, dyn)
    # 段1: vaddr 0x1000..0x1100 -> 文件 0x1000..0x1100
    b.add_phdr(PT_LOAD, PF_R, 0x1000, 0x1000, 0x100, 0x100)
    # 段2: vaddr 0x1100..0x1200 -> 文件 0x2000..0x2100（文件不连续）
    b.add_phdr(PT_LOAD, PF_R, 0x2000, 0x1100, 0x100, 0x100)
    b.add_phdr(PT_DYNAMIC, PF_R, 0x10F8, 0x10F8, len(dyn), len(dyn))
    return analyze(b.build())


def test_cross_segment_dynamic_and_name(analyze):
    r = _cross_segment_sample(analyze)
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.EVIDENCE
    assert len(r.evidence) == 1
    assert r.evidence[0].symbol_name == "__stack_chk_fail"
    # 重定位在第二段：vaddr 0x1140 -> 文件 0x2040
    assert r.evidence[0].reloc_offset == 0x2040


def test_same_mapping_overlap_ok(analyze):
    """相同映射的重叠段正常通过。"""
    b = ELFBuilder(is_64=True, little=True, e_type=ET_DYN)
    strtab, stroff = make_strtab([CHK])
    b.place(0x1000, strtab)
    sym = b.pack_sym(0, 0) + b.pack_sym(stroff[CHK], SHN_UNDEF)
    b.place(0x1100, sym)
    rela = b.pack_rela(0, 1)
    b.place(0x1140, rela)
    dyn = b.pack_dyn([
        (DT_STRTAB, 0x1000), (DT_STRSZ, len(strtab)),
        (DT_SYMTAB, 0x1100), (DT_SYMENT, 24),
        (DT_RELA, 0x1140), (DT_RELASZ, len(rela)), (DT_RELAENT, 24),
        (DT_NULL, 0),
    ])
    b.place(0x1180, dyn)
    b.add_phdr(PT_LOAD, PF_R, 0x1000, 0x1000, 0x200, 0x200)
    # 完全相同的重叠映射
    b.add_phdr(PT_LOAD, PF_R, 0x1000, 0x1000, 0x200, 0x200)
    b.add_phdr(PT_DYNAMIC, PF_R, 0x1180, 0x1180, len(dyn), len(dyn))
    r = analyze(b.build())
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.EVIDENCE


def test_conflicting_overlap_invalid(analyze):
    """不同映射的重叠段判定有歧义，整份无效。"""
    b = ELFBuilder(is_64=True, little=True, e_type=ET_DYN)
    strtab, stroff = make_strtab([CHK])
    b.place(0x1000, strtab)
    sym = b.pack_sym(0, 0) + b.pack_sym(stroff[CHK], SHN_UNDEF)
    b.place(0x1100, sym)
    rela = b.pack_rela(0, 1)
    b.place(0x1140, rela)
    dyn = b.pack_dyn([
        (DT_STRTAB, 0x1000), (DT_STRSZ, len(strtab)),
        (DT_SYMTAB, 0x1100), (DT_SYMENT, 24),
        (DT_RELA, 0x1140), (DT_RELASZ, len(rela)), (DT_RELAENT, 24),
        (DT_NULL, 0),
    ])
    b.place(0x1180, dyn)
    b.add_phdr(PT_LOAD, PF_R, 0x1000, 0x1000, 0x200, 0x200)
    # 同一 vaddr 区间映射到不同文件偏移
    b.add_phdr(PT_LOAD, PF_R, 0x3000, 0x1000, 0x200, 0x200)
    b.add_phdr(PT_DYNAMIC, PF_R, 0x1180, 0x1180, len(dyn), len(dyn))
    r = analyze(b.build())
    assert not r.valid


def test_zero_fill_reference_invalid(analyze):
    """动态指针指向仅 p_memsz 内的零填充区，整份无效。"""
    b = ELFBuilder(is_64=True, little=True, e_type=ET_DYN)
    strtab, stroff = make_strtab([CHK])
    b.place(0x1000, strtab)
    sym = b.pack_sym(0, 0) + b.pack_sym(stroff[CHK], SHN_UNDEF)
    b.place(0x1100, sym)
    rela = b.pack_rela(0, 1)
    b.place(0x1140, rela)
    dyn = b.pack_dyn([
        (DT_STRTAB, 0x1000), (DT_STRSZ, len(strtab)),
        (DT_SYMTAB, 0x1100), (DT_SYMENT, 24),
        (DT_RELA, 0x1300), (DT_RELASZ, len(rela)), (DT_RELAENT, 24),
        (DT_NULL, 0),
    ])
    b.place(0x1180, dyn)
    # filesz 0x200 < memsz 0x400：DT_RELA 指向的 0x1300 落在零填充区
    b.add_phdr(PT_LOAD, PF_R, 0x1000, 0x1000, 0x200, 0x400)
    b.add_phdr(PT_DYNAMIC, PF_R, 0x1180, 0x1180, len(dyn), len(dyn))
    r = analyze(b.build())
    assert not r.valid
