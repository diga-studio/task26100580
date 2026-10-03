"""栈保护证据判定：仅 DT_REL/DT_RELA/DT_JMPREL 引用的未定义目标符号算证据。"""

from elfbuild import (
    DT_JMPREL,
    DT_NULL,
    DT_PLTREL,
    DT_PLTRELSZ,
    DT_REL,
    DT_RELA,
    DT_RELAENT,
    DT_RELASZ,
    DT_RELENT,
    DT_RELSZ,
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
from elfsec import PIEStatus, StackChkStatus

CHK = b"__stack_chk_fail"
CHK_LOCAL = b"__stack_chk_fail_local"
BASE = 0x1000


def build_sample(analyze, *, symbols, relas=(), rels=(), jmprels=(),
                 jmprel_kind=DT_RELA, extra_strings=(), is_64=True,
                 little=True, with_reloc_tags=True):
    """构造含动态字符串表/符号表/重定位表的样本。

    symbols: [(name_bytes, shndx)]，索引 0 自动为全零符号。
    relas/rels/jmprels: 引用的符号索引列表。
    """
    b = ELFBuilder(is_64=is_64, little=little, e_type=ET_DYN)
    names = [n for n, _ in symbols]
    strtab, stroff = make_strtab(list(names) + list(extra_strings))

    strtab_va = BASE
    symtab_va = strtab_va + 0x100
    rela_va = strtab_va + 0x200
    rel_va = strtab_va + 0x300
    jmp_va = strtab_va + 0x400
    dyn_va = strtab_va + 0x500

    b.place(strtab_va, strtab)
    sym_blob = b.pack_sym(0, 0)  # STN_UNDEF
    for name, shndx in symbols:
        sym_blob += b.pack_sym(stroff[name], shndx)
    b.place(symtab_va, sym_blob)

    dyn = [(DT_STRTAB, strtab_va), (DT_STRSZ, len(strtab)),
           (DT_SYMTAB, symtab_va), (DT_SYMENT, 24 if is_64 else 16)]
    if with_reloc_tags:
        if relas:
            blob = b"".join(b.pack_rela(0, i) for i in relas)
            b.place(rela_va, blob)
            dyn += [(DT_RELA, rela_va), (DT_RELASZ, len(blob)),
                    (DT_RELAENT, 24 if is_64 else 12)]
        if rels:
            blob = b"".join(b.pack_rel(0, i) for i in rels)
            b.place(rel_va, blob)
            dyn += [(DT_REL, rel_va), (DT_RELSZ, len(blob)),
                    (DT_RELENT, 16 if is_64 else 8)]
        if jmprels:
            fmt = b.pack_rela if jmprel_kind == DT_RELA else b.pack_rel
            blob = b"".join(fmt(0, i) for i in jmprels)
            b.place(jmp_va, blob)
            dyn += [(DT_JMPREL, jmp_va), (DT_PLTRELSZ, len(blob)),
                    (DT_PLTREL, jmprel_kind)]
    dyn.append((DT_NULL, 0))
    dyn_blob = b.pack_dyn(dyn)
    b.place(dyn_va, dyn_blob)

    end = dyn_va + len(dyn_blob)
    b.add_phdr(PT_LOAD, PF_R, BASE, BASE, end - BASE, end - BASE)
    b.add_phdr(PT_DYNAMIC, PF_R, dyn_va, dyn_va, len(dyn_blob), len(dyn_blob))
    return analyze(b.build()), {
        "rela_va": rela_va, "rel_va": rel_va, "jmp_va": jmp_va,
    }


def test_plain_string_is_not_evidence(analyze):
    """文件中只有目标字符串，不产生证据。"""
    r, _ = build_sample(analyze, symbols=[], extra_strings=[CHK],
                        with_reloc_tags=False)
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.NO_EVIDENCE
    assert r.evidence == []


def test_defined_symbol_is_not_evidence(analyze):
    """已定义的同名符号被重定位引用，不算证据。"""
    r, _ = build_sample(analyze, symbols=[(CHK, 7)], relas=[1])
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.NO_EVIDENCE


def test_undef_symbol_not_referenced_is_not_evidence(analyze):
    """未定义目标符号存在但无重定位引用，不算证据。"""
    r, _ = build_sample(analyze, symbols=[(CHK, SHN_UNDEF)],
                        with_reloc_tags=False)
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.NO_EVIDENCE


def test_undef_symbol_via_rela_is_evidence(analyze):
    r, va = build_sample(analyze, symbols=[(CHK, SHN_UNDEF)], relas=[1])
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.EVIDENCE
    assert len(r.evidence) == 1
    ev = r.evidence[0]
    assert ev.symbol_name == "__stack_chk_fail"
    # 文件偏移：本样本 vaddr == 文件偏移
    assert ev.reloc_offset == va["rela_va"]


def test_undef_local_via_rel_is_evidence(analyze):
    r, va = build_sample(analyze, symbols=[(CHK_LOCAL, SHN_UNDEF)], rels=[1])
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.EVIDENCE
    assert r.evidence[0].symbol_name == "__stack_chk_fail_local"
    assert r.evidence[0].reloc_offset == va["rel_va"]


def test_undef_via_jmprel_is_evidence(analyze):
    r, va = build_sample(analyze, symbols=[(CHK, SHN_UNDEF)], jmprels=[1])
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.EVIDENCE
    assert r.evidence[0].reloc_offset == va["jmp_va"]


def test_unrelated_undef_symbol_is_not_evidence(analyze):
    r, _ = build_sample(analyze, symbols=[(b"printf", SHN_UNDEF)], relas=[1])
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.NO_EVIDENCE


def test_no_reloc_tables_no_evidence(analyze):
    r, _ = build_sample(analyze, symbols=[(CHK, SHN_UNDEF)],
                        with_reloc_tags=False)
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.NO_EVIDENCE


def test_dyn_without_pie_flag_not_pie(analyze):
    """ET_DYN 但无 PIE 标志不得判为 PIE（含完整动态表）。"""
    r, _ = build_sample(analyze, symbols=[(CHK, SHN_UNDEF)], relas=[1])
    assert r.valid, r.invalid_reason
    assert r.pie == PIEStatus.UNKNOWN


def test_multiple_evidence_offsets(analyze):
    r, va = build_sample(analyze,
                         symbols=[(CHK, SHN_UNDEF), (CHK_LOCAL, SHN_UNDEF)],
                         relas=[1, 2], rels=[2])
    assert r.valid, r.invalid_reason
    assert r.stack_chk == StackChkStatus.EVIDENCE
    got = sorted((ev.reloc_offset, ev.symbol_name) for ev in r.evidence)
    ent_rela = 24
    assert got == sorted([
        (va["rela_va"], "__stack_chk_fail"),
        (va["rela_va"] + ent_rela, "__stack_chk_fail_local"),
        (va["rel_va"], "__stack_chk_fail_local"),
    ])
