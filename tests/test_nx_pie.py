"""NX 与 PIE 结论判定。"""

from elfbuild import (
    DF_1_PIE,
    DT_FLAGS_1,
    DT_NULL,
    ET_EXEC,
    ET_DYN,
    ELFBuilder,
    PF_R,
    PF_W,
    PF_X,
    PT_DYNAMIC,
    PT_GNU_STACK,
)
from elfsec import NXStatus, PIEStatus, StackChkStatus


def test_nx_enabled(analyze):
    b = ELFBuilder(e_type=ET_EXEC)
    b.add_phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0)
    r = analyze(b.build())
    assert r.valid, r.invalid_reason
    assert r.nx == NXStatus.ENABLED


def test_nx_disabled(analyze):
    b = ELFBuilder(e_type=ET_EXEC)
    b.add_phdr(PT_GNU_STACK, PF_R | PF_W | PF_X, 0, 0, 0, 0)
    r = analyze(b.build())
    assert r.valid, r.invalid_reason
    assert r.nx == NXStatus.DISABLED


def test_nx_unknown_without_gnu_stack(analyze):
    b = ELFBuilder(e_type=ET_EXEC)
    r = analyze(b.build())
    assert r.valid, r.invalid_reason
    assert r.nx == NXStatus.UNKNOWN


def test_duplicate_gnu_stack_invalid(analyze):
    b = ELFBuilder(e_type=ET_EXEC)
    b.add_phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0)
    b.add_phdr(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0)
    r = analyze(b.build())
    assert not r.valid


def test_pie_no_for_et_exec(analyze):
    b = ELFBuilder(e_type=ET_EXEC)
    r = analyze(b.build())
    assert r.valid, r.invalid_reason
    assert r.pie == PIEStatus.NO


def test_pie_yes_for_dyn_with_flag(analyze):
    b = ELFBuilder(e_type=ET_DYN)
    dyn = b.alloc(b.pack_dyn([(DT_FLAGS_1, DF_1_PIE), (DT_NULL, 0)]))
    b.add_phdr(PT_DYNAMIC, PF_R, dyn, 0, 0, 0)  # filesz 在 build 前修正
    b.phdrs[-1].filesz = b.phdrs[-1].memsz = 32
    r = analyze(b.build())
    assert r.valid, r.invalid_reason
    assert r.pie == PIEStatus.YES


def test_pie_unknown_for_dyn_without_flag(analyze):
    """ET_DYN 但无 PIE 标志不得判为 PIE。"""
    b = ELFBuilder(e_type=ET_DYN)
    dyn = b.alloc(b.pack_dyn([(DT_NULL, 0)]))
    b.add_phdr(PT_DYNAMIC, PF_R, dyn, 0, 16, 16)
    r = analyze(b.build())
    assert r.valid, r.invalid_reason
    assert r.pie == PIEStatus.UNKNOWN
    assert r.stack_chk == StackChkStatus.NO_EVIDENCE


def test_pie_unknown_for_dyn_without_dynamic(analyze):
    b = ELFBuilder(e_type=ET_DYN)
    r = analyze(b.build())
    assert r.valid, r.invalid_reason
    assert r.pie == PIEStatus.UNKNOWN


def test_unsupported_e_type_invalid(analyze):
    b = ELFBuilder(e_type=1)  # ET_REL
    r = analyze(b.build())
    assert not r.valid


def test_non_elf_invalid(analyze):
    r = analyze(b"not an elf at all")
    assert not r.valid
