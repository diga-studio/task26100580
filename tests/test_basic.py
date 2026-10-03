"""基础结论：无节表、跨段数据、节表不影响结果、NX/PIE 三态。"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

import pytest  # noqa: E402

from conftest import CHK_NAME, build_standard  # noqa: E402
from elfbuild import (  # noqa: E402
    ET_EXEC,
    PF_R,
    PF_W,
    PF_X,
    make_shdr_table,
)
from elfsec import EvidenceState, TriState, analyze  # noqa: E402


@pytest.mark.parametrize("is_64,little", [(False, False), (True, False), (False, True), (True, True)])
def test_no_section_header_cross_segment(is_64, little, write_sample):
    """无节表、动态表/符号/名称跨段的样本，结论与独立预期一致。"""
    b, expected = build_standard(
        is_64=is_64, little=little, pie_flag=True, gnu_stack_flags=PF_R | PF_W
    )
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.nx == TriState.YES
    assert report.pie == TriState.YES
    assert report.stack_chk == EvidenceState.FOUND
    assert len(report.stack_chk_evidence) == 1
    hit = report.stack_chk_evidence[0]
    assert hit.reloc_offset == expected["reloc_offset"]
    assert hit.symbol_name == expected["symbol_name"]


@pytest.mark.parametrize("is_64,little", [(False, False), (True, True)])
def test_section_table_does_not_change_result(is_64, little, write_sample):
    """补入节表后结论不变。"""
    b1, _ = build_standard(is_64=is_64, little=little, gnu_stack_flags=PF_R | PF_W)
    b2, _ = build_standard(is_64=is_64, little=little, gnu_stack_flags=PF_R | PF_W)
    b2.shdr_table = make_shdr_table(is_64, little)
    r1 = analyze(write_sample(b1, "a.elf"))
    r2 = analyze(write_sample(b2, "b.elf"))
    assert r1.valid and r2.valid
    assert (r1.nx, r1.pie, r1.stack_chk, r1.stack_chk_evidence) == (
        r2.nx,
        r2.pie,
        r2.stack_chk,
        r2.stack_chk_evidence,
    )


def test_nx_unknown_without_gnu_stack(write_sample):
    b, _ = build_standard(is_64=True, little=True, gnu_stack_flags=None)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.nx == TriState.UNKNOWN


def test_nx_disabled_when_stack_executable(write_sample):
    b, _ = build_standard(is_64=True, little=True, gnu_stack_flags=PF_R | PF_W | PF_X)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.nx == TriState.NO


def test_pie_no_for_et_exec(write_sample):
    b, _ = build_standard(is_64=True, little=True, e_type=ET_EXEC, pie_flag=True)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.pie == TriState.NO


def test_pie_unknown_for_et_dyn_without_flag(write_sample):
    """ET_DYN 但无 DF_1_PIE：不能判为 PIE。"""
    b, _ = build_standard(is_64=True, little=True, pie_flag=False)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.pie == TriState.UNKNOWN


def test_evidence_symbol_name_is_exact(write_sample):
    """证据符号名完整等于目标名。"""
    b, _ = build_standard(is_64=False, little=False)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk_evidence[0].symbol_name == CHK_NAME.decode()
