"""栈保护证据规则：只有真实未定义符号重定位才算证据。"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

import pytest  # noqa: E402

from conftest import CHK_LOCAL_NAME, CHK_NAME, build_standard  # noqa: E402
from elfsec import EvidenceState, analyze  # noqa: E402


@pytest.mark.parametrize("is_64,little", [(False, False), (True, True)])
def test_string_only_is_not_evidence(is_64, little, write_sample):
    """文件中只有目标字符串：未见证据。"""
    b, _ = build_standard(is_64=is_64, little=little, with_dynamic=False)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.NOT_FOUND
    assert report.stack_chk_evidence == []


@pytest.mark.parametrize("is_64,little", [(False, False), (True, True)])
def test_defined_symbol_is_not_evidence(is_64, little, write_sample):
    """已定义的同名符号被重定位引用：未见证据。"""
    b, _ = build_standard(is_64=is_64, little=little, sym_shndx=1)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.NOT_FOUND


@pytest.mark.parametrize("is_64,little", [(False, False), (True, True)])
def test_undef_symbol_reloc_is_evidence(is_64, little, write_sample):
    """SHN_UNDEF 符号被声明的重定位引用：发现证据。"""
    b, expected = build_standard(is_64=is_64, little=little, sym_shndx=0)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.FOUND
    assert len(report.stack_chk_evidence) == 1
    hit = report.stack_chk_evidence[0]
    assert hit.reloc_offset == expected["reloc_offset"]
    assert hit.symbol_name == expected["symbol_name"]


def test_unreferenced_undef_symbol_is_not_evidence(write_sample):
    """存在未定义同名符号但无重定位引用：未见证据。"""
    b, _ = build_standard(is_64=True, little=True, sym_shndx=0, with_reloc=False)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.NOT_FOUND


def test_local_variant_is_evidence(write_sample):
    """__stack_chk_fail_local 同样是证据。"""
    b, expected = build_standard(is_64=True, little=True, name=CHK_LOCAL_NAME)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.FOUND
    assert report.stack_chk_evidence[0].symbol_name == CHK_LOCAL_NAME.decode()


def test_similar_name_is_not_evidence(write_sample):
    """名称必须完整等于目标，前缀相同不算。"""
    b, _ = build_standard(is_64=True, little=True, name=CHK_NAME + b"_x")
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.NOT_FOUND


@pytest.mark.parametrize("kind", ["rel", "rela", "jmprel"])
def test_all_declared_reloc_tables_count(kind, write_sample):
    """DT_REL / DT_RELA / DT_JMPREL 声明的重定位都可作证据来源。"""
    b, expected = build_standard(is_64=True, little=True, reloc_kind=kind)
    report = analyze(write_sample(b))
    assert report.valid, report.error
    assert report.stack_chk == EvidenceState.FOUND
    assert report.stack_chk_evidence[0].reloc_offset == expected["reloc_offset"]
