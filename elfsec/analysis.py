"""分析编排：NX / PIE / 栈保护证据，产出内存中的 Report。"""

from __future__ import annotations

from typing import List

from .constants import (
    DF_1_PIE,
    DT_FLAGS_1,
    ET_DYN,
    ET_EXEC,
    PF_X,
    PT_GNU_STACK,
    SHN_UNDEF,
)
from .dynamic import parse_dynamic
from .errors import ELFError, InvalidReport
from .headers import parse_elf_header, parse_program_headers
from .reader import FileReader
from .relocations import iter_reloc_refs
from .report import (
    NXStatus,
    PIEStatus,
    Report,
    StackChkEvidence,
    StackChkStatus,
)
from .segments import SegmentMapper
from .symbols import read_symbol, read_symbol_name

_TARGET_NAMES = (b"__stack_chk_fail", b"__stack_chk_fail_local")


def _analyze(reader: FileReader) -> Report:
    eh = parse_elf_header(reader)
    if eh.e_type not in (ET_EXEC, ET_DYN):
        raise InvalidReport(f"不支持的 e_type: {eh.e_type}（仅处理 ET_EXEC/ET_DYN）")
    phdrs = parse_program_headers(reader, eh)

    # NX：重复 PT_GNU_STACK 整份无效
    gnu_stack = [ph for ph in phdrs if ph.p_type == PT_GNU_STACK]
    if len(gnu_stack) > 1:
        raise InvalidReport("重复的 PT_GNU_STACK")
    if not gnu_stack:
        nx = NXStatus.UNKNOWN
    elif gnu_stack[0].p_flags & PF_X:
        nx = NXStatus.DISABLED
    else:
        nx = NXStatus.ENABLED

    # 加载段映射（filesz>memsz、越界、地址溢出于此判定）
    mapper = SegmentMapper(phdrs, reader.size, 64 if eh.is_64 else 32)
    dyn = parse_dynamic(reader, phdrs, eh.is_64, eh.little_endian)

    # PIE
    if eh.e_type == ET_EXEC:
        pie = PIEStatus.NO
    elif dyn is not None:
        flags1 = dyn.single(DT_FLAGS_1)
        pie = PIEStatus.YES if (flags1 is not None and flags1 & DF_1_PIE) \
            else PIEStatus.UNKNOWN
    else:
        pie = PIEStatus.UNKNOWN

    # 栈保护证据：必须完整遍历全部重定位，后出现的损坏同样使报告无效
    evidence: List[StackChkEvidence] = []
    if dyn is not None:
        for ref in iter_reloc_refs(reader, mapper, dyn, eh.is_64,
                                   eh.little_endian):
            sym = read_symbol(reader, mapper, dyn, eh.is_64,
                              eh.little_endian, ref.sym_index)
            if sym.st_shndx != SHN_UNDEF:
                continue
            name = read_symbol_name(reader, mapper, dyn, sym.st_name)
            if name in _TARGET_NAMES:
                evidence.append(StackChkEvidence(
                    reloc_offset=ref.reloc_offset,
                    symbol_name=name.decode("ascii"),
                ))
    stack_chk = StackChkStatus.EVIDENCE if evidence else StackChkStatus.NO_EVIDENCE

    return Report(
        valid=True, nx=nx, pie=pie, stack_chk=stack_chk, evidence=evidence,
    )


def analyze_file(path: str) -> Report:
    """分析本地 ELF 文件，返回内存中的报告。不执行被分析文件。

    结构损坏或违反业务规则时返回 valid=False 的报告，不抛异常。
    """
    try:
        with FileReader(path) as reader:
            return _analyze(reader)
    except InvalidReport as exc:
        return Report.invalid(exc.reason)
    except ELFError as exc:
        return Report.invalid(f"ELF 解析失败: {exc}")
