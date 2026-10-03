"""顶层分析入口：读入本地 ELF 文件，输出内存中的报告。不执行被分析文件。"""
from __future__ import annotations

import os

from .dynamic import DF_1_PIE, DT_FLAGS_1, parse_dynamic
from .elf import ET_DYN, ET_EXEC, PT_GNU_STACK, PT_LOAD, parse_elf
from .errors import ElfFormatError
from .reader import Reader
from .reloc import scan_stack_chk
from .types import EvidenceState, Report, TriState
from .vmap import VMap

_PF_X = 0x1


def _analyze_fp(fp, size: int) -> Report:
    reader = Reader(fp, size)
    info = parse_elf(reader)

    vmap = VMap()
    gnu_stack = []
    for phdr in info.phdrs:
        if phdr.p_type == PT_LOAD:
            if phdr.filesz > 0 and phdr.offset + phdr.filesz > size:
                raise ElfFormatError("加载段文件范围越界")
            vmap.add_segment(phdr.vaddr, phdr.filesz, phdr.memsz, phdr.offset)
        elif phdr.p_type == PT_GNU_STACK:
            gnu_stack.append(phdr)
    if len(gnu_stack) > 1:
        raise ElfFormatError("重复的 PT_GNU_STACK")

    dyn = parse_dynamic(reader, info, vmap)

    if not gnu_stack:
        nx = TriState.UNKNOWN
    elif gnu_stack[0].flags & _PF_X:
        nx = TriState.NO
    else:
        nx = TriState.YES

    if info.e_type == ET_EXEC:
        pie = TriState.NO
    elif info.e_type == ET_DYN and dyn.get(DT_FLAGS_1, 0) & DF_1_PIE:
        pie = TriState.YES
    else:
        pie = TriState.UNKNOWN

    evidence = scan_stack_chk(reader, info, vmap, dyn)
    stack_chk = EvidenceState.FOUND if evidence else EvidenceState.NOT_FOUND

    return Report(
        valid=True,
        nx=nx,
        pie=pie,
        stack_chk=stack_chk,
        stack_chk_evidence=evidence,
    )


def analyze(path: str) -> Report:
    """分析本地 ELF 文件，返回内存中的报告。

    文件损坏或数据不可信时返回 valid=False 的无效报告，
    此时不给出任何部分结论。
    """
    try:
        with open(path, "rb") as fp:
            size = os.fstat(fp.fileno()).st_size
            return _analyze_fp(fp, size)
    except ElfFormatError as exc:
        return Report(valid=False, error=str(exc))
    except OSError as exc:
        return Report(valid=False, error=f"无法读取文件: {exc}")
