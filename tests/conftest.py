import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from elfbuild import (  # noqa: E402
    DF_1_PIE,
    DT_FLAGS_1,
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
    PT_DYNAMIC,
    PT_GNU_STACK,
    ElfBuilder,
)

CHK_NAME = b"__stack_chk_fail"
CHK_LOCAL_NAME = b"__stack_chk_fail_local"


def build_standard(
    is_64: bool,
    little: bool,
    e_type: int = ET_DYN,
    pie_flag: bool = False,
    gnu_stack_flags=None,
    sym_shndx: int = 0,
    with_dynamic: bool = True,
    name: bytes = CHK_NAME,
    reloc_kind: str = "rela",
    with_reloc: bool = True,
):
    """构造标准样本：动态表、目标符号、符号名各自横跨加载段边界。

    返回 (ElfBuilder, expected)，expected 含命中重定位的文件偏移与符号名。
    """
    b = ElfBuilder(is_64=is_64, little=little, e_type=e_type)
    # 4 个加载段：虚拟地址连续，文件位置不连续。
    for i in range(4):
        b.add_load(0x200 + i * 0x200, 0x1000 + i * 0x100, 0x100, 0x100)
    if gnu_stack_flags is not None:
        b.add_phdr(PT_GNU_STACK, gnu_stack_flags, 0, 0, 0, 0)

    syment = 24 if is_64 else 16
    relent = 16 if is_64 else 8
    relaent = 24 if is_64 else 12

    dyn_addr = 0x1100 - 8                      # 动态表横跨 0x1100 边界
    symtab_addr = 0x1200 - syment - syment // 2  # 目标符号横跨 0x1200 边界
    strtab_addr = 0x1300 - 8                   # 符号名横跨 0x1300 边界
    reloc_addr = 0x1340

    strtab = b"\x00" + name + b"\x00"
    assert strtab_addr + 1 < 0x1300 < strtab_addr + 1 + len(name)

    expected = {}

    if with_dynamic:
        dyn_entries = [
            (DT_STRTAB, strtab_addr),
            (DT_STRSZ, 0x40),
            (DT_SYMTAB, symtab_addr),
            (DT_SYMENT, syment),
        ]
        if reloc_kind == "rela":
            dyn_entries += [
                (DT_RELA, reloc_addr),
                (DT_RELASZ, relaent),
                (DT_RELAENT, relaent),
            ]
            reloc_ent = relaent
        elif reloc_kind == "rel":
            dyn_entries += [
                (DT_REL, reloc_addr),
                (DT_RELSZ, relent),
                (DT_RELENT, relent),
            ]
            reloc_ent = relent
        elif reloc_kind == "jmprel":
            dyn_entries += [
                (DT_JMPREL, reloc_addr),
                (DT_PLTRELSZ, relaent),
                (DT_PLTREL, DT_RELA),
            ]
            reloc_ent = relaent
        else:
            raise ValueError(reloc_kind)
        if pie_flag:
            dyn_entries.append((DT_FLAGS_1, DF_1_PIE))
        dyn_entries.append((DT_NULL, 0))
        dyn = b.pack_dyn(dyn_entries)
        assert dyn_addr < 0x1100 < dyn_addr + len(dyn)
        b.add_phdr(PT_DYNAMIC, 6, 0x200 + (dyn_addr - 0x1000), dyn_addr, len(dyn), len(dyn))
        _place(b, dyn_addr, dyn)

        # 符号 1 横跨 0x1200 边界。
        sym1_addr = symtab_addr + syment
        assert sym1_addr < 0x1200 < sym1_addr + syment
        syms = b.pack_sym(0, 0) + b.pack_sym(1, sym_shndx)
        _place(b, symtab_addr, syms)

        _place(b, strtab_addr, strtab)

        if with_reloc:
            if reloc_kind == "rel":
                reloc = b.pack_rel(0x2000, b.r_info(1))
            else:
                reloc = b.pack_rela(0x2000, b.r_info(1))
            _place(b, reloc_addr, reloc)
            if sym_shndx == 0:
                expected = {
                    "reloc_offset": 0x800 + (reloc_addr - 0x1300),
                    "symbol_name": name.decode(),
                }
    else:
        # 仅在文件中放置目标字符串，不提供任何动态信息。
        _place(b, strtab_addr, strtab)

    return b, expected


def _place(b: ElfBuilder, vaddr: int, data: bytes) -> None:
    """按 0x1000->0x200, 0x1100->0x400 ... 的映射把数据写进文件区域。"""
    seg_file_base = {0x1000: 0x200, 0x1100: 0x400, 0x1200: 0x600, 0x1300: 0x800}
    pos = 0
    while pos < len(data):
        va = vaddr + pos
        seg_base = va & ~0xFF
        file_off = seg_file_base[seg_base] + (va - seg_base)
        n = min(len(data) - pos, seg_base + 0x100 - va)
        b.set_data(file_off, data[pos : pos + n])
        pos += n


@pytest.fixture
def write_sample(tmp_path):
    def _write(builder: ElfBuilder, name: str = "sample.elf") -> str:
        path = tmp_path / name
        path.write_bytes(builder.build())
        return str(path)

    return _write
