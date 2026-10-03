"""分析报告数据类型。报告只保存在内存中。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class NXStatus(Enum):
    ENABLED = "enabled"        # PT_GNU_STACK 存在且未置 PF_X
    DISABLED = "disabled"      # PT_GNU_STACK 存在且置 PF_X
    UNKNOWN = "unknown"        # 缺少 PT_GNU_STACK


class PIEStatus(Enum):
    YES = "yes"                # ET_DYN 且 DT_FLAGS_1 含 DF_1_PIE
    NO = "no"                  # ET_EXEC
    UNKNOWN = "unknown"        # 其他情况


class StackChkStatus(Enum):
    EVIDENCE = "evidence"      # 发现证据
    NO_EVIDENCE = "no_evidence"  # 未见证据（不代表未启用）


@dataclass(frozen=True, slots=True)
class StackChkEvidence:
    """一条栈保护证据：命中重定位的文件偏移与符号名。"""

    reloc_offset: int   # 重定位表项在文件中的偏移
    symbol_name: str    # "__stack_chk_fail" 或 "__stack_chk_fail_local"


@dataclass(slots=True)
class Report:
    """分析结论。valid=False 时其余字段不可信。"""

    valid: bool
    invalid_reason: Optional[str] = None
    nx: Optional[NXStatus] = None
    pie: Optional[PIEStatus] = None
    stack_chk: Optional[StackChkStatus] = None
    evidence: List[StackChkEvidence] = field(default_factory=list)

    @classmethod
    def invalid(cls, reason: str) -> "Report":
        return cls(valid=False, invalid_reason=reason)
