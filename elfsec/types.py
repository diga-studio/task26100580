"""报告数据类型定义。"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import List, Optional


class TriState(enum.Enum):
    """三态结论：是 / 否 / 未知。"""

    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


class EvidenceState(enum.Enum):
    """栈保护证据状态：发现证据 / 未见证据（后者不代表未启用）。"""

    FOUND = "found"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class StackChkEvidence:
    """一条栈保护证据：命中重定位的文件偏移与符号名。"""

    reloc_offset: int
    symbol_name: str


@dataclass
class Report:
    """分析报告。valid 为 False 时其余结论字段均为 None。"""

    valid: bool
    error: Optional[str] = None
    nx: Optional[TriState] = None
    pie: Optional[TriState] = None
    stack_chk: Optional[EvidenceState] = None
    stack_chk_evidence: List[StackChkEvidence] = field(default_factory=list)
