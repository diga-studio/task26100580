"""elfsec：固件 ELF 安全属性分析库（NX / PIE / 栈保护证据）。

用法::

    from elfsec import analyze_file
    report = analyze_file("/path/to/firmware.elf")
"""

from .analysis import analyze_file
from .report import (
    NXStatus,
    PIEStatus,
    Report,
    StackChkEvidence,
    StackChkStatus,
)

__all__ = [
    "analyze_file",
    "Report",
    "NXStatus",
    "PIEStatus",
    "StackChkStatus",
    "StackChkEvidence",
]

__version__ = "0.1.0"
