"""错误类型：分析输入无法解析或违反业务规则时抛出。"""


class ELFError(Exception):
    """ELF 结构层面的解析错误（格式非法、越界等）。"""


class InvalidReport(Exception):
    """业务规则判定整份报告无效。message 说明原因。"""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason
