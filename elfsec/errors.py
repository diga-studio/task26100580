"""错误类型定义。"""


class ElfFormatError(Exception):
    """ELF 结构损坏或数据不可信，整份报告无效。"""
