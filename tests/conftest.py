import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elfsec import analyze_file  # noqa: E402
from elfsec.report import Report  # noqa: E402


def analyze_bytes(data: bytes) -> Report:
    """将字节写入临时文件并分析。"""
    fd, path = tempfile.mkstemp()
    try:
        os.write(fd, data)
        os.close(fd)
        return analyze_file(path)
    finally:
        os.unlink(path)


@pytest.fixture()
def analyze():
    return analyze_bytes
