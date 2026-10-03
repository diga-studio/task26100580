# elfsec — 固件 ELF 安全属性分析库

对本地固件 ELF 文件做静态安全属性判定，供上层直接调用。
不执行被分析文件，不依赖节表，报告保存在内存中。

## 能力

- 支持 ELF32 / ELF64，大端 / 小端；仅处理 `ET_EXEC` 与 `ET_DYN`。
- 结论只依据程序头与动态信息；节表缺失或变化不影响结果。
- **NX**：`PT_GNU_STACK` 缺失为未知，`PF_X` 置位为未启用，否则已启用。
- **PIE**：`ET_EXEC` 为否；`ET_DYN` 且 `DT_FLAGS_1` 含 `DF_1_PIE` 为是；其余未知。
- **栈保护**：仅报告“发现证据 / 未见证据”。证据必须来自
  `DT_REL` / `DT_RELA` / `DT_JMPREL` 声明的重定位，其引用的动态符号为
  `SHN_UNDEF` 且名称完整等于 `__stack_chk_fail` 或 `__stack_chk_fail_local`。
  每条证据给出命中重定位的文件偏移与符号名，可独立核对。
- 动态指针中的虚拟地址按 `PT_LOAD` 文件覆盖范围解释；支持数据跨越
  虚拟地址连续、文件位置不连续的多个加载段；重叠映射不一致、零填充区
  引用、地址溢出、映射空洞等均使整份报告无效。

## 用法

```python
from elfsec import analyze, TriState, EvidenceState

report = analyze("/path/to/firmware.elf")
if not report.valid:
    print("样本不可信:", report.error)
else:
    print("NX:", report.nx)                 # TriState.YES / NO / UNKNOWN
    print("PIE:", report.pie)               # TriState.YES / NO / UNKNOWN
    print("栈保护:", report.stack_chk)       # EvidenceState.FOUND / NOT_FOUND
    for ev in report.stack_chk_evidence:
        print(f"  命中: 文件偏移 {ev.reloc_offset:#x} 符号 {ev.symbol_name}")
```

`report.valid == False` 时不给出任何部分结论（`nx` / `pie` /
`stack_chk` 均为 `None`），`error` 说明原因。

## 设计要点

- 只按声明范围做有界读取：单次读取不超过 1 MiB，长表按块流式扫描，
  伪造的巨大长度不会导致大量分配或无界循环。
- 符号名读取上限 64 字节（目标名最长 21 字节），`DT_STRSZ` 伪造也不影响内存。
- 不读取节表，不检查本次判定未引用的符号。

## 测试

```sh
python3 -m pytest            # 全部用例（含 10 万重定位、500 MiB 稀疏文件）
python3 -m pytest -m "not slow"   # 仅快速用例
```

样本由 `tests/elfbuild.py` 按显式布局构造，覆盖：无节表的 32 位大端 /
64 位小端、动态表 / 符号 / 名称跨加载段、字符串干扰、已定义同名符号、
重叠段、零填充引用、截断表、巨大伪造长度、先证据后损坏等场景。
