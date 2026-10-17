# refs/rev.md — 逆向（RE）工具箱

> 先静态定位，再动态验证；每条结论附命令与回显。

## 1. 基本信息与保护

```sh
file ./chall
readelf -h ./chall            # ELF 头：架构/入口/类型
readelf -lW ./chall           # 段表：看 GNU_STACK/GNU_RELRO（NX/RELRO）
readelf -dW ./chall           # 动态段：BIND_NOW → Full RELRO
readelf -sW ./chall | head -50
objdump -d -M intel ./chall | head -120
strings -a -n 8 ./chall | less
```
Python 侧（已装 pwntools）：
```python
from pwn import *
e = ELF('./chall'); print(e.checksec()); print(hex(e.symbols.get('main', 0)))
print(hex(e.got['printf']), hex(e.plt['puts']))
```

## 2. 静态分析

- 反汇编：`objdump -d -M intel`；大函数用 `objdump -d --start-address=0x.. --stop-address=0x..`
- 符号执行（跳过手写约束，直接跑出满足条件的输入）：`import angr`（CTF_EXTRA=1 构建时已装）
- 读 ELF/PE 结构用 python：`from elftools.elf.elffile import ELFFile`；`import lief`（改节表/加段很顺手）
- 交叉引用/伪代码：镜像内**没有** radare2/Ghidra/IDA；有 r2 时用 `r2 -A ./chall`（`pdf @ main`、`axt`）
- 反汇编为 Python 对象（做自动化/解密很常用）：
```python
from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(open('./chall','rb').read()[0x1200:0x1300], 0x1200):
    print(f'{i.address:#x}: {i.mnemonic} {i.op_str}')
```
- 汇编回去（patch / 造 shellcode）：`from keystone import *`（ks.asm）
- 模拟执行单段代码（解自解密/校验逻辑）：`from unicorn import *`（Uc + hook_mem/mem_write）
- 约束求解（注册机、迷宫、逐字节校验）：`import z3`，把校验逻辑翻成符号式
- .NET / Java / Python 字节码：`strings` + 对应反编译器；python 有 `python3 -m dis`、`marshal`、`uncompyle6`(未装)

## 3. 动态调试

```sh
gdb -q ./chall
# 常用：b main / r / ni / si / x/20gx $rsp / info registers / vmmap / info proc mappings
gdb -q -ex 'set disassembly-flavor intel' -ex 'b *0x4011a0' -ex 'r' -ex 'x/20gx $rsp' ./chall
strace -f -s 200 ./chall          # 系统调用轨迹（看它读了什么/开了什么）
ltrace -f -s 200 ./chall          # 库调用轨迹（看它和 strcmp/memcmp 怎么交互）
```
跨架构（ARM/MIPS/RISC-V 静态链接样本）：
```sh
qemu-aarch64 -L /usr/aarch64-linux-gnu ./chall_arm64
gdb-multiarch -q ./chall_arm64     # 配 qemu -g 1234 远程调试
```

## 4. 常见套路速查

| 现象 | 先做什么 |
|---|---|
| 输入什么都说错 | `ltrace`/`strace` 看比较点；`strings` 找提示串；z3 解约束 |
| 有大量异或/移位循环 | capstone 反汇编出来，直接用 python 复刻（别在汇编里硬啃） |
| 自解密/自修改代码 | unicorn 模拟执行到解密后 dump 内存 |
| 反调试（ptrace 检测） | `gdb -ex 'catch syscall ptrace'`；或 patch 掉检测分支（`patchelf`/`dd` 改字节） |
| UPX 壳 | `upx -d ./chall`（upx 未预装时用 `command -v upx` 确认；也可用 `python3` 手解 UPX 头） |
| .NET / pyc / class | `strings` 定位语言特征，再找对应反编译路线 |
| 带符号表 | 先 `readelf -sW` / `nm -C` 直接读函数名 |

## 5. 交付要求

- 写清：架构与保护、关键函数地址、判断逻辑、输入格式、解出的 flag
- 每个结论附实际命令 + 回显片段；没跑通的标「未执行」
