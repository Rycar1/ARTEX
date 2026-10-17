# refs/forensics.md — 取证工具箱

> 给的是磁盘镜像 / 内存转储 / 流量 / 日志 / 一堆文件，要从里面捞出 flag 或关键线索。
> 与 misc.md 的分工：misc 管单文件隐写与编码，forensics 管「镜像级、流量级、日志级」的还原。

## 1. 判定特征

- 附件是 `.img/.dd/.raw/.vmdk/.qcow2/.E01`、`.mem/.dmp/.vmem`、`.pcap/.pcapng`、`.evtx/.log/.json`
- 题面出现 磁盘 / 内存 / 流量 / 抓包 / 日志 / 删除文件 / 恢复 / 时间线
- 附件体积明显偏大（几百 MB 以上），`file` 报 data 或 DOS/MBR boot sector
- 给了多份日志要求交叉分析时间线

## 2. 环境自检

```sh
for t in mmls fls icat fsstat photorec foremost testdisk tshark tcpdump strings xxd \
         binwalk exiftool sqlite3 jq rg; do printf '%-11s' "$t"; command -v "$t" || echo MISSING; done
python3 -c "import volatility3" 2>/dev/null && echo 'volatility3 ok' || echo 'volatility3 未预装：pip install volatility3（离线时用 strings+grep 兜底）'
```

## 3. 磁盘 / 文件系统镜像

```sh
file disk.img
mmls disk.img                                   # 分区表，记下每段的起始扇区
fsstat -o 2048 disk.img                         # 文件系统类型
fls -r -o 2048 disk.img | head -60              # 递归列文件（含被删项）
fls -r -d -o 2048 disk.img                      # 只看已删除项（* 开头）
icat -o 2048 disk.img 1234 > /tmp/recovered.bin # 按 inode 取文件
photorec disk.img                               # 交互式按签名雕刻
foremost -T -i disk.img -o /tmp/out/            # 批量签名雕刻
binwalk -eM disk.img                            # 嵌套提取（固件/嵌入式镜像常用）
```

- 找不到文件系统：`binwalk` 看是否有嵌套镜像；`testdisk` 修分区表
- 常见的「隐藏」位置：分区间隙、未分配空间、`$MFT` 记录、文件末尾追加数据
- 拿到 `NTFS` 时优先 `fls -r -p` 看完整路径；`icat` 按 inode 取比按文件名更可靠

## 4. 内存镜像

```sh
python3 -m volatility3 -f mem.raw windows.info         # 先定 profile/版本
python3 -m volatility3 -f mem.raw windows.pslist
python3 -m volatility3 -f mem.raw windows.cmdline
python3 -m volatility3 -f mem.raw windows.filescan | rg -i 'flag|secret|\.txt|\.zip'
python3 -m volatility3 -f mem.raw windows.dumpfiles --virtaddr 0x...
python3 -m volatility3 -f mem.raw windows.malfind
python3 -m volatility3 -f mem.raw windows.hashdump
# Linux 镜像换插件：linux.pslist / linux.bash / linux.lsof
```

volatility3 没装或符号包缺失时的兜底（离线也能跑）：

```sh
strings -n 6 mem.raw | rg -i 'flag\{|DASCTF|password|secret' | head -40
strings -n 6 mem.raw | rg -o '[A-Za-z0-9_]{6,}\{[^}]{4,}\}' | sort -u | head
binwalk -eM mem.raw                            # 抠出内嵌文件系统/压缩包
```

## 5. 流量分析

```sh
tshark -r cap.pcap -q -z io,phs                       # 协议分层总览
tshark -r cap.pcap -Y http -T fields -e http.host -e http.request.uri
tshark -r cap.pcap -Y 'http.request.method==POST' -T fields -e http.file_data | head
tshark -r cap.pcap -Y 'tcp.port==80' -z follow,tcp,ascii,0     # 跟踪流
tshark -r cap.pcap --export-objects http,/tmp/httpobj          # 导出 HTTP 对象
tshark -r cap.pcap -Y 'dns' -T fields -e dns.qry.name | sort -u
tshark -r cap.pcap -T fields -e usb.capdata                     # USB 键盘/鼠标
tcpdump -r cap.pcap -nn -A 'tcp port 80' | head -80
```

- USB 键盘流量：`usb.capdata` 每行 8 字节，第 3 字节是按键码，按 HID 表还原
- 隐藏数据：看有无 `ICMP`/`DNS` 隧道、异常大的 `tcp.len`、非标准端口
- 导出对象后逐个 `file`，常见是图片/压缩包/脚本

## 6. 日志 / 事件

```sh
rg -n -i 'flag|passwd|login|failed|sudo|cmd' *.log | head -40
jq -r '.timestamp + " " + .message' app.json | head -40        # JSON 日志
sqlite3 evidence.db ".tables" && sqlite3 evidence.db "select * from logs limit 20;"
```

- 时间线优先：按时间排序再看「谁在什么时候做了什么」，别逐行读
- Windows 事件日志转文本后可 `rg`；浏览器历史 / 回收站 / 最近访问是高频考点

## 7. 与 misc 的分界

图片、音频、压缩包、单文件隐写 → 走 `refs/misc.md`（exiftool / zsteg / steghide / sox / john）。
本文件只负责镜像级与流量级还原；两边都命中时先做本文件的「提取出文件」，再拿文件去 misc 那套。

## 8. 卡点与换维

| 卡点 | 换维方向 |
|---|---|
| volatility 跑不起来 | 先用 `strings | rg` 直接捞 flag；或 `binwalk -eM` 抠文件 |
| 镜像打不开 | `file` + `binwalk` 看是不是嵌套/固件；`testdisk` 修分区 |
| 流量没 HTTP | 看是不是自定义 TCP/UDP 协议，用 `follow,tcp,raw` 看原始字节再手解 |
| 找不到被删文件 | `fls -r -d` 全盘扫；再不行 `photorec` 雕刻；仍未果看未分配空间 |
| 数据量大 | 先 `strings | rg 'flag\{'` 快速试一遍，命中就不用做完整取证 |
