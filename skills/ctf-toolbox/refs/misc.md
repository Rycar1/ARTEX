# refs/misc.md — misc / 取证 工具箱

> 全部命令在容器内直接可用。凡是标注「(未预装)」的，先别用。

## 1. 文件类型与结构

```sh
file challenge.bin                  # 先看是什么，永远的第一步
xxd challenge.bin | head -40        # 十六进制头
strings -n 6 challenge.bin | head -50
binwalk challenge.bin               # 识别嵌套文件系统/压缩流
binwalk -eM challenge.bin           # 递归提取（-e 提取，-M 递归）
7z l challenge.bin                  # 7z 能认的归档格式
```

## 2. 图片隐写

```sh
exiftool pic.png                    # 元数据/注释/软件痕迹
pngcheck -v pic.png                 # PNG 块结构异常（多出来的块常藏数据）
zsteg -a pic.png                    # PNG/BMP LSB 全通道扫描（最常用）
steghide extract -sf pic.jpg        # JPG/WAV 隐写，需口令；空口令直接回车
outguess -r pic.jpg out.txt         # JPG 隐写
identify -verbose pic.png           # ImageMagick：色彩/尺寸/直方图
convert pic.png -channel RGB -separate ch_%d.png   # 拆通道
zbarimg -q pic.png                  # 图片里的二维码/条码
```

其他常见手法（用 python3 + PIL，已装）：
- 宽高被改：PNG 的 IHDR 宽高 vs 实际数据长度，直接改回来看
- LSB / 位平面 / 通道差：`Image.open(p).convert('RGB').getdata()` 自己算
- 调色板顺序、CRC 校验对不上 → 说明图片被改过

## 3. 音频

```sh
sox in.wav -n spectrogram -o spec.png      # 频谱图，misc 音频第一招
ffmpeg -i in.mp3 -filter_complex showspectrumpic=s=1024x512 spec.png
sox in.wav out.wav reverse                # 倒放
ffmpeg -i in.wav -af "volume=5" loud.wav  # 音量放大
```

## 4. 压缩包

```sh
7z x -oout pkg.7z                  # 通用解压（含嵌套）
fcrackzip -u -D -p rockyou.txt a.zip      # zip 口令爆破（-u 只试可解压的）
pdfcrack -w rockyou.txt doc.pdf           # PDF 口令爆破
zip2john a.zip > h.txt && john --wordlist=rockyou.txt h.txt   # zip 哈希交给 john
rar2john / 7z2john.pl                     # 同族（rar2john 随 john 提供）
qpdf --qdf --object-streams=disable in.pdf out.pdf   # PDF 结构化，便于看内容
pdftotext in.pdf -                 # 抽文本
```

## 5. 流量分析

```sh
tshark -r cap.pcap -Y http.request -T fields -e http.host -e http.request.uri
tshark -r cap.pcap -T fields -e usb.capdata      # USB 键盘/鼠标流量还原
tshark -r cap.pcap -Y "tcp.port==80" -z follow,tcp,ascii,0
tcpdump -r cap.pcap -nn -A 'tcp port 80' | head -100
```

## 6. 磁盘 / 文件系统 / 内存

```sh
mmls disk.img                      # 分区表
fls -r -o <offset> disk.img        # 列文件（-o 分区偏移，单位扇区）
icat -o <offset> disk.img <inode> > recovered.bin   # 按 inode 取文件
testdisk disk.img                  # 交互式分区/引导修复
photorec disk.img                  # 按签名雕刻文件
foremost -T -i disk.img -o out/    # 签名雕刻（与 photorec 互补）
```

## 7. 口令 / 哈希破解

```sh
hashcat --example-hashes | less    # 查 mode 号
hashcat -m 0 -a 0 hash.txt rockyou.txt
hashcat -m 0 -a 3 hash.txt ?a?a?a?a          # 掩码爆破
john --format=raw-md5 --wordlist=rockyou.txt h.txt
john --show h.txt
```

`/usr/share/wordlists/rockyou.txt` 未随镜像安装；常见做法是先 `command -v` 探，
没有就用题目给的字典，或用 `hashcat --stdout -a 3 ?d?d?d?d > wl.txt` 现场生成。

## 8. crypto 辅助（python3，已装）

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse, GCD, isPrime
import sympy, z3, gmpy2
```
- RSA 小 e / 共模 / 广播 / 低指数：`gmpy2.iroot`、`sympy.ntheory`
- 线性/约束型题：`z3.Solver()`（已装）
- 大量位运算：`gmpy2`（已装）

## 9. 数据库/杂项

```sh
sqlite3 data.db ".tables" && sqlite3 data.db "select * from flag;"
gawk '...' / convert / identify 都在
```
