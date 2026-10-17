# refs/attachments.md — 附件指纹 → 工具链映射

> 拿到任何附件，先做「指纹三连」，再照本表直接上工具链，别从零摸索。
> 表里的工具先 `command -v` 探一次；标「(未预装)」的先按注释装或换替代。

## 0. 指纹三连（每个附件都先跑）

```sh
file challenge.bin                      # 类型 + 架构 + 是否 stripped
xxd challenge.bin | head -4             # 魔数（file 认错时以它为准）
strings -n 6 challenge.bin | head -40   # 特征串：语言/库/路径/URL/提示语
binwalk challenge.bin                   # 有无嵌套文件系统/压缩流/尾部追加数据
```

一眼定性的魔数速查（`xxd -l 8 challenge.bin`）：

| 魔数 | 格式 | 魔数 | 格式 |
|---|---|---|---|
| 7f 45 4c 46 | ELF | 50 4b 03 04 | ZIP/JAR/APK/DOCX |
| 4d 5a | PE (MZ) | 52 61 72 21 | RAR |
| fe ed fa ce / ca fe ba be | Mach-O / fat | 37 7a bc af | 7z |
| 89 50 4e 47 | PNG | 25 50 44 46 | PDF |
| ff d8 ff | JPEG | 1f 8b | GZIP |
| 47 49 46 38 | GIF | fd 37 7a 58 | XZ |
| 52 49 46 46 | WAV/AVI | 64 65 78 0a | DEX |
| d4 c3 b2 a1 / 0a 0d 0d 0a | PCAP / PCAPNG | 42 5a 68 | BZIP2 |

## 1. 映射总表

| 指纹 | 判定特征 | 工具链（按顺序上） |
|---|---|---|
| ELF | 7f454c46，file 报 ELF 32/64-bit | checksec（pwntools）→ readelf/objdump → r2（未预装）→ gdb |
| PE | 4d5a，file 报 PE32 | strings → objdump -d -M intel → r2/ghidra（未预装）；.NET 看 strings 里 mscorlib |
| Mach-O | feedface/cafebabe | strings + objdump；llvm-objdump（未预装） |
| APK/DEX | 504b 且含 classes.dex；dex 魔数 6465780a | unzip -l → jadx/apktool（未预装）→ dex2jar（未预装） |
| PCAP/PCAPNG | d4c3b2a1 / 0a0d0d0a | tshark → tcpdump → 手写 python 解析自定义协议 |
| 内存镜像 | 无固定魔数：体积大、strings 里混有 MZ/ELF 碎片 | volatility3（未预装）→ strings + grep |
| 磁盘镜像 | 偏移 510 处 55 aa，或 qcow/vmdk 头 | mmls → fls → icat；photorec / foremost |
| 图片 PNG | 89504e47 | exiftool → pngcheck -v → zsteg -a → binwalk -eM |
| 图片 JPEG | ffd8ff | exiftool → steghide / outguess → binwalk |
| GIF/BMP | 474946 / 424d | identify -verbose → PIL 逐帧、逐通道 |
| 音频 WAV/MP3 | 52494646 / ID3 | sox 频谱 → ffmpeg 变速倒放 → 差分两轨 |
| 二维码/条码 | 图里方块图案 | zbarimg -q；纯色差二维码先 PIL 二值化 |
| 压缩包 ZIP | 504b | 7z l/x → zip2john + john → fcrackzip -u |
| RAR / 7z | 52617221 / 377abcaf | unar / 7z x → rar2john、7z2john.pl |
| PDF | 25504446 | pdfinfo/pdftotext → qpdf --qdf → pdfcrack |
| 源码/脚本 | .py .js .php .rb .go .java | 直接 Read；pyc 用 python3 -m dis / marshal |
| 未知 | file 报 data 或识别失败 | binwalk -eM → strings → foremost → xxd 手看 |

## 2. 常见附加手法

- **尾部追加**：合法文件后面跟数据是经典藏 flag 方式。`binwalk -eM` 提不出来就看
  `tail -c 512 f.png | xxd`，或 `python3 -c "print(open('f.png','rb').read()[-256:])"`。
- **多附件组合**：一个图片 + 一个压缩包、一个流量 + 一份源码，通常要交叉引用（图里是口令、
  流量里是密钥）。先把所有附件各自指纹化并列表，再找关联。
- **嵌套**：`7z x` 与 `binwalk -eM` 交替用到不再出东西；`file` 每次对解出来的新文件重跑。
- **提取失败**：`binwalk -e` 依赖 7z/unsquashfs，失败时改用 `foremost` 按签名雕刻。

## 3. 多附件批量指纹（一次过）

```sh
for f in *; do
  printf '=== %s\n' "$f"; file -b "$f"; xxd -l 8 "$f"; strings -n 6 "$f" | head -5
done
```

- 先跑一遍，拿到「文件 → 类型 → 魔数 → 特征串」四列表，再决定每份附件走哪条链，别边看边猜。
- 多附件通常是组合题（图片给口令、流量给密钥、源码给算法）：两边指纹都列全了再找关联点，
  不要只盯着一个文件死磕。
- 附件名本身就是线索：`flag.zip`、`secret.png`、`dump.raw`、`capture.pcap` 直接指示方向；
  名字与内容不符时（改过扩展名）以魔数为准，`file` 会直接报出真实类型。
