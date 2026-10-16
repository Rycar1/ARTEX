package server

import "testing"

// 「无靶机任务拒跑」的目标识别回归测试。事故原型:CTF 任务建任务时丢了靶机入口
// (描述里没有【靶机】段),worker 于是去翻平台数据目录、扫自家宿主机 45 分钟。
// 判定必须「宁可漏判也不误杀」:文件名 / 产品名不能被当成目标,否则合法任务会被拒跑。

func TestTextHasTargetRecognizesRealTargets(t *testing.T) {
	cases := []string{
		"ISCTF2025 比赛题 #1175《ezrce》\n【靶机】\n入口: challenge.imxbt.cn:32452(端口 32452)",
		"目标 https://portal.example.com/login",
		"内网 10.1.1.5 的 8080 端口",
		"靶场域名 jwgl.demo-univ.edu.cn,已在本机 hosts 映射",
		"扫描 172.22.160.164 全端口",
		"目标站点 target.io",
	}
	for _, c := range cases {
		if !textHasTarget(c) {
			t.Errorf("应识别出目标: %q", c)
		}
	}
}

// 静态附件题(逆向/取证/病毒分析)没有网络目标,只有附件 —— 描述里的显式声明段
// 必须算「有目标」,否则 5 道 re 题会被「无靶机拒跑」全部误杀。
func TestTextHasTargetAcceptsExplicitDeclarations(t *testing.T) {
	cases := []string{
		"ISCTF2025 比赛题 #1155《ELF》(re 方向,难度见题面)。\n\n【题面】\n这个elf有点奇怪呢\n\n【附件】\n题目附件已放在本任务工作目录的 uploads/ 下: 1155_main.zip(6067910 字节)。\n先用 ls uploads/ 确认,再按需解包/分析。\n\n【flag 格式】ISCTF{}",
		"【靶机】本地附件题(无网络目标),样本在 uploads/ 下",
		"【样本】main.exe,离线分析",
		"离线题:分析 uploads/RC4.zip",
		"attachment-only challenge, analyze the provided ELF",
	}
	for _, c := range cases {
		if !textHasTarget(c) {
			t.Errorf("显式声明应算有目标: %q", c)
		}
	}
}

func TestTextHasTargetRejectsNonTargets(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"在隔离的 CTF 比赛环境中解出这道题并拿到 flag。flag 格式:ISCTF{}。",
		"ISCTF2025 比赛题 #1175《ezrce》(web 方向,难度见题面)。出题人:f1@g",
		"读 uploads/main.zip 并用 checksec 看保护",
		"分析 main2.hdr 与 pl.body 这两个响应头文件",
		"读取 404.shtml 的内容",
		"版本号 1.2.3 与 go1.26.3",
	}
	for _, c := range cases {
		if textHasTarget(c) {
			t.Errorf("不应识别为目标: %q", c)
		}
	}
}
