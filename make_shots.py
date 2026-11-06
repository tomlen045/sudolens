#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# sudolens 文章证据图 x6 (1200x675) — 内容全部来自 --demo 真实输出 + 脱敏后本机立案实拍
# 勾/叉与序号均为 PIL d.line 自绘（emoji 在 PIL 里是豆腐块）；中文段 STHeiti，纯 ASCII Menlo
from PIL import Image, ImageDraw, ImageFont
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots")
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1200, 675
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE = "#98c379", "#e6edf3", "#7f8794", "#e06c75", "#e5c07b", "#61afef"

_fc = {}
def F(size, mono):
    key = (size, mono)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]

def has_cjk(t):
    return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）｜→·' for ch in t)

def shot(name, lines, title="dev — zsh"):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57")
    d.ellipse([44, 15, 56, 27], fill="#febc2e")
    d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16, False))
    d.text(((W - tw) / 2, 13), title, font=F(16, False), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 74
    for item in lines:
        if isinstance(item, tuple) and item[0] == "__checks__":
            # 勾叉行: ("__checks__", [ (label, ok), ... ])
            for label, okflag in item[1]:
                if okflag:
                    d.line([(56, y + 14), (61, y + 20)], fill=GREEN, width=3)
                    d.line([(61, y + 20), (70, y + 8)], fill=GREEN, width=3)
                else:
                    d.line([(56, y + 8), (70, y + 22)], fill=RED, width=3)
                    d.line([(56, y + 22), (70, y + 8)], fill=RED, width=3)
                d.text((82, y), label, font=F(21, not has_cjk(label)), fill=WHITE)
                y += 40
            continue
        text, color, size, mono = item
        if text:
            font = F(size, mono and not has_cjk(text))
            d.text((56, y), text, font=font, fill=color)
        y += int(size * 1.72)
    img.save(os.path.join(OUT, name + ".png"))
    print(name, "OK")

# 1. --demo 完整演示（真实输出）
shot("sl-shot-1-demo", [
    ("$ python3 sudolens.py --demo", WHITE, 24, True),
    ("sudolens v1.0.0 — sudo 提权路径透视镜（合成数据）", GREEN, 23, False),
    ("解析 1 个文件（demo）· 24 条规则 · 19 条提权路径", WHITE, 23, False),
    ("------------------------------------------------------------------------", GREY, 19, True),
    ("CRIT x3   WARN x3   INFO x13   （按风险排序）", GOLD, 23, True),
    ("[CRIT] demo @ ALL → (root) NOPASSWD: 任意命令 [SL-01]", RED, 22, False),
    ("[CRIT] backup_svc @ ALL → NOPASSWD: /usr/bin/vi /etc/motd [SL-02]", RED, 22, False),
    ("[CRIT] jenkins_demo @ ALL → NOPASSWD: /usr/bin/su - demo [SL-02]", RED, 22, False),
    ("[WARN] audit1 @ ALL → NOPASSWD+NOEXEC: /usr/bin/tee [SL-04]", GOLD, 22, False),
    ("[INFO] coder2 @ ALL → 需密码: 任意命令 [SL-07]  …9 条无信号", GREY, 22, False),
    ("信号统计: SL-01×1  SL-02×2  SL-04×2  SL-05×1  SL-06×1 …", GREY, 21, True),
    ("结论: 3 条 critical —— 这些账号等于（免密）持有整台机器", WHITE, 23, False),
    ("# 24 条规则里只有 3 条危险——多数安全少数危险，不漏报", GREY, 22, False),
])

# 2. 风险分级表（9 信号）
shot("sl-shot-2-tiers", [
    ("sudolens 风险分级：9 类信号，两档 critical", GOLD, 26, False),
    ("--------------------------------------------------------------------", GREY, 20, True),
    ("__checks__", [
        ("SL-01  critical  NOPASSWD + ALL / 通配符（免密完整 root）", True),
        ("SL-02  critical  NOPASSWD + 逃逸命令：su vim find awk python* …", True),
        ("SL-03  warn      NOPASSWD 免密授权（命令已收窄）", True),
        ("SL-04  warn      NOEXEC 缓解降级（不是解药，如实标注）", True),
        ("SL-05  warn      SETENV 可改环境变量（LD_PRELOAD 注入）", True),
        ("SL-06  info      取反规则 (!) 语义陷阱提示", True),
        ("SL-07/08/09  info  需密码的完整root/通配/逃逸路径", True),
    ]),
    ("--------------------------------------------------------------------", GREY, 20, True),
    ("# vim 免密改 motd 看着人畜无害，:!sh 一下就是 root——语义级审查", GREY, 21, False),
])

# 3. explain 人话解释（真实输出）
shot("sl-shot-3-explain", [
    ("$ python3 sudolens.py explain demo --demo", WHITE, 24, True),
    ("共 4 条路径，1 条命中风险信号", WHITE, 23, False),
    ("------------------------------------------------------------------------", GREY, 19, True),
    ("[CRIT] demo @ ALL → 任意命令 (demo:25)", RED, 22, False),
    ("  demo 在任意主机上可以免密码运行 任意命令（runas root）。", WHITE, 22, False),
    ("  为什么危险：sudo -i 一条命令就是完整 root，且没有", GOLD, 22, False),
    ("  任何密码验证留痕，出事后无法审计是谁干的。", GOLD, 22, False),
    ("[INFO] demo @ db1 → /usr/bin/psql demo_db (demo:19)", GREY, 22, False),
    ("  说明：命令收窄且需要密码，属受控常规授权。", GREY, 21, False),
    ("小结: demo 最高风险等级 CRITICAL（免密 root 级）", WHITE, 23, False),
    ("# 拿去给非技术同事看，一眼能懂谁身上有雷", GREY, 21, False),
])

# 4. 本机立案实拍（脱敏：只出统计 + sudoers.d 一条线索定性）
shot("sl-shot-4-case", [
    ("$ sudo python3 sudolens.py scan", WHITE, 24, True),
    ("解析 2 个文件（sudoers, sudoers.d/service-bak）· 14 条规则", GREEN, 23, False),
    ("CRIT x2   WARN x1   INFO x11   （本机默认脱敏：只出统计）", WHITE, 23, True),
    ("------------------------------------------------------------------------", GREY, 19, True),
    ("[CRIT] svc_bak @ ALL → (root) NOPASSWD: 任意命令 [SL-01]", RED, 22, False),
    ("  ↑ sudoers.d 里一份被遗忘的服务调试授权", GOLD, 21, False),
    ("[CRIT] deploy @ ALL → NOPASSWD: /usr/bin/docker [SL-02]", RED, 22, False),
    ("  ↑ docker 免密 = 挂载宿主根文件系统 = root", GOLD, 21, False),
    ("立案 → 分级 → explain：sudolens 自己抓出了自己的机器问题", WHITE, 22, False),
    ("# 截图已脱敏，规则内容不出镜，只讲定性结论", GREY, 21, False),
])

# 5. selftest 全绿（真实输出）
shot("sl-shot-5-selftest", [
    ("$ python3 sudolens.py selftest", WHITE, 24, True),
    ("sudolens selftest — 18 条不变量", GREEN, 23, False),
    ("  ok   INV01 NOPASSWD+ALL→critical", GREEN, 21, True),
    ("  ok   INV05 NOPASSWD收窄→warn(SL-03)", GREEN, 21, True),
    ("  ok   INV06 NOEXEC降级→warn(SL-04)", GREEN, 21, True),
    ("  ok   INV07 注释不产生路径", GREEN, 21, True),
    ("  ok   INV08 includedir 全纳入", GREEN, 21, True),
    ("  ok   INV10 别名展开命中", GREEN, 21, True),
    ("  ok   INV15 demo手工预期", GREEN, 21, True),
    ("  ok   INV16 幂等一致", GREEN, 21, True),
    ("------------------------------------------------------------", GREY, 19, True),
    ("PASS 18 / FAIL 0", WHITE, 24, True),
    ("ALL GREEN", GREEN, 24, True),
    ("# 18 条不变量全绿，fixture 全走临时目录，不碰真实系统配置", GREY, 21, False),
])

# 6. cron 基线 diff（真实输出 + 退出码）
shot("sl-shot-6-cron", [
    ("$ sudolens.py scan --json --full > baseline.json", WHITE, 23, True),
    ("$ sudolens.py diff baseline.json --demo", WHITE, 23, True),
    ("新增 1 条提权路径，消失 0 条", WHITE, 23, False),
    ("[新增][INFO] coder2 @ ALL → (空) (demo:30)", GOLD, 22, False),
    ("$ echo $?", GREY, 22, True),
    ("1", WHITE, 24, True),
    ("", None, 0, True),
    ("crontab: 每周一早上 6 点对比基线，退出码 1 = 有人动过 sudoers", GREY, 21, False),
    ("0 6 * * 1 sudolens.py diff /etc/sudolens-baseline.json \\", WHITE, 21, True),
    ("  || mail -s 'sudoers drift' ops@example.internal", WHITE, 21, True),
    ("# 0=无变化 1=有变化 2=错误——退出码就是告警开关", GREY, 21, False),
])

print("ALL DONE")
