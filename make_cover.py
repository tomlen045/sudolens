#!/opt/homebrew/bin/python3
# sudolens 公众号封面 900x383 — 对话钩子形态（A线，不晒星数）
from PIL import Image, ImageDraw, ImageFont
import os

W, H = 900, 383
BG_TOP, BG_BOT = (11, 14, 26), (26, 15, 46)
GOLD = (240, 180, 41)
WHITE = (255, 255, 255)
GREY = (139, 148, 158)
GREEN = (63, 185, 80)

CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
MONO = "/System/Library/Fonts/Menlo.ttc"

img = Image.new("RGB", (W, H))
d = ImageDraw.Draw(img)
for y in range(H):
    t = y / H
    d.line([(0, y), (W, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(BG_TOP, BG_BOT)))

F = lambda size, mono=False: ImageFont.truetype(MONO if mono else CJK, size)

# 左金竖条锚
d.rectangle([42, 64, 50, 318], fill=GOLD)

# 栏目标签（金）
d.text((72, 60), "我是小薅薅 · 自研工具 第 11 期", font=F(19), fill=GOLD)

# 主钩子两行（白大字，右侧留出数据区）
d.text((72, 104), "AI说：sudoers里那行NOPASSWD", font=F(38), fill=WHITE)
d.text((72, 160), "没问题吧？我说：证据呢", font=F(38), fill=WHITE)

# 金句反驳（金，小字）
d.text((72, 238), "sudoers 从不出错，出错的永远是那行没人复述过的人话", font=F(21), fill=GOLD)

# 底部信息条（重点行黑衬底）
d.rectangle([72, 294, 700, 318], fill=(0, 0, 0))
d.text((80, 296), "sudolens · 9 类风险信号 · 18 项自测全绿 · 单文件零依赖", font=F(17), fill=WHITE)
d.text((72, 336), "只读解析 · 绝不改 sudoers · Gitee / GitHub 双仓开源", font=F(16), fill=GREY)

# 右侧数据区（硬指标，不晒星数）
d.text((672, 96), "9", font=F(66, mono=True), fill=GOLD)
d.text((664, 178), "类信号", font=F(22), fill=WHITE)
d.text((800, 96), "18", font=F(66, mono=True), fill=GOLD)
d.text((792, 178), "项自测", font=F(22), fill=WHITE)

out = os.path.join(os.path.expanduser("~"), "Desktop", "sudolens-cover.png")
img.save(out)
print("saved:", out)
