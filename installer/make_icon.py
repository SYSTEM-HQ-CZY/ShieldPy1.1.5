# -*- coding: utf-8 -*-
"""把生成的 PNG 图标转换为多尺寸 ICO。
用法: python installer/make_icon.py
"""
import sys
from pathlib import Path

from PIL import Image

BASE = Path(__file__).resolve().parent.parent
ICON_DIR = BASE / "installer"
SRC = ICON_DIR / "shield_icon.png"
OUT = ICON_DIR / "shield_icon.ico"


def main():
    img = Image.open(SRC).convert("RGBA")
    # 统一裁成正方形，去掉背景外扩
    w, h = img.size
    s = min(w, h)
    img = img.crop(((w - s) // 2, (h - s) // 2, (w + s) // 2, (h + s) // 2))

    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(OUT, format="ICO", sizes=sizes)
    print(f"[OK] ICO 已生成: {OUT} ({img.size[0]}x{img.size[1]})")
    print(f"     包含尺寸: {[s[0] for s in sizes]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
