# -*- coding: utf-8 -*-
"""误报实测：真实系统正常脚本 vs 恶意样本。
用法: python tests/test_false_positive.py
"""
import io
import os
import sys
import time
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from core.scanner import engine
from core.heuristics import detect_script_threat, read_text_safe


def collect_scripts(roots, exts, limit=400):
    """收集真实系统里的脚本文件。"""
    out = []
    skip = ("node_modules", ".git", "__pycache__", "site-packages")
    for root in roots:
        if not Path(root).exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in skip]
            for fn in filenames:
                if len(out) >= limit:
                    break
                if fn.lower().endswith(exts):
                    out.append(os.path.join(dirpath, fn))
            if len(out) >= limit:
                break
    return out


def main():
    print("=" * 60)
    print("A. 恶意样本（应检出）")
    print("=" * 60)
    sample = BASE / "tests" / "sample"
    for f in sorted(sample.iterdir()):
        item = engine.scan_file(str(f))
        if item:
            print(f"  [检出] {f.name}: {item.detection} / {item.severity}")
        else:
            print(f"  [安全] {f.name}")

    print()
    print("=" * 60)
    print("B. 真实系统正常脚本（不应误报）")
    print("=" * 60)
    roots = [
        "D:\\python\\Lib",          # Python 标准库
        "C:\\Windows\\System32",     # Windows 系统脚本
    ]
    exts = (".py", ".cmd", ".bat", ".ps1")
    files = collect_scripts(roots, exts)
    fp = []
    total = 0
    for f in files:
        try:
            ext = Path(f).suffix.lower()
            if ext not in (".py", ".cmd", ".bat", ".ps1"):
                continue
            text = read_text_safe(Path(f))
            if not text:
                continue
            total += 1
            name, desc, sev = detect_script_threat(None, text, ext)
            if name and sev in ("high", "medium"):
                fp.append((f, name, sev))
        except Exception:
            continue
    print(f"  测试 {total} 个真实脚本")
    if fp:
        print(f"  ⚠ 误报 {len(fp)} 个:")
        for f, name, sev in fp[:20]:
            print(f"    - {f}  ({name}/{sev})")
    else:
        print("  ✓ 0 误报")

    print()
    print("=" * 60)
    print("C. 扫描性能（balanced 模式，测试样本目录）")
    print("=" * 60)
    engine.start_scan([str(sample)])
    if engine._thread:
        engine._thread.join(timeout=60)
    print(f"  扫描 {engine.stats['scanned']} 个文件，耗时 {engine.stats.get('elapsed', 0)}s，"
          f"威胁 {engine.stats['threats']}，提示 {engine.stats['hints']}")

    return 0 if not fp else 1


if __name__ == "__main__":
    sys.exit(main())
