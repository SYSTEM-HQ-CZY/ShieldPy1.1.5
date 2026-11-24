# -*- coding: utf-8 -*-
"""进度条调试：验证单次扫描进度是否单调、并发启动是否导致乱跳。
用法: python tests/progress_debug.py
"""
import io
import sys
import time
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from core.scanner import engine


def test_single():
    """单次扫描：进度是否单调？"""
    seq = []
    engine.on_progress = lambda p, t, fp: seq.append((p, t))
    engine.start_scan([str(BASE / "tests" / "sample")])
    if engine._thread:
        engine._thread.join(timeout=120)
    mono = all(b[0] >= a[0] for a, b in zip(seq, seq[1:]))
    pcts = [round(p / t * 100, 1) for p, t in seq]
    print(f"[单次扫描] {len(seq)} 次进度回调, 单调递增: {mono}")
    print(f"  进度序列: {pcts[:20]}")
    return mono


def test_double_start():
    """连续两次 start_scan（模拟跨页重复开始扫描）：进度是否混乱？"""
    engine.on_progress = lambda p, t, fp: progress_log.append((p, t))
    engine.start_scan([str(BASE / "tests" / "sample")])
    time.sleep(0.05)
    engine.start_scan([str(BASE / "tests" / "sample")])   # 第二个线程可能并发
    if engine._thread:
        engine._thread.join(timeout=120)
    time.sleep(0.5)
    pcts = [round(p / t * 100, 1) for p, t in progress_log]
    mono = all(b[0] >= a[0] for a, b in zip(progress_log, progress_log[1:]))
    print(f"[并发启动] {len(progress_log)} 次进度回调, 单调递增: {mono}")
    print(f"  进度序列: {pcts[:30]}")
    return mono


progress_log = []
if __name__ == "__main__":
    test_single()
    print("---")
    test_double_start()
