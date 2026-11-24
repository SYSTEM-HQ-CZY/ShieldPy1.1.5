# -*- coding: utf-8 -*-
"""命令行扫描（用于 CPU 占用实测）。
用法: python tests/run_scan.py <路径> [模式 low|balanced|high]
"""
import io
import sys
import time
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from core.config import config


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else str(BASE / "tests" / "sample")
    mode = sys.argv[2] if len(sys.argv) > 2 else "balanced"
    config.set("scan_perf_mode", mode)

    from core.scanner import engine
    print(f"模式={mode} 扫描 {path}")
    t0 = time.time()
    engine.start_scan([path])
    if engine._thread:
        engine._thread.join(timeout=600)
    elapsed = time.time() - t0
    print(f"RESULT mode={mode} scanned={engine.stats['scanned']} "
          f"threats={engine.stats['threats']} hints={engine.stats['hints']} "
          f"elapsed={elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
