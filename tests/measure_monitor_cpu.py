# -*- coding: utf-8 -*-
"""全盘防护 CPU 实测：启动 watchdog 全盘监控，采样进程 CPU。
用法: python tests/measure_monitor_cpu.py
"""
import ctypes
import io
import sys
import time
from ctypes import wintypes
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))


def cpu_seconds():
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = ctypes.windll.kernel32
    pid = ctypes.windll.kernel32.GetCurrentProcessId()
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD),
                    ("dwHighDateTime", wintypes.DWORD)]

    ct, et, kt, ut = FILETIME(), FILETIME(), FILETIME(), FILETIME()
    kernel32.GetProcessTimes(h, ctypes.byref(ct), ctypes.byref(et),
                             ctypes.byref(kt), ctypes.byref(ut))
    kernel32.CloseHandle(h)

    def to_sec(ft):
        return ((ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 1e7
    return to_sec(kt) + to_sec(ut)


def main():
    from core.monitor import monitor
    ok, msg = monitor.start()
    print(f"全盘防护启动: {ok} / {msg}")
    if not ok:
        return 1
    dirs = getattr(monitor, "_dirs", [])
    print(f"监控范围: {dirs}")
    # 采样 12 秒
    samples = []
    prev = cpu_seconds()
    t0 = time.time()
    while time.time() - t0 < 12:
        time.sleep(1.0)
        cur = cpu_seconds()
        now = time.time()
        samples.append((cur - prev) / 1.0 * 100.0)
        prev = cur
    monitor.stop()
    avg = sum(samples) / len(samples)
    peak = max(samples)
    print(f"空闲 CPU 占用: 平均 {avg:.1f}%  峰值 {peak:.1f}%  （{len(samples)} 次采样）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
