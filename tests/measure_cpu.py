# -*- coding: utf-8 -*-
"""CPU 占用实测（ctypes 调 Windows API 采样进程 CPU 时间）。
用法: python tests/measure_cpu.py <扫描路径> <模式 low|balanced|high>
"""
import ctypes
import io
import subprocess
import sys
import time
from ctypes import wintypes

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
BASE = "C:\\Users\\admin\\Doubao\\chats\\2026-08-26\\new-chat\\ShieldPy"


def process_cpu_seconds(pid):
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = ctypes.windll.kernel32
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD),
                    ("dwHighDateTime", wintypes.DWORD)]

    ct, et, kt, ut = FILETIME(), FILETIME(), FILETIME(), FILETIME()
    ok = kernel32.GetProcessTimes(h, ctypes.byref(ct), ctypes.byref(et),
                                  ctypes.byref(kt), ctypes.byref(ut))
    kernel32.CloseHandle(h)
    if not ok:
        return None

    def to_sec(ft):
        return ((ft.dwHighDateTime << 32) | ft.dwLowDateTime) / 1e7
    return to_sec(kt) + to_sec(ut)   # kernel + user 秒


def main():
    path = sys.argv[1]
    mode = sys.argv[2]
    script = "tests\\run_scan.py"

    p = subprocess.Popen(["D:\\python\\python.exe", script, path, mode],
                         cwd=BASE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    samples = []
    prev_cpu = None
    prev_t = time.time()
    while p.poll() is None:
        cur_cpu = process_cpu_seconds(p.pid)
        now = time.time()
        if cur_cpu is not None and prev_cpu is not None:
            dt = now - prev_t
            if dt > 0:
                samples.append((cur_cpu - prev_cpu) / dt * 100.0)
        prev_cpu = cur_cpu
        prev_t = now
        time.sleep(0.15)

    out_all, _ = p.communicate()
    print(out_all.decode("utf-8", errors="replace"))
    if samples:
        avg = sum(samples) / len(samples)
        peak = max(samples)
        print(f"CPU 占用: 平均 {avg:.1f}%  峰值 {peak:.1f}%  （{len(samples)} 次采样）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
