# -*- coding: utf-8 -*-
"""进程体检：枚举当前进程，按特征库与可疑特征检测恶意进程（Windows）。"""
import os
import subprocess
import threading

from . import logger

try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    HAS_PSUTIL = False

# 已知恶意/可疑进程名（演示库，可按需扩展）
SUSPICIOUS_PROCESS = {
    "mimikatz.exe": "凭据窃取工具 Mimikatz",
    "procdump.exe": "内存转储工具（可能被用于窃密）",
    "cobaltstrike.exe": "CobaltStrike 木马",
    "beacon.exe": "CobaltStrike Beacon",
    "nc.exe": "Netcat 反向 Shell",
    "pwdump.exe": "密码抓取工具",
    "fgdump.exe": "密码抓取工具",
    "wcesp.exe": "漏洞利用工具",
    "gmer.exe": "内核 rootkit 扫描工具",
    "keylogger.exe": "键盘记录器",
}


def list_processes():
    """返回 [(pid, name, path)] 列表。"""
    out = []
    if HAS_PSUTIL:
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                out.append((info.get("pid"), info.get("name") or "", info.get("exe") or ""))
            except Exception:
                continue
    else:
        try:
            r = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, timeout=20,
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            for line in r.stdout.strip().splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                    except ValueError:
                        continue
                    out.append((pid, parts[0], ""))
        except Exception:
            pass
    return out


def scan_processes(on_item=None):
    """
    进程体检。返回 (进程数, 威胁列表)。
    威胁项: {"pid","name","path","threat"}
    """
    procs = list_processes()
    threats = []
    for pid, name, path in procs:
        base = (name or "").lower()
        if base in SUSPICIOUS_PROCESS:
            threats.append({
                "pid": pid, "name": name, "path": path,
                "threat": SUSPICIOUS_PROCESS[base],
            })
    if threats:
        logger.warning(f"进程体检发现 {len(threats)} 个可疑进程")
    return len(procs), threats


def kill_process(pid):
    """结束指定进程。返回 (ok, msg)。"""
    try:
        if HAS_PSUTIL:
            p = psutil.Process(pid)
            p.terminate()
        else:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=10)
        logger.warning(f"已结束进程 PID={pid}")
        return True, "已结束"
    except Exception as e:
        return False, str(e)
