# -*- coding: utf-8 -*-
"""进程终止器（v1.1.0）：处置链路第一环。

要求：先终止恶意进程及其**全部子进程**，再动文件 —— 否则文件被占用、
或者父进程会立刻把孩子重新拉起来（典型双击型木马行为）。
"""
import os
import subprocess

from . import logger

try:
    import psutil
    HAS_PSUTIL = True
except Exception:
    HAS_PSUTIL = False


def _children(pid):
    """递归取所有子进程 PID（先深后浅，保证先杀叶子）。"""
    if not HAS_PSUTIL:
        return []
    try:
        p = psutil.Process(pid)
        kids = p.children(recursive=True)
        return [k.pid for k in kids]
    except Exception:
        return []


def kill_pid(pid, force=True):
    if not HAS_PSUTIL:
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=10)
            return True, "已结束（taskkill）"
        except Exception as e:
            return False, str(e)
    try:
        p = psutil.Process(pid)
        p.kill() if force else p.terminate()
        return True, f"已结束 PID={pid} ({p.name()})"
    except Exception as e:
        return False, str(e)


def kill_tree(pid, exclude=None):
    """终止进程树：先子后父。返回 (ok_count, messages)。"""
    exclude = set(exclude or ())
    if pid in exclude or pid == os.getpid():
        return 0, ["跳过自身进程"]
    killed, msgs = 0, []
    for child_pid in reversed(_children(pid)):
        if child_pid in exclude:
            continue
        ok, msg = kill_pid(child_pid)
        if ok:
            killed += 1
        msgs.append(msg)
    ok, msg = kill_pid(pid)
    if ok:
        killed += 1
    msgs.append(msg)
    if killed:
        logger.warning(f"已终止进程树 PID={pid}，共 {killed} 个进程")
    return killed, msgs


def processes_with_path(path):
    """找出可执行路径等于（或位于）目标路径的进程 PID 列表。"""
    out = []
    if not HAS_PSUTIL:
        return out
    try:
        target = os.path.normcase(os.path.abspath(path))
    except Exception:
        return out
    for proc in psutil.process_iter(["pid", "exe", "name"]):
        try:
            exe = proc.info.get("exe") or ""
            if not exe:
                continue
            if os.path.normcase(os.path.abspath(exe)) == target:
                out.append(proc.pid)
        except Exception:
            continue
    return out


def terminate_holders(path, extra_pids=None):
    """终止占用目标文件的进程（按 exe 路径匹配 + 调用方指定 PID）。
    返回 (killed, msgs)。"""
    pids = set(processes_with_path(path))
    for p in (extra_pids or []):
        try:
            pids.add(int(p))
        except Exception:
            pass
    killed, msgs = 0, []
    for pid in sorted(pids):
        k, m = kill_tree(pid)
        killed += k
        msgs.extend(m)
    return killed, msgs


def list_processes():
    """[(pid, name, path)]"""
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
            r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=20,
                               creationflags=0x08000000)
            for line in r.stdout.strip().splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    try:
                        out.append((int(parts[1]), parts[0], ""))
                    except ValueError:
                        continue
        except Exception:
            pass
    return out
