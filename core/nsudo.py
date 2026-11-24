# -*- coding: utf-8 -*-
"""NSudo 提权封装（v1.1.0 高级清除用）。

设计：玄盾卫士整体是用户态方案，没有内核驱动；遇到被 System/TrustedInstaller
占有的顽固文件时，借用 NSudo（开源提权启动器）以 TrustedInstaller 身份执行一次
受控命令，而不是常驻提权。

注意：NSudo 本身会被部分安全软件标记为"风险工具"，因此只在用户明确点击
"高级清除"并确认风险提示后才调用，且每条命令都完整写入日志。
"""
import os
import shutil
import subprocess
from pathlib import Path

from . import logger
from .config import BASE_DIR, DATA_DIR, config

# 常见 NSudoLC.exe 位置（含用户本机 G 盘工具箱、安装目录随附副本）
_SEARCH_PATHS = [
    Path(BASE_DIR) / "tools" / "nsudo" / "NSudoLC.exe",
    Path(BASE_DIR) / "tools" / "NSudoLC.exe",
    r"G:\陈卓一\NSudo\NSudo_8.2_All_Components\NSudo Launcher\x64\NSudoLC.exe",
    r"G:\陈卓一\NSudo\NSudo_8.2_All_Components\NSudo Launcher\Win32\NSudoLC.exe",
    r"C:\Program Files\NSudo\NSudoLC.exe",
    r"C:\Program Files\NSudo 8.2\NSudoLC.exe",
]

LOG_FILE = Path(DATA_DIR) / "advanced_clear.log"


def _candidates():
    """全部候选路径：配置项优先。"""
    out = []
    cfg_path = str(config.get("nsudo_path", "") or "").strip()
    if cfg_path:
        out.append(cfg_path)
    out.extend(str(p) for p in _SEARCH_PATHS)
    found = shutil.which("NSudoLC.exe")
    if found:
        out.append(found)
    return out


def find_nsudo():
    """返回可用的 NSudoLC.exe 绝对路径，找不到返回空串。"""
    for p in _candidates():
        try:
            if p and os.path.isfile(p):
                return p
        except Exception:
            continue
    return ""


def available():
    return bool(find_nsudo())


def _quote_arg(s):
    s = str(s)
    if not s:
        return '""'
    if any(ch in s for ch in ' \t"'):
        return '"' + s.replace('"', '""') + '"'
    return s


def run(cmdline, user="T", privileges="E", integrity="S",
        hidden=True, wait=True, timeout=120, purpose="高级清除"):
    """以 TrustedInstaller 身份执行一条命令行。

    cmdline   : 完整命令行，如  cmd.exe /c del /f /q "C:\\x.exe"
                也可以是列表 ["cmd.exe","/c","del","/f","/q","C:\\x.exe"]
    返回 (ok, msg)，其中 msg 含返回码与输出摘要（同时写日志）。
    """
    nsudo = find_nsudo()
    if not nsudo:
        logger.warn("未找到 NSudoLC.exe，高级清除不可用")
        return False, "未找到 NSudoLC.exe（请在设置中指定提权工具路径）"

    if isinstance(cmdline, (list, tuple)):
        cmdline = " ".join(_quote_arg(x) for x in cmdline)

    args = [nsudo, f"-U:{user}", f"-P:{privileges}", f"-M:{integrity}"]
    if hidden:
        args.append("-ShowWindowMode:Hide")
    if wait:
        args.append("-Wait")
    args.append(cmdline)

    started = " ".join(_quote_arg(a) for a in args)
    logger.warning(f"[{purpose}] NSudo 提权执行: {started}")
    _append_log(purpose, started)
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout,
                              universal_newlines=True,
                              creationflags=0x08000000 if os.name == "nt" else 0)
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        ok = proc.returncode == 0
        summary = f"返回码 {proc.returncode}" + (f" | {out[:300]}" if out else "")
        logger.log("OK" if ok else "WARN", f"[{purpose}] NSudo 结果: {summary}")
        _append_log(purpose, summary)
        return ok, summary
    except Exception as e:
        logger.error(f"[{purpose}] NSudo 调用异常: {e}")
        _append_log(purpose, f"异常: {e}")
        return False, f"调用异常: {e}"


def delete_file_ti(path, timeout=90):
    """以 TrustedInstaller 身份强制删除文件（含清只读属性）。"""
    if not os.path.exists(path):
        return True, "文件已不存在"
    q = _quote_arg(os.path.abspath(path))
    return run(f'cmd.exe /c attrib -r -s -h {q} & del /f /q {q}',
               timeout=timeout, purpose="删除顽固文件")


def rename_and_delete_ti(path, timeout=90):
    """先改名（破坏运行链）再删除，绕过部分自保护。"""
    if not os.path.exists(path):
        return True, "文件已不存在"
    abs_p = os.path.abspath(path)
    bak = abs_p + ".spbak"
    q = _quote_arg(abs_p)
    qb = _quote_arg(bak)
    return run(f'cmd.exe /c move /y {q} {qb} & del /f /q {qb}',
               timeout=timeout, purpose="改名后删除")


def _append_log(purpose, text):
    """高级清除全程日志（单独一份，便于事后核对）。"""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        import datetime
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{purpose}] {text}\n")
    except Exception:
        pass


def read_advanced_log(n=200):
    try:
        if not LOG_FILE.exists():
            return []
        lines = LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
        return lines[-n:]
    except Exception:
        return []
