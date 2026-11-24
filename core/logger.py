# -*- coding: utf-8 -*-
"""轻量日志模块：滚动写文件 + 内存环形缓冲（供 GUI 日志页读取）。"""
import datetime
import os
import threading
from collections import deque
from pathlib import Path

from .config import LOGS_DIR

LOG_FILE = Path(LOGS_DIR) / "shieldpy.log"
_MAX_MEM = 500
_lock = threading.Lock()
_buffer = deque(maxlen=_MAX_MEM)


def _fmt():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(level: str, msg: str):
    line = f"[{_fmt()}] [{level}] {msg}"
    with _lock:
        _buffer.append(line)
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + os.linesep)
        except Exception:
            pass


def info(msg):
    log("INFO", msg)


def warn(msg):
    log("WARN", msg)


def warning(msg):
    log("WARN", msg)


def error(msg):
    log("ERROR", msg)


def success(msg):
    log("OK", msg)


def recent(n=200):
    with _lock:
        return list(_buffer)[-n:]


def flush_log_file():
    """日志文件超过 2MB 时截断为最近 500 行。"""
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 2 * 1024 * 1024:
            lines = recent(500)
            LOG_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass
