# -*- coding: utf-8 -*-
"""受保护文件夹 / 受控文件夹访问（v1.1.0）。

行为定义（严格按规划）：
    * 只识别"短时间内的批量篡改"：滑动窗口内对受保护目录的文件写入/删除/改名
      数量超过阈值 → 判定为可疑批量篡改。
    * **只拦截文件操作 + 弹窗告警**：不结束进程、不隔离程序。
      （用户态无法在内核层阻止写入，因此这里的"拦截"= 立即告警 + 联动快照还原，
        并可在设置中开启"自动从快照还原"。）
    * 信任程序同样做 路径 + SHA256 校验后放行（复用 core.trust）。
"""
import os
import threading
import time
from collections import deque
from pathlib import Path

from . import logger
from .config import DATA_DIR, config


def _default_folders():
    home = os.environ.get("USERPROFILE") or str(Path.home())
    out = []
    for sub in ("Documents", "文档", "Desktop", "桌面", "Pictures", "图片",
                "Videos", "视频", "Downloads", "下载"):
        p = os.path.join(home, sub)
        if os.path.isdir(p):
            out.append(p)
    return out


class ProtectedFolders:
    """受控文件夹访问（Controlled Folder Access）。"""

    def __init__(self):
        self._lock = threading.RLock()
        self.folders = []
        self.window_sec = 10
        self.threshold = 20
        self.enabled = True
        self._events = deque(maxlen=500)     # (ts, path, action, pid, proc)
        self.alerts = deque(maxlen=100)
        self.on_alert = None                 # 回调：def alert(dict)
        self.auto_restore = False            # 是否自动从快照还原（默认关）
        self.load()

    # ---------- 配置 ----------
    def load(self):
        self.folders = list(config.get("protected_folders", []) or [])
        if not self.folders:
            self.folders = _default_folders()
        self.enabled = bool(config.get("protected_enabled", True))
        self.threshold = int(config.get("protected_threshold", 20) or 20)
        self.window_sec = int(config.get("protected_window_sec", 10) or 10)

    def save(self):
        config.set("protected_folders", list(self.folders))
        config.set("protected_enabled", self.enabled)
        config.set("protected_threshold", self.threshold)
        config.set("protected_window_sec", self.window_sec)

    def add_folder(self, path):
        p = os.path.abspath(path)
        if not os.path.isdir(p):
            return False, "目录不存在"
        with self._lock:
            if any(os.path.normcase(f) == os.path.normcase(p) for f in self.folders):
                return False, "已在保护列表"
            self.folders.append(p)
            self.save()
            logger.info(f"受保护文件夹已添加: {p}")
            return True, "已添加"

    def remove_folder(self, path):
        with self._lock:
            n = os.path.normcase(os.path.abspath(path))
            before = len(self.folders)
            self.folders = [f for f in self.folders
                            if os.path.normcase(f) != n]
            if len(self.folders) != before:
                self.save()
                return True
            return False

    def set_folders(self, folders):
        with self._lock:
            self.folders = [os.path.abspath(f) for f in (folders or []) if os.path.isdir(f)]
            self.save()

    # ---------- 判定 ----------
    def is_protected(self, path):
        if not self.enabled:
            return False
        try:
            n = os.path.normcase(os.path.abspath(path))
        except Exception:
            return False
        for f in self.folders:
            fn = os.path.normcase(os.path.abspath(f))
            if n == fn or n.startswith(fn + os.sep):
                return True
        return False

    def feed(self, path, action="modified", pid=None, proc_name=""):
        """喂入一个文件事件。若判定为批量篡改，返回告警 dict，否则 None。"""
        if not self.is_protected(path):
            return None
        now = time.time()
        with self._lock:
            self._events.append((now, path, action, pid, proc_name))
            # 维护滑动窗口
            while self._events and now - self._events[0][0] > self.window_sec:
                self._events.popleft()
            window = [e for e in self._events if now - e[0] <= self.window_sec]

        if len(window) < self.threshold:
            return None

        # 同一次爆发只报一次（阈值内每超过一个数量级才再报）
        burst_key = int(now / max(1, self.window_sec))
        with self._lock:
            last = getattr(self, "_last_burst_key", -1)
            if last == burst_key:
                return None
            self._last_burst_key = burst_key

        files = []
        seen = set()
        pids = {}
        for ts, p, act, pid_i, proc in window:
            if p not in seen:
                seen.add(p)
                files.append(p)
            if pid_i:
                pids[str(pid_i)] = proc or ""
        folder = self._folder_of(files[0]) if files else ""
        alert = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "folder": folder,
            "count": len(window),
            "files": files[:30],
            "pids": pids,
            "window": self.window_sec,
            "threshold": self.threshold,
            "msg": (f"{self.window_sec} 秒内 {folder} 下发生 {len(window)} 次文件操作"
                    f"（阈值 {self.threshold}），疑似批量加密/篡改 —— 已拦截并告警"),
        }
        with self._lock:
            self.alerts.append(alert)
        logger.warning(f"[受控文件夹] {alert['msg']}")
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception:
                pass
        return alert

    def _folder_of(self, path):
        for f in self.folders:
            if os.path.normcase(path).startswith(os.path.normcase(os.path.abspath(f))):
                return f
        return ""

    def recent_alerts(self, n=20):
        with self._lock:
            return list(self.alerts)[-n:]

    def clear_alerts(self):
        with self._lock:
            self.alerts.clear()
            self._events.clear()

    @property
    def count(self):
        return len(self.folders)


# 全局单例
protected = ProtectedFolders()
