# -*- coding: utf-8 -*-
"""System Watcher —— 系统行为采集中枢 + 加权风险打分（v1.1.0）。

采集五类行为（对标卡巴斯基 System Watcher）：
    1. 文件行为    写入 / 删除 / 改名（由实时监控 watchdog 喂入）
    2. 进程行为    新进程创建（轮询差分）
    3. 命令行      新进程命令行特征（卷影删除、关闭恢复、计划任务、解码器等）
    4. 注册表      Run / Services / 文件关联 关键键变化
    5. VSS        卷影副本删除迹象（命令行 + 卷影数量变化）

打分：每类行为带权重分，同一来源（进程/目录）在滚动窗口内累计，
超过阈值（默认 60）即判定为"勒索/破坏型行为"并发出高危告警，
可联动受保护文件夹告警与快照备份。
"""
import os
import threading
import time
from collections import deque

from . import logger
from .config import config

# ---- 命令行特征权重 ----
CMD_PATTERNS = [
    (("vssadmin", "delete", "shadows"), 75, "删除卷影副本（vssadmin）"),
    (("wmic", "shadowcopy", "delete"), 75, "删除卷影副本（wmic）"),
    (("vssadmin", "resize", "shadowstorage"), 45, "缩小卷影存储"),
    (("bcdedit", "recoveryenabled", "no"), 60, "关闭系统恢复"),
    (("wbadmin", "delete", "catalog"), 70, "删除备份目录"),
    (("wbadmin", "delete", "backup"), 70, "删除备份"),
    (("wevtutil", "cl"), 55, "清空事件日志"),
    (("schtasks", "/create"), 30, "创建计划任务（持久化）"),
    (("reg", "add"), 20, "注册表写入命令"),
    (("certutil", "-decode"), 40, "certutil 解码载荷"),
    (("certutil", "-urlcache"), 45, "certutil 下载载荷"),
    (("bitsadmin", "/transfer"), 45, "bitsadmin 下载载荷"),
    (("powershell", "-enc"), 55, "PowerShell 编码命令（隐藏执行）"),
    (("powershell", "bypass"), 50, "绕过 PowerShell 执行策略"),
    (("net", "user"), 25, "账户操作"),
    (("net", "localgroup", "administrators"), 30, "提权到管理员组"),
    (("takeown", "/f"), 15, "夺取文件所有权"),
    (("icacls", "/grant"), 15, "修改文件权限"),
    (("attrib", "-s", "-h"), 25, "清除隐藏/系统属性"),
    (("del", "/f", "/q"), 12, "静默删除文件"),
    (("curl", "-o"), 20, "命令行下载文件"),
    (("mshta", "http"), 45, "mshta 远程执行"),
    (("rundll32", "javascript"), 45, "rundll32 执行脚本"),
    (("cipher", "/w"), 40, "擦除磁盘空闲空间"),
    (("format",), 50, "格式化命令"),
]

# ---- 勒索特征扩展名 ----
RANSOM_EXT = {
    ".locked", ".locky", ".encrypted", ".enc", ".crypt", ".crypted", ".crypto",
    ".cerber", ".zepto", ".thor", ".aesir", ".wncry", ".wcry", ".wncryt",
    ".wallet", ".onion", ".paym", ".pay", ".ransom", ".readme", ".howtodecrypt",
    ".jury", ".zzzz", ".929", ".china", ".shields", ".玄盾", ".毒霸",
    ".wannacry", ".petya", ".notpetya", ".badrabbit", ".conti", ".lockbit",
    ".blackcat", ".hive", ".royal", ".akira", ".babuk", ".ragnar",
}

# 勒索信常见文件名关键词
RANSOM_NOTE_KEYWORDS = ("how to decrypt", "decrypt", "readme", "restore files",
                        "your files", "比特币", "btc", "付钱", "恢复文件")

DEFAULT_THRESHOLD = 60


class WatchEvent:
    def __init__(self, kind="", detail="", score=0, path="", pid=None,
                 proc="", cmdline="", source=""):
        self.kind = kind
        self.detail = detail
        self.score = score
        self.path = path
        self.pid = pid
        self.proc = proc
        self.cmdline = cmdline
        self.source = source or (str(pid) if pid else (path or "system"))
        self.time = time.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return {"time": self.time, "kind": self.kind, "detail": self.detail,
                "score": self.score, "path": self.path, "pid": self.pid,
                "proc": self.proc, "cmdline": self.cmdline}


class SystemWatcher:
    def __init__(self):
        self._lock = threading.RLock()
        self.events = deque(maxlen=300)
        self.alerts = deque(maxlen=100)
        self._scores = {}                 # source -> deque[(ts, score, detail)]
        self.threshold = int(config.get("ransomware_threshold", DEFAULT_THRESHOLD) or DEFAULT_THRESHOLD)
        self.window_sec = 60
        self.enabled = bool(config.get("ransomware_enabled", True))
        self.on_alert = None
        self.on_file_burst = None
        self._file_ops = {}               # dir -> deque[ts]
        self._proc_snapshot = {}          # pid -> (name, exe, cmdline)
        self._first_tick = True
        self.file_burst_count = 0
        self.file_burst_window = 10
        self.file_burst_threshold = 25

    # ---------- 采样入口 ----------
    def feed_file(self, path, action="modified", pid=None, proc=""):
        """文件行为（watchdog 事件）。"""
        if not self.enabled:
            return None
        ext = os.path.splitext(path or "")[1].lower()
        score, detail = 0, ""
        if ext in RANSOM_EXT:
            score, detail = 70, f"勒索特征扩展名 {ext}"
        else:
            base = os.path.basename(path or "").lower()
            if any(k in base for k in RANSOM_NOTE_KEYWORDS):
                score, detail = 55, "疑似勒索说明文件"
            if action == "deleted":
                score = score or 8
                detail = detail or "文件被删除"

        # 目录级批量操作计数（同一目录滚动窗口）
        try:
            d = os.path.dirname(os.path.abspath(path))
        except Exception:
            d = ""
        burst = 0
        if d:
            with self._lock:
                q = self._file_ops.setdefault(d, deque(maxlen=200))
                now = time.time()
                q.append(now)
                while q and now - q[0] > self.file_burst_window:
                    q.popleft()
                burst = len(q)
            if burst >= self.file_burst_threshold:
                score += 40
                detail = (detail + "；" if detail else "") + \
                    f"{self.file_burst_window}秒内同目录 {burst} 次文件操作（疑似批量加密）"

        if score <= 0:
            return None
        ev = WatchEvent("file", detail, score, path=path, pid=pid, proc=proc)
        return self._record(ev)

    def feed_process(self, pid, name="", exe="", cmdline=""):
        """进程行为（新进程或命令行特征）。"""
        if not self.enabled:
            return None
        score, detail = 0, []
        cl = (cmdline or "").lower()
        for pats, w, desc in CMD_PATTERNS:
            hit = all(p in cl for p in pats) if len(pats) > 1 else (pats[0] in cl)
            if hit:
                score += w
                detail.append(desc)
        # 从可疑目录启动
        exe_l = (exe or "").lower()
        for d in ("\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\"):
            if d in exe_l:
                score += 12
                detail.append("进程从临时/下载目录启动")
                break
        if score <= 0:
            return None
        ev = WatchEvent("process", "；".join(detail), score, pid=pid,
                        proc=name or os.path.basename(exe or ""),
                        cmdline=(cmdline or "")[:400], path=exe)
        return self._record(ev)

    def feed_registry(self, key="", name="", value="", action="added"):
        """注册表关键键变化。"""
        if not self.enabled:
            return None
        score, detail = 0, ""
        kl = (key or "").lower()
        if "\\run" in kl or "runonce" in kl:
            score, detail = 20, f"自启动项{'新增' if action == 'added' else '变化'}：{name}"
        elif "\\services\\" in kl or kl.endswith("\\services"):
            score, detail = 15, f"服务配置变化：{name}"
        elif "currentversion\\explorer\\fileexts" in kl:
            score, detail = 10, f"文件关联变化：{name}"
        if score <= 0:
            return None
        ev = WatchEvent("registry", detail, score, path=value)
        return self._record(ev)

    def feed_vss(self, detail="卷影副本数量减少", count_before=0, count_after=0):
        """VSS 卷影副本变化。"""
        if not self.enabled:
            return None
        score = 70 if count_before and count_after < count_before else 40
        ev = WatchEvent("vss", f"{detail}（{count_before} → {count_after}）", score)
        return self._record(ev)

    def tick_processes(self):
        """轮询进程差分，检测新进程。返回新进程事件列表。"""
        if not self.enabled:
            return []
        try:
            import psutil
        except Exception:
            return []
        seen = {}
        new_events = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                info = proc.info
                pid = info.get("pid")
                if not pid:
                    continue
                seen[pid] = (info.get("name") or "", info.get("exe") or "")
                if pid not in self._proc_snapshot and not self._first_tick:
                    cmdline = ""
                    try:
                        cmdline = " ".join(proc.cmdline() or [])
                    except Exception:
                        cmdline = ""
                    ev = self.feed_process(pid, info.get("name") or "",
                                           info.get("exe") or "", cmdline)
                    if ev:
                        new_events.append(ev)
            except Exception:
                continue
        self._proc_snapshot = seen
        self._first_tick = False
        return new_events

    # ---------- 打分与告警 ----------
    def _record(self, ev):
        with self._lock:
            self.events.append(ev)
            q = self._scores.setdefault(ev.source, deque(maxlen=100))
            now = time.time()
            q.append((now, ev.score, ev.detail))
            while q and now - q[0][0] > self.window_sec:
                q.popleft()
            total = sum(x[1] for x in q)

        logger.info(f"[SystemWatcher] {ev.kind} +{ev.score} ({ev.detail}) "
                    f"累计={min(total, 200)} 源={ev.source[:60]}")

        if total >= self.threshold:
            detail_sample = [x[2] for x in list(q)[-4:]]
            alert = {
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "score": total,
                "threshold": self.threshold,
                "source": ev.source,
                "pid": ev.pid,
                "proc": ev.proc,
                "cmdline": ev.cmdline,
                "path": ev.path,
                "kind": ev.kind,
                "behaviors": detail_sample,
                "msg": (f"风险评分 {total} 超过阈值 {self.threshold}："
                        + "；".join(detail_sample)),
            }
            with self._lock:
                last = self.alerts[-1] if self.alerts else None
                if last and last.get("source") == alert["source"] and \
                        last.get("time") == alert["time"]:
                    return ev
                self.alerts.append(alert)
            logger.warning(f"[SystemWatcher 高危] {alert['msg']}")
            if self.on_alert:
                try:
                    self.on_alert(alert)
                except Exception:
                    pass
        return ev

    # ---------- 查询 ----------
    def recent(self, n=50):
        with self._lock:
            return list(self.events)[-n:][::-1]

    def recent_alerts(self, n=20):
        with self._lock:
            return list(self.alerts)[-n:]

    def clear(self):
        with self._lock:
            self.events.clear()
            self.alerts.clear()
            self._scores.clear()
            self._file_ops.clear()

    def score_of(self, source):
        q = self._scores.get(source)
        if not q:
            return 0
        now = time.time()
        return sum(x[1] for x in q if now - x[0] <= self.window_sec)

    @property
    def stats(self):
        return {"events": len(self.events), "alerts": len(self.alerts),
                "threshold": self.threshold, "enabled": self.enabled}


# 全局单例
watcher = SystemWatcher()
