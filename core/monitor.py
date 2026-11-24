# -*- coding: utf-8 -*-
"""主动防御引擎 v1.1.0（System Watcher 中枢）。

组成：
  1. 文件实时监控    watchdog 事件驱动（无 watchdog 时降级轮询）→ 新文件自动扫描
  2. 威胁自动处置    按策略：仅告警 / 自动隔离 / 自动删除（走完整处置链路）
  3. 自启动项监控    注册表 Run/RunOnce + 启动文件夹 快照对比
  4. hosts 保护      hosts 文件 size+mtime 变化告警
  5. System Watcher  文件/进程/命令行/注册表/VSS 行为加权打分（见 core.systemwatcher）
  6. 受保护文件夹    批量篡改检测（只告警，不杀进程）
  7. 勒索联动        高危评分 → 记录告警，可按设置自动创建快照

所有事件写入 data/defense.log 并保存在内存 events（防御中心展示）。
"""
import os
import subprocess
import threading
import time
from collections import deque

from . import logger, protected as protected_mod, residue, scanner, systemwatcher as watcher_mod
from .config import config

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except Exception:
    Observer = None
    FileSystemEventHandler = object
    HAS_WATCHDOG = False


class DefenseEvent:
    def __init__(self, kind="", level="info", title="", detail="", path="",
                 time_str=""):
        self.kind = kind
        self.level = level          # info / warn / high
        self.title = title
        self.detail = detail
        self.path = path
        self.time = time_str or time.strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        return {"time": self.time, "kind": self.kind, "level": self.level,
                "title": self.title, "detail": self.detail, "path": self.path}


if HAS_WATCHDOG:
    class _Handler(FileSystemEventHandler):
        """watchdog 事件处理器 —— 注意必须调 self._parent（历史 bug 已修）。"""

        def __init__(self, parent):
            self._parent = parent
            super().__init__()

        def _push(self, event, action):
            try:
                self._parent._on_fs_event(getattr(event, "src_path", ""), action)
            except Exception:
                pass

        def on_created(self, event):
            if not event.is_directory:
                self._push(event, "created")

        def on_modified(self, event):
            if not event.is_directory:
                self._push(event, "modified")

        def on_deleted(self, event):
            if not event.is_directory:
                self._push(event, "deleted")

        def on_moved(self, event):
            if not event.is_directory:
                self._push(event, "moved")
                try:
                    self._parent._on_fs_event(getattr(event, "dest_path", ""), "created")
                except Exception:
                    pass


class RealtimeMonitor:
    def __init__(self):
        self.events = deque(maxlen=200)
        self.running = False
        self.scope = "full"
        self.current_dirs = []
        self._observer = None
        self._aux_thread = None
        self._stop_flag = threading.Event()
        self._poll_thread = None
        self._lock = threading.Lock()
        self._recent = {}          # path -> ts 去抖
        self._startup_snapshot = None
        self._hosts_sig = None
        self._vss_count = None
        self._last_vss_check = 0.0
        self.on_event = None       # UI 回调 def cb(DefenseEvent)
        self.paused = False
        self.stats = {"scanned": 0, "threats": 0, "disposed": 0}

    # ---------------- 目录枚举 ----------------
    def all_drives(self):
        """全部需要监控的磁盘（固定盘 + 可移动盘）。"""
        out = scanner.fixed_drives()
        try:
            out.extend([d for d in scanner.removable_drives() if d not in out])
        except Exception:
            pass
        return out

    def key_dirs(self):
        """降级方案：只监控关键目录。"""
        dirs = []
        for env in ("TEMP", "TMP", "APPDATA", "USERPROFILE", "LOCALAPPDATA",
                    "ProgramData", "PUBLIC"):
            v = os.environ.get(env)
            if v and os.path.isdir(v):
                dirs.append(v)
        windir = os.environ.get("WINDIR", r"C:\Windows")
        for sub in ("Temp", "System32\\Tasks"):
            p = os.path.join(windir, sub)
            if os.path.isdir(p):
                dirs.append(p)
        home = os.environ.get("USERPROFILE") or ""
        for sub in ("Desktop", "桌面", "Downloads", "下载", "Documents", "文档"):
            p = os.path.join(home, sub)
            if os.path.isdir(p):
                dirs.append(p)
        seen, out = set(), []
        for d in dirs:
            k = os.path.normcase(d)
            if k not in seen:
                seen.add(k)
                out.append(d)
        return out

    # ---------------- 启动 / 停止 ----------------
    def start(self, dirs=None, scope=None):
        if self.running:
            return True, "已经在运行"
        scope = scope or config.get("realtime_scope", "full") or "full"
        if scope == "custom":
            target = list(dirs or config.get("realtime_dirs", []) or self.key_dirs())
        else:
            target = self.all_drives() or self.key_dirs()
        target = [d for d in target if os.path.isdir(d)]
        if not target:
            return False, "没有可监控的目录"
        self.scope = scope
        self.current_dirs = target
        self._stop_flag.clear()
        self.paused = False

        if HAS_WATCHDOG:
            try:
                self._observer = Observer()
                handler = _Handler(self)
                for d in target:
                    try:
                        self._observer.schedule(handler, d, recursive=True)
                    except Exception as e:
                        logger.warn(f"监控目录失败 {d}: {e}")
                self._observer.daemon = True
                self._observer.start()
            except Exception as e:
                logger.error(f"watchdog 启动失败，降级轮询: {e}")
                self._observer = None

        if not self._observer:
            self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._poll_thread.start()

        self._aux_thread = threading.Thread(target=self._aux_loop, daemon=True)
        self._aux_thread.start()

        self.running = True
        self.add_event(DefenseEvent(
            kind="system", level="info", title="实时防护已启动",
            detail=f"{'全盘' if scope == 'full' else '自定义'}监控，"
                   f"{len(target)} 个位置，"
                   f"引擎={'watchdog' if self._observer else '轮询'}"
                   f"，自动处置={config.get('realtime_auto_action', 'quarantine')}"))
        logger.warning(f"实时防护已启动（scope={scope}, {len(target)} 个目录）")
        return True, f"已启动（{len(target)} 个位置）"

    def stop(self):
        self._stop_flag.set()
        self.running = False
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass
            self._observer = None
        for t in (self._poll_thread, self._aux_thread):
            if t and t.is_alive():
                try:
                    t.join(timeout=5)
                except Exception:
                    pass
        self._poll_thread = self._aux_thread = None
        self.add_event(DefenseEvent(kind="system", level="info",
                                    title="实时防护已停止", detail="所有监控位置已解除"))
        logger.info("实时防护已停止")

    def restart(self, dirs=None, scope=None):
        if self.running:
            self.stop()
        return self.start(dirs=dirs, scope=scope)

    def pause(self):
        self.paused = True
        self.add_event(DefenseEvent(kind="system", level="warn", title="实时防护已暂停",
                                    detail="监控线程保留，但不再扫描与处置"))
        return True

    def resume(self):
        self.paused = False
        self.add_event(DefenseEvent(kind="system", level="info", title="实时防护已恢复"))
        return True

    # ---------------- 事件记录 ----------------
    def add_event(self, ev):
        with self._lock:
            self.events.appendleft(ev)
        try:
            logger.log("WARN" if ev.level in ("warn", "high") else "INFO",
                       f"[防御] {ev.title} | {ev.detail}")
        except Exception:
            pass
        try:
            from .config import DATA_DIR
            with open(os.path.join(str(DATA_DIR), "defense.log"), "a", encoding="utf-8") as f:
                f.write(f"[{ev.time}] [{ev.level}] [{ev.kind}] {ev.title} | {ev.detail}\n")
        except Exception:
            pass
        if self.on_event:
            try:
                self.on_event(ev)
            except Exception:
                pass
        return ev

    def clear_events(self):
        with self._lock:
            self.events.clear()

    def recent(self, n=50):
        with self._lock:
            return list(self.events)[:n]

    # ---------------- 文件事件处理 ----------------
    def _debounce(self, path, window=1.0):
        now = time.time()
        last = self._recent.get(path, 0)
        if now - last < window:
            return False
        self._recent[path] = now
        if len(self._recent) > 2000:
            cut = now - 10
            self._recent = {k: v for k, v in self._recent.items() if v > cut}
        return True

    def _on_fs_event(self, path, action):
        if not self.running or self.paused or not path:
            return
        if not os.path.exists(path) or not os.path.isfile(path):
            # 删除事件仍喂给行为中枢（勒索检测需要）
            try:
                watcher_mod.watcher.feed_file(path, action)
            except Exception:
                pass
            return
        try:
            watcher_mod.watcher.feed_file(path, action)
        except Exception:
            pass
        if action != "created" and action != "modified":
            return
        if not config.get("realtime_monitor", True):
            return
        if not self._debounce(path):
            return
        # 受保护文件夹：批量篡改检测（只告警，不杀进程）
        try:
            alert = protected_mod.protected.feed(path, action)
            if alert:
                self.add_event(DefenseEvent(
                    kind="protected", level="high", title="受保护文件夹批量篡改告警",
                    detail=alert["msg"], path=alert.get("folder", "")))
                self._maybe_snapshot(alert["msg"])
        except Exception:
            pass
        self._scan_and_act(path)

    def _scan_and_act(self, path):
        """对单个新文件做扫描，并按策略处置。"""
        try:
            item = scanner.engine.scan_file(path)
        except Exception:
            item = None
        self.stats["scanned"] += 1
        if not item:
            return
        sev = getattr(item, "severity", "medium")
        self.add_event(DefenseEvent(
            kind="threat", level="high" if sev == "high" else "warn",
            title=f"实时防护发现威胁（{item.detection}）",
            detail=f"{item.threat}",
            path=item.path))
        if sev == "low":
            return
        self.stats["threats"] += 1
        action = str(config.get("realtime_auto_action", "quarantine") or "quarantine")
        if action == "alert":
            return
        self._dispose(item, "quarantine" if action == "quarantine" else "delete")

    def _dispose(self, item, level):
        try:
            from . import dispose as dispose_mod
            res = dispose_mod.dispose_file(
                item.path, level=level, threat=item.threat,
                detection=item.detection, md5=item.md5,
                sha256=item.sha256, size=item.size)
            self.stats["disposed"] += 1
            self.add_event(DefenseEvent(
                kind="action", level="high",
                title=f"已自动处置（{dispose_mod.LEVEL_LABELS.get(level, level)}）",
                detail=res.msg, path=item.path))
        except Exception as e:
            self.add_event(DefenseEvent(kind="action", level="warn",
                                        title="自动处置失败", detail=str(e),
                                        path=item.path))

    # ---------------- 降级轮询 ----------------
    def _poll_loop(self):
        seen = {}
        first = True
        while not self._stop_flag.is_set():
            try:
                for base in self.current_dirs:
                    for dirpath, dirnames, filenames in os.walk(base):
                        if self._stop_flag.is_set():
                            break
                        depth = dirpath[len(base):].count(os.sep)
                        if depth > 3:
                            dirnames[:] = []
                        for fn in filenames:
                            full = os.path.join(dirpath, fn)
                            try:
                                st = os.stat(full)
                            except Exception:
                                continue
                            key = (full, int(st.st_mtime), st.st_size)
                            if key in seen:
                                continue
                            seen[key] = time.time()
                            if not first:
                                self._on_fs_event(full, "created")
                first = False
                if len(seen) > 5000:
                    seen = {k: v for k, v in seen.items()
                            if time.time() - v < 300}
            except Exception as e:
                logger.warn(f"轮询监控异常: {e}")
            for _ in range(10):
                if self._stop_flag.is_set():
                    break
                time.sleep(0.5)

    # ---------------- 辅助监控循环 ----------------
    def _aux_loop(self):
        interval = 8
        while not self._stop_flag.is_set():
            for _ in range(interval * 2):
                if self._stop_flag.is_set():
                    break
                time.sleep(0.5)
            if self.paused:
                continue
            try:
                if config.get("defense_startup", True):
                    self._check_startup()
                if config.get("defense_hosts", True):
                    self._check_hosts()
                if config.get("modules_enabled", {}).get("system_watcher", True):
                    watcher_mod.watcher.tick_processes()
                if config.get("modules_enabled", {}).get("ransomware", True):
                    self._check_vss()
            except Exception as e:
                logger.warn(f"辅助监控异常: {e}")

    def _check_startup(self):
        entries = residue.list_startup_entries()
        cur = {(e["location"], e["name"]) for e in entries}
        if self._startup_snapshot is None:
            self._startup_snapshot = cur
            return
        added = cur - self._startup_snapshot
        if added:
            for loc, name in list(added)[:5]:
                detail = ""
                for e in entries:
                    if e["location"] == loc and e["name"] == name:
                        detail = e.get("command", "")
                        break
                self.add_event(DefenseEvent(
                    kind="startup", level="warn", title="发现新增自启动项",
                    detail=f"{name} → {detail[:120]}", path=loc))
                try:
                    watcher_mod.watcher.feed_registry(loc, name, detail, "added")
                except Exception:
                    pass
            self._startup_snapshot = cur

    def _check_hosts(self):
        hosts = os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                             r"System32\drivers\etc\hosts")
        try:
            st = os.stat(hosts)
            sig = (st.st_size, int(st.st_mtime))
        except Exception:
            return
        if self._hosts_sig is None:
            self._hosts_sig = sig
            return
        if sig != self._hosts_sig:
            self._hosts_sig = sig
            self.add_event(DefenseEvent(
                kind="hosts", level="warn", title="hosts 文件被修改",
                detail=f"size={sig[0]} mtime={sig[1]}", path=hosts))

    def _check_vss(self):
        now = time.time()
        if now - self._last_vss_check < 60:
            return
        self._last_vss_check = now
        try:
            r = subprocess.run(["vssadmin", "list", "shadows"],
                               capture_output=True, timeout=20,
                               universal_newlines=True, creationflags=0x08000000)
            txt = (r.stdout or "").lower()
            # 中文系统输出"卷影副本 ID"，英文 "Shadow Copy ID"
            cnt = txt.count("shadow copy id") + txt.count("卷影副本 id")
            if self._vss_count is None:
                self._vss_count = cnt
                return
            if cnt < self._vss_count:
                ev = watcher_mod.watcher.feed_vss("卷影副本减少", self._vss_count, cnt)
                self.add_event(DefenseEvent(
                    kind="vss", level="high", title="卷影副本被删除",
                    detail=f"{self._vss_count} → {cnt}"))
                self._maybe_snapshot("卷影副本减少")
            self._vss_count = cnt
        except Exception:
            pass

    def _maybe_snapshot(self, reason=""):
        if not config.get("snapshot_enabled", True):
            return
        try:
            from . import snapshot as snap_mod
            if snap_mod.snapshot.list_snapshots():
                last = snap_mod.snapshot.list_snapshots()[0]
                if self._recent_snapshot_guard(last.get("created", "")):
                    return
            res = snap_mod.snapshot.create(
                label=f"自动快照（{reason[:30]}）",
                max_file_mb=config.get_int("snapshot_max_file_mb", 20),
                max_total_mb=config.get_int("snapshot_max_total_mb", 500))
            if res.get("ok"):
                self.add_event(DefenseEvent(
                    kind="snapshot", level="info", title="已自动创建防勒索快照",
                    detail=f"{res.get('count')} 个文件，"
                           f"{res.get('bytes', 0) / 1024 / 1024:.1f} MB"))
        except Exception as e:
            logger.warn(f"自动快照失败: {e}")

    def _recent_snapshot_guard(self, created):
        """5 分钟内已自动快照过则跳过，避免连续触发。"""
        try:
            t = time.mktime(time.strptime(created, "%Y-%m-%d %H:%M:%S"))
            return time.time() - t < 300
        except Exception:
            return False

    @property
    def status(self):
        return {
            "running": self.running,
            "paused": self.paused,
            "scope": self.scope,
            "dirs": self.current_dirs,
            "engine": "watchdog" if self._observer else ("轮询" if self.running else "未启动"),
            "events": len(self.events),
            "stats": dict(self.stats),
            "has_watchdog": HAS_WATCHDOG,
        }


# 全局单例
monitor = RealtimeMonitor()
