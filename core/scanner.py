# -*- coding: utf-8 -*-
"""扫描引擎 v4（v1.1.5）

四种扫描模式：
    quick        快速扫描（常用目录）
    full         全盘扫描（全部固定磁盘）
    removable    可移动驱动器扫描（U 盘 / 移动硬盘 / 存储卡）
    background   后台低优先级扫描（进程降到 IDLE 优先级 + 单 worker + 长节流）

检测链（v1.1.5 改为"特征收集 + 加权打分"，不再命中即判定）：
    信任项(路径+SHA256) → [特征库哈希] [YARA] [Office 宏] [高危扩展名] [脚本启发式] [加壳]
    → core.risk 加权打分（含数字签名减免、日志基线白名单）→ 过阈值才判威胁

保留历史修复：
    * 单文件一次 I/O（同时算 MD5/SHA256 + 取文件头）
    * 多线程 worker 内节流（PERF_MODES 真正生效）
    * start_scan 前先停旧线程（避免进度条回跳）
"""
import ctypes
import hashlib
import os
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import logger, olevba_engine, yara_engine, risk
from .config import config
from .heuristics import (
    detect_script_threat, detect_packer, read_text_safe,
    RISK_EXT_HINT,
)
from .signature import signature_db
from .trust import trust

_SCRIPT_EXT = {".vbs", ".vbe", ".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse",
               ".hta", ".html", ".py", ".lnk"}
_ARCHIVE_EXT = {".zip"}
_SKIP_DIR_NAMES = {"$recycle.bin", "system volume information",
                   "windows\\system32\\drivers\\etc"}

# YARA 只对"有载体意义"的文件做匹配，避免全盘扫描时拖慢
_YARA_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx",
             ".ps1", ".psm1", ".vbs", ".vbe", ".bat", ".cmd", ".js", ".jse",
             ".hta", ".lnk", ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm",
             ".zip", ".rar", ".7z", ".pdf", ".jar", ".py", ".txt", ".dat", ".bin"}
_YARA_MAX_MB = 8

# 性能模式 -> (worker 线程数, 每文件节流秒)
PERF_MODES = {
    "low": (1, 0.006),
    "balanced": (2, 0.012),
    "high": (2, 0.001),
    "background": (1, 0.020),
}
_BATCH = 200

SCAN_MODES = {
    "quick": "快速扫描",
    "full": "全盘扫描",
    "removable": "可移动驱动器",
    "background": "后台低优先级",
}

DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3


class ThreatItem:
    """威胁条目。severity: high/medium/low，score: 加权评分（v1.1.5）"""

    def __init__(self, path="", name="", detection="", threat="",
                 md5="", sha256="", size=0, action="未处理", time="",
                 severity="medium", source="", score=0):
        self.path = path
        self.name = name
        self.detection = detection
        self.threat = threat
        self.md5 = md5
        self.sha256 = sha256
        self.size = size
        self.action = action
        self.time = time
        self.severity = severity
        self.source = source
        self.score = score

    def to_dict(self):
        return {"path": self.path, "name": self.name, "detection": self.detection,
                "threat": self.threat, "md5": self.md5, "sha256": self.sha256,
                "size": self.size, "action": self.action, "time": self.time,
                "severity": self.severity, "source": self.source,
                "score": self.score}


def drive_type(path):
    try:
        return ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(str(path)))
    except Exception:
        return 0


def all_drives(types=(DRIVE_FIXED,)):
    """枚举盘符（按 GetDriveType 过滤）。types=(DRIVE_FIXED,) 默认固定盘。"""
    out = []
    try:
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            root = letter + ":\\"
            try:
                if not os.path.exists(root):
                    continue
            except Exception:
                continue
            dt = drive_type(root)
            if dt in types:
                out.append(root)
    except Exception:
        pass
    return out


def removable_drives():
    """可移动驱动器列表（U 盘 / 移动硬盘 / 读卡器）。"""
    return all_drives(types=(DRIVE_REMOVABLE,))


def fixed_drives():
    return all_drives(types=(DRIVE_FIXED,))


class ScanEngine:
    def __init__(self):
        self._stop_flag = threading.Event()
        self._thread = None
        self._result_lock = threading.Lock()
        self.results = []
        self.stats = {"scanned": 0, "skipped": 0, "threats": 0, "hints": 0, "errors": 0}
        self._start_time = 0.0
        self.scan_mode = "quick"
        self.on_progress = None
        self.on_threat = None
        self.on_done = None
        self._old_priority = None
        self.last_assessments = []      # v1.1.5：留档评分明细，便于排查误报

    # ---------------- 单文件检测（v1.1.5 评分制） ----------------
    def scan_file(self, path, inside_archive=False):
        """返回 ThreatItem 或 None。

        v1.1.5 变更：任何检出先收集为"特征"，再由 core.risk 加权打分；
        分数不到阈值只记提示甚至不报，避免"单特征误判"。
        """
        p = Path(path)
        try:
            if not p.exists() or not p.is_file():
                return None
            size = p.stat().st_size
            if size <= 0:
                return None

            # 1) 信任项（路径 + SHA256 双哈希；被篡改则自动失效并继续扫描）
            if config.get("trust_dual_hash", True):
                if trust.contains(str(p)):
                    return None
            else:
                from .whitelist import whitelist
                if whitelist.contains(str(p)):
                    return None

            # 2) 一次读取（大小受限时），同时算双哈希 + 取文件头
            max_mb = config.get("max_file_mb", 100)
            data = None
            if size <= max_mb * 1024 * 1024:
                try:
                    with open(p, "rb") as f:
                        data = f.read()
                except Exception:
                    data = None

            md5 = sha256 = ""
            ext = p.suffix.lower()
            head = data[:65536] if data is not None else b""
            feats = []

            # 3) 特征库哈希（强特征，直接判定）
            if data is not None:
                md5 = hashlib.md5(data).hexdigest()
                sha256 = hashlib.sha256(data).hexdigest()
                rec = signature_db.lookup(md5=md5, sha256=sha256)
                if rec:
                    feats.append(risk.Feature(
                        "sig_hash", "high",
                        f"{rec.get('name', '已知威胁')}", "特征库"))

            # 4) YARA 规则（可复用 Loki / signature-base 规则）
            if config.get("yara_enabled", True) and ext in _YARA_EXT \
                    and size <= _YARA_MAX_MB * 1024 * 1024:
                try:
                    hits = yara_engine.match_file(str(p))
                except Exception:
                    hits = []
                for rule, tags, sev in (hits or [])[:3]:
                    fid = {"high": "yara_high", "medium": "yara_medium",
                           "low": "yara_low"}.get(str(sev), "yara_medium")
                    feats.append(risk.Feature(
                        fid, sev if sev in ("high", "medium", "low") else "high",
                        f"YARA 命中规则 {rule}", "YARA"))

            # 5) Office 宏分析（olevba）
            if config.get("olevba_enabled", True) and olevba_engine.is_office_file(str(p)):
                try:
                    rep = olevba_engine.analyze(str(p))
                except Exception:
                    rep = {}
                if rep.get("has_macro") and rep.get("severity") in ("high", "medium"):
                    fid = "macro_high" if rep.get("severity") == "high" else "macro_medium"
                    feats.append(risk.Feature(
                        fid, rep.get("severity"),
                        f"文档宏可疑（评分 {rep.get('score')}）：{rep.get('detail')}",
                        "olevba"))

            # 6) 高危扩展名（弱特征，只用于提示，单独存在不判威胁）
            if ext in RISK_EXT_HINT and not inside_archive:
                name, desc = RISK_EXT_HINT[ext]
                feats.append(risk.Feature(
                    "risk_ext", "low", f"{name} - {desc}", "扩展名提示"))

            # 7) 脚本启发式（分级权重）
            if config.get("deep_heuristic", True) and ext in _SCRIPT_EXT:
                text = read_text_safe(p, data=data)
                if text:
                    name, desc, sev = detect_script_threat(p, text, ext)
                    if name and sev:
                        fid = {"high": "heur_high", "medium": "heur_medium",
                               "low": "heur_low"}.get(sev, "heur_medium")
                        feats.append(risk.Feature(fid, sev, f"{name} - {desc}", "启发式"))

            # 8) 加壳 / 特殊文件头
            if head:
                name, desc, sev = detect_packer(p, head)
                if name and sev:
                    fid = {"high": "packer_high", "medium": "packer_medium",
                           "low": "packer_low"}.get(sev, "packer_medium")
                    feats.append(risk.Feature(fid, sev, f"{name} - {desc}", "加壳检测"))

            if not feats:
                return None

            # 9) 加权打分（含签名校验与日志基线减免）
            a = risk.assess(
                feats, path=str(p), ext=ext, size=size, data_sample=head,
                check_signature=config.get_bool("signature_check", True),
                inside_archive=inside_archive)

            if a.verdict == "clean":
                if config.get_bool("risk_log", True):
                    logger.info(f"[评分豁免] {p} 特征={[f.id for f in feats]} "
                                f"评分={a.score} 减免={a.mitigations} → 不判定威胁")
                self._remember(p, a)
                return None

            self._remember(p, a)
            return ThreatItem(
                path=str(p), name=p.name, detection=a.detection, threat=a.threat,
                md5=md5, sha256=sha256, size=size, severity=a.severity,
                source=a.source, score=a.score,
                time=time.strftime("%Y-%m-%d %H:%M:%S"),
            )
        except Exception as e:
            logger.warn(f"扫描文件异常 {path}: {e}")
            return None

    def _remember(self, p, a):
        try:
            with self._result_lock:
                self.last_assessments.append({"path": str(p), "score": a.score,
                                              "verdict": a.verdict,
                                              "features": [f.id for f in a.features],
                                              "mitigations": a.mitigations})
                if len(self.last_assessments) > 3000:
                    del self.last_assessments[:1000]
        except Exception:
            pass

    # ---------------- 启动扫描 ----------------
    def start_scan(self, roots, follow_links=False, mode="custom"):
        # 防并发：旧线程仍在跑就先停掉（否则两路进度同时回调 → 进度条回跳）
        if self._thread and self._thread.is_alive():
            self._stop_flag.set()
            try:
                self._thread.join(timeout=10)
            except Exception:
                pass
        self._stop_flag.clear()
        self.results = []
        self.stats = {"scanned": 0, "skipped": 0, "threats": 0, "hints": 0, "errors": 0}
        self._start_time = time.time()
        self.scan_mode = mode
        self.last_assessments = []
        self._thread = threading.Thread(
            target=self._run, args=(list(roots), follow_links, mode), daemon=True)
        self._thread.start()

    def start_background_scan(self, roots=None):
        """后台低优先级扫描：降进程优先级 + background 性能档。"""
        if roots is None:
            roots = fixed_drives()
        self._lower_priority()
        logger.info("启动后台低优先级扫描")
        self.start_scan(roots, mode="background")

    def _lower_priority(self):
        try:
            import psutil
            p = psutil.Process(os.getpid())
            self._old_priority = p.nice()
            p.nice(psutil.IDLE_PRIORITY_CLASS)
            logger.info("扫描进程已降为 IDLE 优先级")
        except Exception as e:
            logger.warn(f"降低进程优先级失败: {e}")

    def _restore_priority(self):
        if self._old_priority is None:
            return
        try:
            import psutil
            psutil.Process(os.getpid()).nice(self._old_priority)
            self._old_priority = None
        except Exception:
            pass

    def stop(self):
        self._stop_flag.set()

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def _perf_params(self, mode=None):
        if mode == "background":
            return PERF_MODES["background"]
        cfg_mode = config.get("scan_perf_mode", "balanced")
        return PERF_MODES.get(cfg_mode, PERF_MODES["balanced"])

    # ---------------- 扫描主流程 ----------------
    def _run(self, roots, follow_links, mode="custom"):
        try:
            files = []
            for root in roots:
                root = os.path.abspath(root)
                if not os.path.exists(root):
                    logger.warn(f"扫描路径不存在: {root}")
                    continue
                if os.path.isfile(root):
                    files.append(root)
                else:
                    files.extend(self._walk(root, follow_links))

            total = len(files)
            workers, throttle = self._perf_params(mode)
            processed = [0]

            def account(fp, item):
                if self._stop_flag.is_set():
                    return
                processed[0] += 1
                self.stats["scanned"] += 1
                if self.on_progress:
                    self.on_progress(processed[0], total, fp)
                if item:
                    with self._result_lock:
                        self.results.append(item)
                    if item.severity in ("high", "medium"):
                        self.stats["threats"] += 1
                        logger.warning(f"[威胁] {item.detection} {item.threat} @ {item.path}")
                    else:
                        self.stats["hints"] += 1
                        logger.info(f"[提示] {item.detection} {item.threat} @ {item.path}")
                    if self.on_threat:
                        self.on_threat(item)

            if workers <= 1:
                for fp in files:
                    if self._stop_flag.is_set():
                        break
                    account(fp, self.scan_file(fp))
                    if throttle:
                        time.sleep(throttle)
            else:
                def work(fp):
                    if self._stop_flag.is_set():
                        return None
                    item = self.scan_file(fp)
                    if throttle:
                        time.sleep(throttle)
                    return item

                with ThreadPoolExecutor(max_workers=workers) as ex:
                    batch = []
                    for fp in files:
                        if self._stop_flag.is_set():
                            break
                        batch.append((fp, ex.submit(work, fp)))
                        if len(batch) >= _BATCH:
                            self._drain(batch, account)
                            batch = []
                    self._drain(batch, account)

            self.stats["elapsed"] = round(time.time() - self._start_time, 2)
            self.stats["mode"] = SCAN_MODES.get(mode, mode)
            if config.get("perf_log", True):
                logger.info(f"扫描完成：{SCAN_MODES.get(mode, mode)} "
                            f"{self.stats['scanned']}/{total} 文件，"
                            f"{self.stats['elapsed']}s，威胁 {self.stats['threats']}，"
                            f"提示 {self.stats['hints']}")
            if self.on_done:
                self.on_done(self.stats)
        except Exception as e:
            logger.error(f"扫描线程异常: {e}")
            if self.on_done:
                self.on_done(self.stats)
        finally:
            self._restore_priority()

    def _drain(self, batch, account):
        for fp, fut in batch:
            try:
                account(fp, fut.result())
            except Exception:
                account(fp, None)

    def _walk(self, root, follow_links):
        out = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_links):
            if self._stop_flag.is_set():
                break
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in _SKIP_DIR_NAMES and not d.lower().startswith("$")
            ]
            for fn in filenames:
                if self._stop_flag.is_set():
                    break
                try:
                    full = os.path.join(dirpath, fn)
                    if os.path.islink(full) and not follow_links:
                        continue
                    out.append(full)
                except Exception:
                    continue
        return out

    # ---------------- 压缩包扫描 ----------------
    def scan_archive(self, zip_path):
        threats = []
        if not config.get("scan_archives", False):
            return threats
        try:
            with zipfile.ZipFile(zip_path) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    name = info.filename.lower()
                    if name.endswith((".exe", ".scr", ".bat", ".cmd", ".ps1",
                                      ".vbs", ".vbe", ".js", ".jse", ".hta")):
                        threats.append(ThreatItem(
                            path=f"{zip_path}::>{info.filename}",
                            name=info.filename.rsplit("/", 1)[-1],
                            detection="Archive.Content",
                            threat="压缩包内含高危类型文件（仅提示）",
                            size=info.file_size, severity="low", source="压缩包",
                            score=0,
                        ))
        except Exception:
            pass
        return threats


# 全局单例
engine = ScanEngine()
