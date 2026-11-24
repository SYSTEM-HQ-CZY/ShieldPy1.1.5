# -*- coding: utf-8 -*-
"""全局路径与配置管理（v1.1.5）。

v1.1.5 变更：
    * 主程序默认普通权限 → data 目录若不可写（装到 Program Files 且非管理员），
      自动回退到 %LOCALAPPDATA%\\ShieldPy\\data，避免"能开界面但写不了日志"。
    * 新增误报治理配置项（签名校验、日志基线白名单、评分阈值）。
"""
import json
import os
import sys
from pathlib import Path

# ---- 项目根目录（core 的上一级），保证从任意 cwd 启动都正确 ----
BASE_DIR = Path(__file__).resolve().parent.parent
if getattr(sys, "frozen", False):          # PyInstaller 打包后
    BASE_DIR = Path(sys.executable).resolve().parent


def _probe_writable(p: Path) -> bool:
    """真实写一次，确认目录可用（比 os.access 可靠）。"""
    try:
        p.mkdir(parents=True, exist_ok=True)
        probe = p / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except Exception:
        return False


_LOCAL_DIR = (Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
              / "ShieldPy")

DATA_DIR = BASE_DIR / "data"
DATA_DIR_FALLBACK = False
if not _probe_writable(DATA_DIR):
    _fallback = _LOCAL_DIR / "data"
    if _probe_writable(_fallback):
        DATA_DIR = _fallback
        DATA_DIR_FALLBACK = True

QUARANTINE_DIR = DATA_DIR / "quarantine"
LOGS_DIR = DATA_DIR / "logs"
REPORTS_DIR = (DATA_DIR / "reports") if DATA_DIR_FALLBACK else (BASE_DIR / "reports")
TOOLS_DIR = BASE_DIR / "tools"
CONFIG_FILE = DATA_DIR / "config.json"
WHITELIST_FILE = DATA_DIR / "whitelist.json"
SIGNATURE_FILE = DATA_DIR / "signatures.json"
HEURISTIC_FILE = DATA_DIR / "heuristics.json"
BASELINE_FILE = DATA_DIR / "baseline_logs.json"

for _d in (DATA_DIR, QUARANTINE_DIR, REPORTS_DIR, LOGS_DIR):
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

# 日志 / 文本类基线扩展名（第三方软件日志误杀防线）
# 注意：这里只放纯文本类扩展名，.dat 等可承载二进制的格式不纳入
LOG_BASELINE_EXTS = [".log", ".txt", ".ini", ".cfg", ".conf", ".json", ".xml",
                     ".csv", ".md", ".yml", ".yaml", ".bak", ".old", ".tmp"]


def _default_quick_dirs():
    """快速扫描目录：系统 Temp、用户 Temp、下载目录、桌面。"""
    dirs = []
    windir = os.environ.get("WINDIR", "C:\\Windows")
    temp_env = os.environ.get("TEMP") or os.environ.get("TMP")
    if temp_env:
        dirs.append(temp_env)
    dirs.append(str(Path(windir) / "Temp"))
    user_home = Path.home()
    for sub in ("Downloads", "下载", "Desktop", "桌面"):
        p = user_home / sub
        if p.exists():
            dirs.append(str(p))
    # 去重保序
    seen, out = set(), []
    for d in dirs:
        k = os.path.normcase(os.path.normpath(d))
        if k not in seen:
            seen.add(k)
            out.append(d)
    return out


def _default_protected_folders():
    home = os.environ.get("USERPROFILE") or str(Path.home())
    out = []
    for sub in ("Documents", "文档", "Desktop", "桌面", "Pictures", "图片",
                "Videos", "视频", "Downloads", "下载"):
        p = os.path.join(home, sub)
        if os.path.isdir(p):
            out.append(p)
    return out


# 防护模块分组（卡巴斯基化）
DEFAULT_MODULES = {
    "file_av": True,          # 文件反病毒（扫描引擎）
    "network": True,          # 反网络攻击（仅行为告警，不主动断网）
    "system_watcher": True,   # System Watcher 行为监控
    "protected": True,        # 受控文件夹防护
    "ransomware": True,       # 勒索防护（快照/回滚）
    "advanced_clear": False,  # 高级清除（默认关，需用户显式开启并接受风险）
}

DEFAULT_CONFIG = {
    "quick_dirs": _default_quick_dirs(),
    # ---- 实时防护（v1.0.55 行为保留）----
    "realtime_monitor": True,
    "realtime_scope": "full",             # full=全盘 / custom=自定义目录
    "realtime_dirs": [],
    "realtime_auto_action": "quarantine",  # alert/quarantine/delete
    "defense_startup": True,
    "defense_hosts": True,
    # ---- 扫描 ----
    "deep_heuristic": True,
    "scan_archives": False,
    "scan_perf_mode": "balanced",          # low/balanced/high
    "max_file_mb": 100,
    "scan_removable": True,                # 可移动驱动器扫描开关
    "scan_background_idle": True,          # 后台低优先级扫描
    # ---- v1.1.0 处置链路 ----
    "dispose_level": "quarantine",         # quarantine/delete/advanced
    "advanced_clear_ack": False,           # 用户已确认高级清除风险
    "nsudo_path": "",                      # NSudoLC.exe 路径（空=自动探测）
    # ---- v1.1.0 信任项 ----
    "trust_dual_hash": True,               # 路径+SHA256 双哈希校验
    # ---- v1.1.0 原地锁定 ----
    "lock_enabled": True,
    # ---- v1.1.0 受保护文件夹 ----
    "protected_enabled": True,
    "protected_folders": _default_protected_folders(),
    "protected_threshold": 20,
    "protected_window_sec": 10,
    # ---- v1.1.0 勒索防护 / System Watcher ----
    "ransomware_enabled": True,
    "ransomware_threshold": 60,
    "snapshot_enabled": True,
    "snapshot_max_file_mb": 20,
    "snapshot_max_total_mb": 500,
    # ---- v1.1.0 引擎 ----
    "yara_enabled": True,
    "olevba_enabled": True,
    # ---- v1.1.5 误报治理（风险加权打分）----
    "signature_check": True,               # 有效数字签名 → 扣分减免
    "log_baseline": True,                  # 日志/文本类基线白名单
    "log_baseline_exts": list(LOG_BASELINE_EXTS),
    "risk_threshold": 60,                  # 判威胁阈值（单特征达不到就不判）
    "risk_log": True,                      # 记录"评分豁免"明细，便于复查误报
    # ---- v1.1.5 权限模型（主程序普通权限）----
    "run_as_user": True,                   # 主程序默认普通权限，高危机能时才提权
    "elevate_on_advanced": True,           # 高级清除点击时才调 NSudo
    # ---- 防护模块分组 ----
    "modules_enabled": dict(DEFAULT_MODULES),
    # ---- v1.1.0 界面 ----
    "theme": "dark",
    "ui_borderless": True,                 # 无原生标题栏 + 自制顶部栏
    "ui_scale": 1.0,
    "wizard_done": False,                  # 初次启动向导是否完成
    "perf_log": True,                      # 性能日志
    "auto_add_whitelist_on_trust": True,
    "last_scan_time": "",
    "stats": {"scanned": 0, "threats": 0, "cleaned": 0},
}


class Config:
    """轻量配置读写。"""

    def __init__(self, path: Path = CONFIG_FILE):
        self.path = Path(path)
        self.data = dict(DEFAULT_CONFIG)
        self.data["modules_enabled"] = dict(DEFAULT_MODULES)
        self.load()

    def load(self):
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = {**DEFAULT_CONFIG, **loaded}
                    # 嵌套字典合并（modules_enabled）
                    merged = dict(DEFAULT_MODULES)
                    if isinstance(loaded.get("modules_enabled"), dict):
                        merged.update(loaded["modules_enabled"])
                    self.data["modules_enabled"] = merged
                    # v1.0.55 迁移：旧版配置（无 realtime_scope）升级为全盘实时防护
                    if "realtime_scope" not in loaded:
                        self.data["realtime_monitor"] = True
                        self.data["realtime_scope"] = "full"
                    # v1.1.0 迁移：旧配置没有向导标记 → 视为未完成向导
                    if "wizard_done" not in loaded:
                        self.data["wizard_done"] = False
                    # 受保护目录为空 → 补默认
                    if not self.data.get("protected_folders"):
                        self.data["protected_folders"] = _default_protected_folders()
            except Exception:
                pass

    def save(self):
        try:
            self.path.write_text(
                json.dumps(self.data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def get(self, key, default=None):
        return self.data.get(key, default)

    def get_bool(self, key, default=False):
        v = self.data.get(key, default)
        if isinstance(v, str):
            return v.lower() in ("1", "true", "yes", "on")
        return bool(v)

    def get_int(self, key, default=0):
        try:
            return int(self.data.get(key, default))
        except Exception:
            return default

    def set(self, key, value):
        self.data[key] = value
        self.save()

    def set_many(self, **kwargs):
        self.data.update(kwargs)
        self.save()

    def module_enabled(self, name):
        m = self.data.get("modules_enabled") or {}
        return bool(m.get(name, DEFAULT_MODULES.get(name, False)))

    def set_module(self, name, enabled):
        m = dict(self.data.get("modules_enabled") or {})
        m[name] = bool(enabled)
        self.data["modules_enabled"] = m
        self.save()

    def bump_stats(self, **kw):
        st = self.data.setdefault("stats", dict(DEFAULT_CONFIG["stats"]))
        for k, v in kw.items():
            st[k] = st.get(k, 0) + v
        self.save()


# 全局单例
config = Config()
