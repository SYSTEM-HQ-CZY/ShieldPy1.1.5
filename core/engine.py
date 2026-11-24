# -*- coding: utf-8 -*-
"""引擎层统一门面（v1.1.5）。

按项目文件拆分要求，engine.py 是"引擎层"的对外入口，聚合三块能力：

    扫描引擎   ScanEngine / engine 单例 / 四种扫描模式（quick full removable background）
    风险打分   assess / Feature / verify_signature / is_log_baseline
              （数字签名减免、日志基线白名单、加权阈值，单特征不直接判恶意）
    处置逻辑   dispose_file / batch_dispose / 三档处置（隔离 删除 高级清除）
              顺序固定：先终止进程树（提示"进程已终止"）→ 再隔离/删除 → 清残留

内部实现仍在 core/ 的专用模块（scanner / risk / dispose / terminator / residue / ...），
这里只做聚合导出与便捷封装，便于"一个引擎一个入口"地调用与测试。
"""
from . import logger
from .dispose import (DISPOSE_LEVELS, LEVEL_LABELS, DisposeResult, batch_dispose,
                      dispose_file, is_system_critical)
from .risk import (Feature, HIGH_THRESHOLD, MITIGATIONS, THRESHOLD, WEIGHTS,
                   assess, is_log_baseline, is_pext, is_texty, verify_signature)
from .risk import stats as risk_stats
from .scanner import (DRIVE_FIXED, DRIVE_REMOVABLE, PERF_MODES, SCAN_MODES,
                      ScanEngine, ThreatItem, all_drives, drive_type, engine,
                      fixed_drives, removable_drives)

__all__ = [
    "ScanEngine", "engine", "ThreatItem", "SCAN_MODES", "PERF_MODES",
    "fixed_drives", "removable_drives", "all_drives", "drive_type",
    "DRIVE_FIXED", "DRIVE_REMOVABLE",
    "assess", "Feature", "verify_signature", "is_log_baseline", "THRESHOLD",
    "HIGH_THRESHOLD", "WEIGHTS", "MITIGATIONS", "risk_stats",
    "dispose_file", "batch_dispose", "DisposeResult", "DISPOSE_LEVELS",
    "LEVEL_LABELS", "is_system_critical",
    "scan_file", "dispose", "scan_and_dispose", "engine_info",
]


# ---------------- 便捷封装 ----------------
def scan_file(path, inside_archive=False):
    """扫描单个文件。返回 ThreatItem 或 None（走全局引擎单例）。"""
    return engine.scan_file(path, inside_archive=inside_archive)


def dispose(path, level=None, item=None, pids=None):
    """处置单个文件。item 可为 ThreatItem，自动带上威胁信息。"""
    kw = {}
    if item is not None:
        kw = {"threat": getattr(item, "threat", ""),
              "detection": getattr(item, "detection", ""),
              "md5": getattr(item, "md5", ""),
              "sha256": getattr(item, "sha256", ""),
              "size": getattr(item, "size", 0)}
    return dispose_file(path, level=level, pids=pids, **kw)


def scan_and_dispose(paths, level=None, stop_on_clean=True):
    """扫描 + 处置联动：只处置被判为威胁（high/medium）的文件。

    返回 {"threats": [ThreatItem], "results": [DisposeResult]}
    """
    threats = []
    for p in (paths or []):
        item = scan_file(p)
        if item and getattr(item, "severity", "") in ("high", "medium"):
            threats.append(item)
    results = []
    if threats:
        logger.warning(f"scan_and_dispose：{len(threats)} 个文件判为威胁，开始处置")
        results = batch_dispose([t.path for t in threats], level=level, items=threats)
    elif stop_on_clean:
        logger.info("scan_and_dispose：未发现威胁，跳过处置")
    return {"threats": threats, "results": results}


def engine_info():
    """引擎自检信息（版本、阈值、权重、各模式参数）。"""
    return {
        "scanner_modes": dict(SCAN_MODES),
        "perf_modes": {k: {"workers": v[0], "throttle": v[1]}
                       for k, v in PERF_MODES.items()},
        "dispose_levels": list(DISPOSE_LEVELS),
        "dispose_labels": dict(LEVEL_LABELS),
        "risk": risk_stats(),
    }
