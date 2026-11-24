# -*- coding: utf-8 -*-
"""威胁处置链路（v1.1.0 核心）。

对标卡巴斯基的处置顺序：
    ① 先终止恶意进程及其子进程（避免"边删边复活"）
    ② 再尝试删除源文件
    ③ 文件被占用删不掉 → 写入 PendMoves（重启后由系统在挂载早期删除）
    ④ 清理启动项 / 服务 / 注册表残留（切断自动复活链）

三档处置：
    quarantine  隔离（默认，可恢复）
    delete      删除（源文件抹除 + 残留清理）
    advanced    高级清除（借 NSudo 拿 TrustedInstaller 权限，需用户红字确认，全程日志）
"""
import os

from . import logger, nsudo, pendmoves, residue, terminator, quarantine as quarantine_mod
from .config import config


DISPOSE_LEVELS = ("quarantine", "delete", "advanced")
LEVEL_LABELS = {"quarantine": "隔离", "delete": "删除", "advanced": "高级清除"}


class DisposeResult:
    """处置结果：逐步骤记录，便于 UI 展示与事后核对。

    v1.1.5：新增 notification（"进程已终止"等需单独弹给用户的通知）与
    killed_msgs（被杀进程明细），供卡巴式处置提示使用。
    """

    def __init__(self, path="", level="quarantine"):
        self.path = path
        self.level = level
        self.ok = False
        self.msg = ""
        self.steps = []            # [{"name","ok","msg"}]
        self.removed_residue = []  # [{"type","location","detail"}]
        self.need_reboot = False
        self.quarantine_id = ""
        self.killed = 0
        self.killed_msgs = []
        self.notification = ""

    def step(self, name, ok, msg=""):
        self.steps.append({"name": name, "ok": bool(ok), "msg": msg})
        logger.log("OK" if ok else "WARN", f"[处置:{name}] {msg}")
        return ok

    def to_dict(self):
        return {
            "path": self.path, "level": self.level, "ok": self.ok, "msg": self.msg,
            "steps": self.steps, "removed_residue": self.removed_residue,
            "need_reboot": self.need_reboot, "quarantine_id": self.quarantine_id,
            "killed": self.killed, "killed_msgs": self.killed_msgs,
            "notification": self.notification,
        }


def is_system_critical(path):
    """判断是否位于系统关键目录（处置时需要额外确认）。"""
    try:
        p = os.path.abspath(path).lower()
    except Exception:
        return False
    crit = [r"c:\windows", r"c:\program files", r"c:\program files (x86)",
            r"c:\windows\system32", r"c:\windows\syswow64"]
    return any(p.startswith(c + "\\") or p == c for c in crit)


def dispose_file(path, level=None, threat="", detection="", md5="", sha256="",
                 size=0, pids=None):
    """按处置链路处理单个威胁文件。返回 DisposeResult。"""
    level = level or str(config.get("dispose_level", "quarantine") or "quarantine")
    if level not in DISPOSE_LEVELS:
        level = "quarantine"
    res = DisposeResult(path=str(path), level=level)
    target_name = os.path.basename(str(path) or "")
    logger.warning(f"开始处置（{LEVEL_LABELS[level]}）: {path}")

    # ---------- ① 终止进程树（卡巴式：先杀进程，再隔离文件）----------
    try:
        killed, msgs = terminator.terminate_holders(str(path), extra_pids=pids)
        res.killed = killed
        res.killed_msgs = list(msgs or [])
        if killed:
            note = f"进程已终止（{killed} 个）"
            if res.killed_msgs:
                note += "：" + "；".join(str(m) for m in res.killed_msgs[:3])
            res.notification = note
            res.step("终止恶意进程", True, note)
        else:
            res.notification = "未发现占用进程，直接处置"
            res.step("终止恶意进程", True, "未发现占用进程")
    except Exception as e:
        res.notification = ""
        res.step("终止恶意进程", False, f"异常: {e}")

    # ---------- ②③④ 按档位处置 ----------
    if level == "quarantine":
        _dispose_quarantine(res, path, threat, detection, md5, sha256, size)
    elif level == "delete":
        _dispose_delete(res, path, target_name)
    else:
        _dispose_advanced(res, path, target_name)

    # ---------- ④ 残留清理（删除/高级清除必做；隔离也顺手清启动项） ----------
    try:
        removed, count = residue.clean_all(str(path), target_name)
        res.removed_residue = removed
        res.step("清理启动项/服务残留", True, f"清理 {count} 项")
    except Exception as e:
        res.step("清理启动项/服务残留", False, f"异常: {e}")

    if level == "advanced":
        try:
            deep = residue.scan_residue(str(path), target_name, depth_search=True)
            leftovers = [d for d in deep
                         if not any(d["detail"] == r.get("detail") for r in res.removed_residue)]
            if leftovers:
                res.step("深度残留扫描", True, f"另发现 {len(leftovers)} 项可疑残留，详见事件日志")
                res.removed_residue.extend(leftovers)
        except Exception:
            pass

    res.ok = res.msg.startswith("已") or "成功" in res.msg or res.need_reboot
    config.bump_stats(cleaned=1)
    logger.warning(f"处置完成（{LEVEL_LABELS[level]}）{path} -> {res.msg}")
    return res


def _dispose_quarantine(res, path, threat, detection, md5, sha256, size):
    ok, info = quarantine_mod.quarantine.quarantine_file(
        path, threat=threat, detection=detection, md5=md5, sha256=sha256, size=size)
    if ok and not isinstance(info, str):
        res.quarantine_id = getattr(info, "id", "")
        res.msg = "已隔离（可在隔离区恢复）"
        res.step("隔离文件", True, res.msg)
        return
    # 隔离失败（多为文件仍被占用）→ 退化为 PendMoves
    res.step("隔离文件", False, str(info))
    pok, pmsg = pendmoves.schedule_delete(path)
    res.need_reboot = pok
    res.msg = f"隔离失败，已登记重启删除：{pmsg}" if pok else f"隔离失败：{info}"
    res.step("登记重启删除", pok, pmsg)


def _dispose_delete(res, path, target_name):
    # 常规删除
    try:
        if os.path.exists(path):
            os.remove(path)
        res.msg = "已删除源文件"
        res.step("删除源文件", True, res.msg)
        return
    except Exception as e:
        res.step("删除源文件", False, f"{e}")
    # PendMoves 兜底
    pok, pmsg = pendmoves.schedule_delete(path)
    if pok:
        res.need_reboot = True
        res.msg = "文件被占用，已登记重启后删除"
        res.step("登记重启删除", True, pmsg)
        return
    res.msg = f"删除失败：{pmsg}"
    res.step("登记重启删除", False, pmsg)


def _dispose_advanced(res, path, target_name):
    ok, msg = nsudo.delete_file_ti(path)
    if ok and not os.path.exists(path):
        res.msg = "已用 TrustedInstaller 权限删除"
        res.step("提权删除（TrustedInstaller）", True, msg)
        return
    res.step("提权删除（TrustedInstaller）", False, msg)
    ok2, msg2 = nsudo.rename_and_delete_ti(path)
    if ok2 and not os.path.exists(path):
        res.msg = "已用 TrustedInstaller 权限改名后删除"
        res.step("提权改名删除", True, msg2)
        return
    res.step("提权改名删除", False, msg2)
    pok, pmsg = pendmoves.schedule_delete(path)
    if pok:
        res.need_reboot = True
        res.msg = "提权删除未完全成功，已登记重启后删除"
        res.step("登记重启删除", True, pmsg)
        return
    res.msg = f"高级清除未完成：{pmsg}"
    res.step("登记重启删除", False, pmsg)


def batch_dispose(paths, level=None, items=None):
    """批量处置。items 可为 ThreatItem 列表以带上威胁信息。返回 [DisposeResult]。"""
    out = []
    for p in (paths or []):
        info = {}
        for it in (items or []):
            if getattr(it, "path", "") == p:
                info = {"threat": getattr(it, "threat", ""),
                        "detection": getattr(it, "detection", ""),
                        "md5": getattr(it, "md5", ""),
                        "sha256": getattr(it, "sha256", ""),
                        "size": getattr(it, "size", 0)}
                break
        out.append(dispose_file(p, level=level, **info))
    return out
