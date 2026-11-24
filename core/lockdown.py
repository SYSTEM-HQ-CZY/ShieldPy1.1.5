# -*- coding: utf-8 -*-
"""原地锁定（v1.1.0）：可疑文件"只允许存在、不允许运行"。

适用场景：双击才运行的木马（用户不双击就没事，但文件本身是活的），
删掉可能毁掉证据/用户的文件，于是原地"冰封"：

    改所有者 → NT AUTHORITY\\SYSTEM
    追加 ACL → 拒绝 Everyone 执行（(X)）
    锁定前保存原始所有者 + DACL 快照，放行时原样还原

安全边界（硬性）：
    * 只对 **用户目录**（%USERPROFILE% 及桌面/下载/文档/图片/视频）生效
    * 系统目录（C:\\Windows、Program Files 等）一律禁用，直接拒绝
"""
import ctypes
import json
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path

from . import logger, nsudo
from .config import DATA_DIR

LOCKS_DIR = Path(DATA_DIR) / "locks"
LOCKS_DIR.mkdir(parents=True, exist_ok=True)
LOCK_INDEX = LOCKS_DIR / "index.json"

SYSTEM_DIRS = [
    r"c:\windows", r"c:\program files", r"c:\program files (x86)",
    r"c:\programdata", r"c:\$recycle.bin",
]


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def user_home():
    return os.environ.get("USERPROFILE") or str(Path.home())


def user_dirs():
    """允许锁定的用户目录白名单（含子目录）。"""
    home = user_home()
    out = [home]
    for sub in ("Desktop", "桌面", "Downloads", "下载", "Documents", "文档",
                "Pictures", "图片", "Videos", "视频", "Music", "音乐"):
        p = os.path.join(home, sub)
        if os.path.isdir(p):
            out.append(p)
    return [os.path.normcase(os.path.abspath(d)) for d in out]


def can_lock(path):
    """检查路径是否允许原地锁定。返回 (ok, reason)。"""
    try:
        p = os.path.normcase(os.path.abspath(path))
    except Exception:
        return False, "非法路径"
    for sd in SYSTEM_DIRS:
        if p.startswith(sd + "\\") or p == sd:
            return False, "系统目录禁止锁定（原地锁定仅作用于用户目录）"
    for ud in user_dirs():
        if p == ud or p.startswith(ud + "\\"):
            if not os.path.isfile(path):
                return False, "目标不是文件"
            return True, ""
    return False, "不在用户目录范围内（原地锁定仅作用于用户目录）"


class LockRecord:
    def __init__(self, **kw):
        self.id = kw.get("id", "")
        self.path = kw.get("path", "")
        self.owner_before = kw.get("owner_before", "")
        self.acl_file = kw.get("acl_file", "")
        self.locked_at = kw.get("locked_at", "")
        self.reason = kw.get("reason", "")
        self.size = kw.get("size", 0)
        self.sha256 = kw.get("sha256", "")

    def to_dict(self):
        return {"id": self.id, "path": self.path, "owner_before": self.owner_before,
                "acl_file": self.acl_file, "locked_at": self.locked_at,
                "reason": self.reason, "size": self.size, "sha256": self.sha256}


class Lockdown:
    def __init__(self):
        self._lock = threading.RLock()
        self.records = []
        self.load()

    # ---------- 索引 ----------
    def load(self):
        with self._lock:
            self.records = []
            if LOCK_INDEX.exists():
                try:
                    data = json.loads(LOCK_INDEX.read_text(encoding="utf-8"))
                    self.records = [LockRecord(**it) for it in data.get("items", [])]
                except Exception:
                    self.records = []

    def save(self):
        with self._lock:
            try:
                LOCK_INDEX.write_text(
                    json.dumps({"items": [r.to_dict() for r in self.records]},
                               ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception as e:
                logger.warn(f"保存锁定索引失败: {e}")

    # ---------- 内部：icacls 调用 ----------
    def _run_elevated(self, cmdline, purpose):
        """管理员→直接执行；否则经 NSudo 提权。返回 (ok, output)。"""
        if is_admin():
            try:
                r = subprocess.run(cmdline, capture_output=True, timeout=90,
                                   universal_newlines=True, creationflags=0x08000000)
                out = ((r.stdout or "") + (r.stderr or "")).strip()
                return r.returncode == 0, out
            except Exception as e:
                return False, str(e)
        return nsudo.run(cmdline, timeout=90, purpose=purpose)

    def _query_owner(self, path):
        """取当前所有者（icacls 输出中的第一行）。"""
        try:
            r = subprocess.run(["icacls", path], capture_output=True, timeout=30,
                               universal_newlines=True, creationflags=0x08000000)
            first = (r.stdout or "").strip().splitlines()[0]
            # 输出形如  C:\path\file  DOMAIN\user
            if " " in first:
                parts = first.rsplit(" ", 1)
                if len(parts) == 2 and ("\\" in parts[1] or parts[1] == "BUILTIN\\Administrators"):
                    return parts[1].strip()
            return ""
        except Exception:
            return ""

    # ---------- 锁定 ----------
    def lock(self, path, reason="可疑文件原地锁定"):
        """锁定文件（改所有者 SYSTEM + 拒绝执行）。返回 (ok, msg or LockRecord)。"""
        ok, why = can_lock(path)
        if not ok:
            return False, why
        with self._lock:
            for r in self.records:
                if os.path.normcase(r.path) == os.path.normcase(os.path.abspath(path)):
                    return False, "该文件已被锁定"
            rid = uuid.uuid4().hex[:10]
            snap_dir = LOCKS_DIR / rid
            snap_dir.mkdir(parents=True, exist_ok=True)
            acl_file = snap_dir / "acl.txt"
            parent = os.path.dirname(os.path.abspath(path))
            owner_before = self._query_owner(path)

            # ① 保存 DACL 快照
            ok_save, out_save = self._run_elevated(
                f'icacls "{path}" /save "{acl_file}"', "保存权限快照")
            if not ok_save:
                logger.warn(f"保存 ACL 快照失败（继续尝试锁定）: {out_save}")

            # ② 改所有者 → SYSTEM
            ok_own, out_own = self._run_elevated(
                f'icacls "{path}" /setowner "NT AUTHORITY\\SYSTEM"', "改所有者为 System")
            if not ok_own:
                ok_own, out_own = self._run_elevated(
                    f'takeown /f "{path}" /a', "takeown 改所有者")

            # ③ 拒绝 Everyone 执行
            ok_deny, out_deny = self._run_elevated(
                f'icacls "{path}" /deny "*S-1-1-0:(X)"', "拒绝 Everyone 执行")

            if not (ok_own or ok_deny):
                logger.warn(f"原地锁定失败 {path}: {out_own} | {out_deny}")
                return False, f"锁定失败：{out_own or out_deny}"

            from .trust import file_sha256
            rec = LockRecord(
                id=rid, path=os.path.abspath(path), owner_before=owner_before,
                acl_file=str(acl_file), locked_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                reason=reason, size=os.path.getsize(path) if os.path.isfile(path) else 0,
                sha256=file_sha256(path))
            self.records.append(rec)
            self.save()
            logger.warning(f"已原地锁定: {path}（所有者→System，拒绝执行；快照 {acl_file}）")
            return True, rec

    # ---------- 放行 ----------
    def unlock(self, rid_or_path):
        """还原权限快照并恢复所有者。返回 (ok, msg)。"""
        with self._lock:
            rec = None
            for r in self.records:
                if r.id == rid_or_path or \
                        os.path.normcase(r.path) == os.path.normcase(str(rid_or_path)):
                    rec = r
                    break
            if not rec:
                return False, "未找到该锁定记录"
            parent = os.path.dirname(rec.path)
            msgs = []

            # ① 先给我自己（管理员/TI）放行，否则可能读不到文件
            self._run_elevated(f'icacls "{rec.path}" /grant "*S-1-5-32-544:(F)"', "放行管理员")

            # ② 还原 DACL
            acl_file = Path(rec.acl_file)
            restored = False
            if acl_file.exists():
                ok_r, out_r = self._run_elevated(
                    f'icacls "{parent}" /restore "{acl_file}"', "还原权限快照")
                restored = ok_r
                msgs.append(f"ACL还原:{'OK' if ok_r else out_r}")
            else:
                msgs.append("ACL快照缺失，回退为直接授权")

            # ③ 恢复所有者
            if rec.owner_before:
                ok_o, out_o = self._run_elevated(
                    f'icacls "{rec.path}" /setowner "{rec.owner_before}"', "恢复所有者")
                msgs.append(f"所有者:{'OK' if ok_o else out_o}")
            if not restored:
                self._run_elevated(
                    f'icacls "{rec.path}" /grant "*S-1-1-0:(RX)"', "放行 Everyone 读取执行")

            self.records = [r for r in self.records if r.id != rec.id]
            self.save()
            logger.warning(f"已放行（还原权限）: {rec.path} | {' ; '.join(msgs)}")
            return True, f"已放行并还原权限（{' ; '.join(msgs)}）"

    def list_records(self):
        with self._lock:
            return list(self.records)

    def is_locked(self, path):
        n = os.path.normcase(os.path.abspath(path))
        return any(os.path.normcase(r.path) == n for r in self.records)

    @property
    def count(self):
        return len(self.records)


# 全局单例
lockdown = Lockdown()
