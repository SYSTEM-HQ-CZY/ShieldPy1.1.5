# -*- coding: utf-8 -*-
"""防勒索快照备份与手动回滚（v1.1.0）。

机制：
    * 快照 = 受保护目录 / 指定目录内文件的 SHA256 + 内容副本（按哈希去重存放）。
    * 回滚 = 逐文件比对当前 SHA256：不一致（被加密/篡改）或文件缺失，就从快照还原；
      被覆盖前的"坏版本"另存为 rollback_backup，便于事后取证。
    * 体积保护：单文件上限（默认 20MB）、快照总量上限（默认 500MB）。
"""
import hashlib
import json
import os
import shutil
import threading
import time
import uuid
from pathlib import Path

from . import logger
from .config import DATA_DIR, config

SNAP_DIR = Path(DATA_DIR) / "snapshots"
SNAP_DIR.mkdir(parents=True, exist_ok=True)

# 值得备份的数据类扩展名（快照不备份可执行文件，避免体积失控）
BACKUP_EXTS = {
    ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm",
    ".pdf", ".txt", ".md", ".rtf", ".csv", ".json", ".xml", ".ini", ".cfg",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".heic", ".webp",
    ".mp3", ".wav", ".flac", ".m4a", ".aac",
    ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv",
    ".zip", ".7z", ".rar", ".tar", ".gz",
    ".py", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ".pst", ".ost", ".db", ".sqlite", ".kdbx", ".pem", ".key",
}


def _sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(1024 * 1024)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except Exception:
        return ""


class SnapshotManager:
    def __init__(self):
        self._lock = threading.RLock()
        self.last_result = None

    # ---------- 创建 ----------
    def create(self, label="手动快照", folders=None, max_file_mb=20, max_total_mb=500,
               exts=None):
        """创建快照。返回 dict 结果。"""
        with self._lock:
            sid = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
            root = SNAP_DIR / sid
            files_dir = root / "files"
            files_dir.mkdir(parents=True, exist_ok=True)

            if folders:
                targets = [os.path.abspath(f) for f in folders if os.path.isdir(f)]
            else:
                from .protected import protected
                targets = [os.path.abspath(f) for f in protected.folders if os.path.isdir(f)]

            allowed_exts = set(exts) if exts else BACKUP_EXTS
            max_file = int(max_file_mb) * 1024 * 1024
            max_total = int(max_total_mb) * 1024 * 1024
            total = 0
            entries = []
            skipped_big = 0
            skipped_type = 0

            for base in targets:
                for dirpath, dirnames, filenames in os.walk(base):
                    dirnames[:] = [d for d in dirnames
                                   if not d.lower().startswith(("$", "."))]
                    for fn in filenames:
                        full = os.path.join(dirpath, fn)
                        ext = os.path.splitext(fn)[1].lower()
                        if ext not in allowed_exts:
                            skipped_type += 1
                            continue
                        try:
                            size = os.path.getsize(full)
                        except Exception:
                            continue
                        if size <= 0 or size > max_file:
                            skipped_big += 1
                            continue
                        if total + size > max_total:
                            logger.warn("快照达到总量上限，提前结束")
                            break
                        sha = _sha256(full)
                        if not sha:
                            continue
                        blob = files_dir / sha
                        if not blob.exists():
                            try:
                                shutil.copy2(full, blob)
                            except Exception:
                                continue
                            total += size
                        entries.append({
                            "path": full, "sha256": sha, "size": size,
                            "mtime": int(os.path.getmtime(full)),
                            "stored": sha,
                        })

            manifest = {
                "id": sid,
                "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                "label": label,
                "folders": targets,
                "files": entries,
                "file_count": len(entries),
                "total_bytes": total,
                "max_file_mb": max_file_mb,
                "max_total_mb": max_total_mb,
                "skipped_big": skipped_big,
                "skipped_type": skipped_type,
            }
            try:
                (root / "manifest.json").write_text(
                    json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception as e:
                return {"ok": False, "msg": f"写入清单失败: {e}"}

            logger.warning(f"已创建快照 {sid}：{len(entries)} 个文件，"
                           f"{total / 1024 / 1024:.1f} MB")
            self.last_result = {"ok": True, "id": sid, "count": len(entries),
                                "bytes": total, "msg": f"已备份 {len(entries)} 个文件"}
            return self.last_result

    # ---------- 列表 ----------
    def list_snapshots(self):
        out = []
        try:
            for d in sorted(SNAP_DIR.glob("*"), reverse=True):
                mf = d / "manifest.json"
                if not mf.exists():
                    continue
                try:
                    data = json.loads(mf.read_text(encoding="utf-8"))
                    out.append({
                        "id": data.get("id", d.name),
                        "created": data.get("created", ""),
                        "label": data.get("label", ""),
                        "count": data.get("file_count", 0),
                        "bytes": data.get("total_bytes", 0),
                        "folders": data.get("folders", []),
                    })
                except Exception:
                    continue
        except Exception:
            pass
        return out

    def _load(self, sid):
        mf = SNAP_DIR / sid / "manifest.json"
        if not mf.exists():
            return None
        try:
            return json.loads(mf.read_text(encoding="utf-8"))
        except Exception:
            return None

    # ---------- 回滚 ----------
    def rollback(self, sid, keep_bad=True):
        """按快照还原。返回 dict：{ok, restored[], kept[], failed[], msg}"""
        with self._lock:
            m = self._load(sid)
            if not m:
                return {"ok": False, "msg": "快照不存在或清单损坏",
                        "restored": [], "failed": []}
            files_dir = SNAP_DIR / sid / "files"
            bad_dir = SNAP_DIR / sid / "rollback_backup"
            restored, failed, unchanged = [], [], 0
            for e in m.get("files", []):
                path, sha = e.get("path"), e.get("sha256")
                blob = files_dir / str(e.get("stored") or sha or "")
                if not blob.exists():
                    continue
                cur = _sha256(path) if os.path.isfile(path) else ""
                if cur == sha:
                    unchanged += 1
                    continue
                try:
                    parent = os.path.dirname(path)
                    if parent:
                        os.makedirs(parent, exist_ok=True)
                    if keep_bad and os.path.isfile(path) and cur:
                        bad_dir.mkdir(parents=True, exist_ok=True)
                        try:
                            shutil.copy2(path, bad_dir / (os.path.basename(path) + "." + cur[:8]))
                        except Exception:
                            pass
                    shutil.copy2(blob, path)
                    os.utime(path, (e.get("mtime", time.time()), e.get("mtime", time.time())))
                    restored.append(path)
                    logger.warning(f"已回滚: {path}")
                except Exception as ex:
                    failed.append({"path": path, "error": str(ex)})
                    logger.warn(f"回滚失败 {path}: {ex}")
            msg = f"回滚完成：还原 {len(restored)} 个，未变 {unchanged} 个，失败 {len(failed)} 个"
            logger.warning(msg)
            return {"ok": not failed, "restored": restored, "failed": failed,
                    "unchanged": unchanged, "msg": msg}

    def delete_snapshot(self, sid):
        with self._lock:
            d = SNAP_DIR / sid
            if not d.exists():
                return False, "快照不存在"
            try:
                shutil.rmtree(d)
                logger.warning(f"已删除快照 {sid}")
                return True, "已删除"
            except Exception as e:
                return False, str(e)

    def stats(self):
        snaps = self.list_snapshots()
        total = sum(s.get("bytes", 0) for s in snaps)
        return {"count": len(snaps), "bytes": total,
                "dir": str(SNAP_DIR), "enabled": bool(config.get("snapshot_enabled", True))}


# 全局单例
snapshot = SnapshotManager()
