# -*- coding: utf-8 -*-
"""信任项（v1.1.0）：路径 + SHA256 双哈希校验。

规则：
  * 加入信任时记录文件的规范化路径与 SHA256（小文件同时记录 MD5）。
  * 校验时要求"路径存在 且 SHA256 完全一致"才视为可信。
  * 文件一旦被篡改（内容变化），其 SHA256 不再匹配 → 信任自动失效，
    该项会被标记 invalid，并在下次扫描时重新作为可疑文件处理。
"""
import hashlib
import json
import os
import threading
import time
from pathlib import Path

from .config import DATA_DIR
from . import logger

TRUST_FILE = Path(DATA_DIR) / "trust.json"
_CHUNK = 1024 * 1024


def norm_path(path):
    """规范化路径用于比较（大小写不敏感）。"""
    try:
        return str(Path(path)).replace("/", "\\").lower()
    except Exception:
        return str(path or "").lower()


def file_sha256(path):
    """分块计算 SHA256，失败返回空串。"""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(_CHUNK)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except Exception:
        return ""


def file_md5(path):
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(_CHUNK)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except Exception:
        return ""


class TrustItem:
    def __init__(self, **kw):
        self.path = kw.get("path", "")
        self.sha256 = kw.get("sha256", "")
        self.md5 = kw.get("md5", "")
        self.size = kw.get("size", 0)
        self.reason = kw.get("reason", "手动信任")
        self.added = kw.get("added", "")
        self.invalid = bool(kw.get("invalid", False))
        self.invalid_reason = kw.get("invalid_reason", "")

    def to_dict(self):
        return {
            "path": self.path, "sha256": self.sha256, "md5": self.md5,
            "size": self.size, "reason": self.reason, "added": self.added,
            "invalid": self.invalid, "invalid_reason": self.invalid_reason,
        }


class Trust:
    def __init__(self, path=TRUST_FILE):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.items = []
        self.load()

    # ---------- 持久化 ----------
    def load(self):
        with self._lock:
            self.items = []
            if self.path.exists():
                try:
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                    self.items = [TrustItem(**it) for it in data.get("items", [])]
                except Exception:
                    self.items = []
            if not self.items:
                self._migrate_legacy()

    def save(self):
        with self._lock:
            try:
                self.path.write_text(
                    json.dumps({"items": [it.to_dict() for it in self.items]},
                               ensure_ascii=False, indent=2),
                    encoding="utf-8")
            except Exception as e:
                logger.warn(f"保存信任项失败: {e}")

    def _migrate_legacy(self):
        """从 v1.0.x 的 whitelist.json 迁移，补齐 SHA256。"""
        legacy = Path(DATA_DIR) / "whitelist.json"
        if not legacy.exists():
            return
        try:
            data = json.loads(legacy.read_text(encoding="utf-8"))
            old = data.get("items", [])
        except Exception:
            return
        migrated = 0
        for it in old:
            p = str(it.get("path", "") or "")
            if not p:
                continue
            sha = file_sha256(p) if os.path.isfile(p) else ""
            self.items.append(TrustItem(
                path=norm_path(p), sha256=sha, md5=str(it.get("md5", "") or ""),
                size=os.path.getsize(p) if os.path.isfile(p) else 0,
                reason=str(it.get("reason", "旧版白名单迁移")),
                added=str(it.get("added", "")) or time.strftime("%Y-%m-%d %H:%M:%S"),
                invalid=False if sha else True,
                invalid_reason="" if sha else "原文件不存在，无法计算哈希",
            ))
            migrated += 1
        if migrated:
            self.save()
            logger.info(f"已从旧白名单迁移 {migrated} 条信任项（补齐 SHA256）")

    # ---------- 增删查 ----------
    def add(self, path, reason="手动信任", capture_hash=True):
        """加入信任。返回 (ok, msg)。"""
        with self._lock:
            n = norm_path(path)
            for it in self.items:
                if norm_path(it.path) == n:
                    # 已存在 → 刷新哈希（用户明确信任该文件当前状态）
                    it.sha256 = file_sha256(path) if capture_hash else it.sha256
                    it.md5 = file_md5(path) if capture_hash else it.md5
                    it.size = os.path.getsize(path) if os.path.isfile(path) else it.size
                    it.invalid = False
                    it.invalid_reason = ""
                    it.added = time.strftime("%Y-%m-%d %H:%M:%S")
                    it.reason = reason
                    self.save()
                    return True, "已刷新信任项哈希"
            sha = file_sha256(path) if capture_hash else ""
            item = TrustItem(
                path=n, sha256=sha,
                md5=file_md5(path) if capture_hash else "",
                size=os.path.getsize(path) if os.path.isfile(path) else 0,
                reason=reason, added=time.strftime("%Y-%m-%d %H:%M:%S"),
                invalid=False if (sha or not capture_hash) else True,
                invalid_reason="" if (sha or not capture_hash) else "无法读取文件计算哈希",
            )
            self.items.append(item)
            self.save()
            logger.info(f"已加入信任（路径+SHA256）: {n} sha256={sha[:16] if sha else 'N/A'}")
            return True, "已加入信任"

    def remove(self, path):
        with self._lock:
            n = norm_path(path)
            before = len(self.items)
            self.items = [it for it in self.items if norm_path(it.path) != n]
            if len(self.items) != before:
                self.save()
                logger.info(f"已移除信任: {n}")
                return True
            return False

    def verify(self, path):
        """校验某路径当前是否仍然可信。返回 (ok, msg)。"""
        with self._lock:
            n = norm_path(path)
            for it in self.items:
                if norm_path(it.path) != n:
                    continue
                if not os.path.isfile(path):
                    return False, "文件不存在"
                if not it.sha256:
                    return True, "无哈希记录（旧项放行）"
                cur = file_sha256(path)
                if not cur:
                    return False, "无法读取文件"
                if cur.lower() == it.sha256.lower():
                    return True, "路径与 SHA256 均匹配"
                return False, "SHA256 不匹配 —— 文件已被篡改，信任失效"
            return False, "不在信任列表"

    def contains(self, path):
        """扫描时调用：只有路径 + SHA256 都匹配才跳过。"""
        ok, msg = self.verify(path)
        if not ok and msg.startswith("SHA256 不匹配"):
            self._mark_invalid(path, msg)
        return ok

    def _mark_invalid(self, path, reason):
        n = norm_path(path)
        changed = False
        for it in self.items:
            if norm_path(it.path) == n and not it.invalid:
                it.invalid = True
                it.invalid_reason = reason
                changed = True
        if changed:
            self.save()
            logger.warning(f"信任项已失效（文件被篡改）: {n}")

    def refresh_all(self):
        """全量重校验：返回失效条目数。"""
        invalid = 0
        with self._lock:
            for it in self.items:
                if not it.sha256:
                    continue
                p = it.path
                if not os.path.isfile(p):
                    it.invalid = True
                    it.invalid_reason = "文件不存在"
                    invalid += 1
                    continue
                cur = file_sha256(p)
                if cur and cur.lower() == it.sha256.lower():
                    it.invalid = False
                    it.invalid_reason = ""
                else:
                    it.invalid = True
                    it.invalid_reason = "SHA256 不匹配（文件已变化）"
                    invalid += 1
            self.save()
        return invalid

    def list_items(self, only_invalid=False):
        with self._lock:
            return [it for it in self.items if (it.invalid if only_invalid else True)]

    @property
    def count(self):
        return len(self.items)

    @property
    def invalid_count(self):
        return sum(1 for it in self.items if it.invalid)


# 全局单例
trust = Trust()
