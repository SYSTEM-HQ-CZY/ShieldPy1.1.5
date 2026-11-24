# -*- coding: utf-8 -*-
"""病毒特征库：基于文件哈希（MD5/SHA256）的精确匹配，支持 JSON 存储、增删查。"""
import hashlib
import json
import time
import threading
from pathlib import Path

from .config import SIGNATURE_FILE
from . import logger


class SignatureDB:
    """哈希特征库。记录结构: {name, md5, sha256, type, desc, added}"""

    def __init__(self, path: Path = SIGNATURE_FILE):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.signatures = []      # 全量列表
        self._index = {}          # (md5, sha256) -> record
        self.version = "1.0.0"
        self.updated = ""
        self.load()

    def load(self):
        with self._lock:
            self.signatures = []
            self._index = {}
            if self.path.exists():
                try:
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                    self.version = data.get("version", "1.0.0")
                    self.updated = data.get("updated", "")
                    for rec in data.get("signatures", []):
                        self._add_index(rec)
                except Exception as e:
                    logger.warn(f"特征库加载失败: {e}")
            logger.info(f"特征库已加载: {len(self.signatures)} 条")

    def _add_index(self, rec):
        self.signatures.append(rec)
        md5 = (rec.get("md5") or "").lower()
        sha = (rec.get("sha256") or "").lower()
        if md5:
            self._index.setdefault(("md5", md5), rec)
        if sha:
            self._index.setdefault(("sha256", sha), rec)

    def save(self):
        with self._lock:
            data = {
                "version": self.version,
                "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
                "count": len(self.signatures),
                "signatures": self.signatures,
            }
            self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            self.updated = data["updated"]

    # ---- 查询 ----
    def lookup_md5(self, md5):
        return self._index.get(("md5", (md5 or "").lower()))

    def lookup_sha256(self, sha256):
        return self._index.get(("sha256", (sha256 or "").lower()))

    def lookup(self, md5=None, sha256=None):
        rec = self.lookup_md5(md5) or self.lookup_sha256(sha256)
        return rec

    # ---- 维护 ----
    def add(self, name, md5="", sha256="", vtype="unknown", desc=""):
        with self._lock:
            if self.lookup(md5=md5, sha256=sha256):
                return False, "该哈希已在特征库中"
            rec = {
                "name": name,
                "md5": (md5 or "").lower(),
                "sha256": (sha256 or "").lower(),
                "type": vtype,
                "desc": desc,
                "added": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._add_index(rec)
            self.save()
            logger.success(f"已添加特征: {name}")
            return True, "添加成功"

    def remove_by_md5(self, md5):
        with self._lock:
            md5 = (md5 or "").lower()
            before = len(self.signatures)
            self.signatures = [r for r in self.signatures if (r.get("md5") or "").lower() != md5]
            self._index = {}
            for r in self.signatures:
                self._index.setdefault(("md5", (r.get("md5") or "").lower()), r)
                self._index.setdefault(("sha256", (r.get("sha256") or "").lower()), r)
            if len(self.signatures) != before:
                self.save()
                return True
            return False

    @property
    def count(self):
        return len(self.signatures)


# 全局单例
signature_db = SignatureDB()


def file_hashes(path: Path):
    """一次性返回 (md5, sha256)。"""
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                md5.update(chunk)
                sha.update(chunk)
        return md5.hexdigest(), sha.hexdigest()
    except Exception:
        return None, None
