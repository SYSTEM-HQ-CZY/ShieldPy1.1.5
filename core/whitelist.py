# -*- coding: utf-8 -*-
"""白名单：按文件路径（规范化）+ 可选哈希，命中则跳过扫描。"""
import json
import threading
from pathlib import Path

from .config import WHITELIST_FILE
from . import logger


def _norm(path: str) -> str:
    p = Path(path or "").resolve()
    return str(p).lower()


class Whitelist:
    def __init__(self, path: Path = WHITELIST_FILE):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.items = []     # [{"path":..., "md5":..., "reason":..., "added":...}]
        self.load()

    def load(self):
        with self._lock:
            self.items = []
            if self.path.exists():
                try:
                    data = json.loads(self.path.read_text(encoding="utf-8"))
                    self.items = data.get("items", [])
                except Exception:
                    self.items = []

    def save(self):
        with self._lock:
            self.path.write_text(
                json.dumps({"items": self.items}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

    def contains(self, path: str, md5: str = "") -> bool:
        with self._lock:
            n = _norm(path)
            for it in self.items:
                if _norm(it.get("path", "")) == n:
                    return True
                if md5 and it.get("md5") and it.get("md5", "").lower() == md5.lower():
                    return True
            return False

    def add(self, path: str, md5: str = "", reason: str = "手动信任"):
        with self._lock:
            n = _norm(path)
            for it in self.items:
                if _norm(it.get("path", "")) == n:
                    return False, "已存在于白名单"
            import time
            self.items.append({
                "path": n,
                "md5": (md5 or "").lower(),
                "reason": reason,
                "added": time.strftime("%Y-%m-%d %H:%M:%S"),
            })
            self.save()
            logger.info(f"已加入白名单: {n}")
            return True, "已加入白名单"

    def remove(self, path: str):
        with self._lock:
            n = _norm(path)
            before = len(self.items)
            self.items = [it for it in self.items if _norm(it.get("path", "")) != n]
            if len(self.items) != before:
                self.save()
                return True
            return False

    @property
    def count(self):
        return len(self.items)


# 全局单例
whitelist = Whitelist()
