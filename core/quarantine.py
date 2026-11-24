# -*- coding: utf-8 -*-
"""隔离区：将威胁文件安全转移至隔离目录，支持恢复 / 彻底删除 / 列表。"""
import json
import os
import shutil
import time
import uuid
import threading
from pathlib import Path

from .config import QUARANTINE_DIR
from . import logger


class QuarantineItem:
    def __init__(self, **kw):
        self.id = kw.get("id", "")
        self.orig_path = kw.get("orig_path", "")
        self.quar_path = kw.get("quar_path", "")
        self.threat = kw.get("threat", "")
        self.detection = kw.get("detection", "")
        self.md5 = kw.get("md5", "")
        self.sha256 = kw.get("sha256", "")
        self.size = kw.get("size", 0)
        self.time = kw.get("time", "")

    def to_dict(self):
        return {
            "id": self.id,
            "orig_path": self.orig_path,
            "quar_path": self.quar_path,
            "threat": self.threat,
            "detection": self.detection,
            "md5": self.md5,
            "sha256": self.sha256,
            "size": self.size,
            "time": self.time,
        }


class Quarantine:
    """隔离区管理器。文件以 {id}.quar 存在 QUARANTINE_DIR，meta 存 {id}.json。"""

    def __init__(self, base: Path = QUARANTINE_DIR):
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def list_items(self):
        with self._lock:
            items = []
            for meta in self.base.glob("*.json"):
                try:
                    data = json.loads(meta.read_text(encoding="utf-8"))
                    items.append(QuarantineItem(**data))
                except Exception:
                    continue
            items.sort(key=lambda x: x.time, reverse=True)
            return items

    def quarantine_file(self, path, threat="", detection="", md5="", sha256="", size=0):
        """把威胁文件复制进隔离区，原文件删除。返回 (ok, msg or QuarantineItem)。"""
        src = Path(path)
        with self._lock:
            if not src.exists():
                return False, "原文件不存在"
            qid = uuid.uuid4().hex[:12]
            quar_file = self.base / f"{qid}.quar"
            try:
                shutil.copy2(src, quar_file)
            except Exception as e:
                return False, f"隔离失败: {e}"
            item = QuarantineItem(
                id=qid,
                orig_path=str(src),
                quar_path=str(quar_file),
                threat=threat,
                detection=detection,
                md5=md5,
                sha256=sha256,
                size=size,
                time=time.strftime("%Y-%m-%d %H:%M:%S"),
            )
            meta = self.base / f"{qid}.json"
            meta.write_text(json.dumps(item.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
            # 删除原文件（可回滚：隔离副本还在）
            try:
                src.unlink()
            except Exception as e:
                logger.warn(f"隔离后删除原文件失败 {src}: {e}")
            logger.warning(f"已隔离: {src} -> {quar_file} ({threat})")
            return True, item

    def restore(self, qid):
        """恢复：隔离副本复制回原路径。返回 (ok, msg)。"""
        with self._lock:
            item = self._load(qid)
            if not item:
                return False, "隔离记录不存在"
            orig = Path(item.orig_path)
            quar = Path(item.quar_path)
            if not quar.exists():
                return False, "隔离文件已丢失"
            if orig.exists():
                return False, f"原位置已有文件，请先处理: {orig}"
            try:
                orig.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(quar, orig)
                quar.unlink()
                (self.base / f"{qid}.json").unlink()
                logger.info(f"已恢复: {orig}")
                return True, f"已恢复到 {orig}"
            except Exception as e:
                return False, f"恢复失败: {e}"

    def delete_forever(self, qid):
        """彻底删除隔离文件。"""
        with self._lock:
            item = self._load(qid)
            if not item:
                return False, "隔离记录不存在"
            quar = Path(item.quar_path)
            removed = False
            try:
                if quar.exists():
                    quar.unlink()
                    removed = True
            except Exception:
                pass
            meta = self.base / f"{qid}.json"
            if meta.exists():
                try:
                    meta.unlink()
                except Exception:
                    pass
            logger.warning(f"已彻底删除隔离文件: {item.orig_path}")
            return removed, "已彻底删除"

    def _load(self, qid):
        meta = self.base / f"{qid}.json"
        if not meta.exists():
            return None
        try:
            return QuarantineItem(**json.loads(meta.read_text(encoding="utf-8")))
        except Exception:
            return None

    @property
    def count(self):
        return len(self.list_items())


# 全局单例
quarantine = Quarantine()
