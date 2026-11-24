# -*- coding: utf-8 -*-
"""主动防御引擎测试（v1.0.55）。"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from core.config import config
from core.monitor import monitor, DefenseEvent
from core.scanner import engine
from core.quarantine import quarantine

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class TestMonitor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="shielpy_test_")
        self.eicar_path = os.path.join(self.tmp, "eicar.com")
        with open(self.eicar_path, "wb") as f:
            f.write(EICAR)
        monitor.clear_events()
        # 确保监控不在运行（若上一测试遗留则停止）
        if monitor.running:
            monitor.stop()

    def tearDown(self):
        if monitor.running:
            monitor.stop()
        for f in os.listdir(self.tmp):
            try:
                os.remove(os.path.join(self.tmp, f))
            except Exception:
                pass
        os.rmdir(self.tmp)
        # 清理隔离区中本次测试产物
        for it in quarantine.list_items():
            try:
                quarantine.restore(it.id)
            except Exception:
                pass
        monitor.clear_events()

    # ---------- 范围计算 ----------
    def test_all_drives(self):
        drives = monitor.all_drives()
        self.assertTrue(drives)
        self.assertTrue(all(d.endswith(":\\") for d in drives))

    def test_key_dirs(self):
        dirs = monitor.key_dirs()
        self.assertIsInstance(dirs, list)
        self.assertTrue(dirs)

    # ---------- 启停 ----------
    def test_start_stop_custom(self):
        ok, msg = monitor.start(dirs=[self.tmp], scope="custom")
        self.assertTrue(ok, msg)
        self.assertTrue(monitor.running)
        monitor.stop()
        self.assertFalse(monitor.running)

    def test_start_default_full(self):
        # 默认无参数应计算全盘（不真正长时间运行，启动后立即停止）
        ok, msg = monitor.start()
        self.assertTrue(ok, msg)
        self.assertTrue(monitor.running)
        monitor.stop()
        self.assertFalse(monitor.running)

    # ---------- 辅助防御 ----------
    def test_startup_snapshot(self):
        snap = monitor._startup_snapshot()
        self.assertIsInstance(snap, dict)

    def test_hosts_state(self):
        st = monitor._hosts_state()
        # hosts 存在则返回 (size, mtime)，否则 None；两种都算合法
        self.assertTrue(st is None or (isinstance(st, tuple) and len(st) == 2))

    # ---------- 事件记录 ----------
    def test_log_event(self):
        monitor._log_event(DefenseEvent("file", "C:\\x.exe", "已自动隔离", "Test", "high"))
        self.assertEqual(len(monitor.events), 1)
        self.assertEqual(monitor.events[0].kind, "file")
        monitor.clear_events()
        self.assertEqual(len(monitor.events), 0)

    # ---------- 自动处置 ----------
    def test_handle_threat_quarantine(self):
        old = config.get("realtime_auto_action", "quarantine")
        config.set("realtime_auto_action", "quarantine")
        try:
            item = engine.scan_file(self.eicar_path)
            self.assertIsNotNone(item)
            monitor._handle_threat(item)
            # eicar 已被隔离（原路径不存在）
            self.assertFalse(os.path.exists(self.eicar_path))
            self.assertTrue(monitor.events)
            self.assertEqual(monitor.events[0].action, "已自动隔离")
        finally:
            config.set("realtime_auto_action", old)

    def test_handle_threat_alert(self):
        old = config.get("realtime_auto_action", "quarantine")
        config.set("realtime_auto_action", "alert")
        try:
            # 重新生成 eicar
            with open(self.eicar_path, "wb") as f:
                f.write(EICAR)
            item = engine.scan_file(self.eicar_path)
            self.assertIsNotNone(item)
            monitor._handle_threat(item)
            # 仅告警：文件保留
            self.assertTrue(os.path.exists(self.eicar_path))
            self.assertTrue(monitor.events)
            self.assertEqual(monitor.events[0].action, "仅告警")
        finally:
            config.set("realtime_auto_action", old)


if __name__ == "__main__":
    unittest.main()
