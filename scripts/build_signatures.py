# -*- coding: utf-8 -*-
"""构建内置特征库 data/signatures.json（自动计算 EICAR 测试样本的精确哈希）。
用法: python scripts/build_signatures.py
"""
import hashlib
import json
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DATA_DIR = BASE / "data"

# 标准 EICAR 测试文件内容（杀软行业通用测试样本，非真实病毒）
EICAR_BYTES = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def main():
    md5 = hashlib.md5(EICAR_BYTES).hexdigest()
    sha256 = hashlib.sha256(EICAR_BYTES).hexdigest()

    signatures = [
        {
            "name": "EICAR-Test-File (标准杀软测试样本)",
            "md5": md5,
            "sha256": sha256,
            "type": "test",
            "desc": "EICAR 标准防病毒测试文件，用于验证杀毒软件是否正常工作，本身无害。",
            "added": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
    ]

    data = {
        "version": "1.0.0",
        "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(signatures),
        "signatures": signatures,
    }
    out = DATA_DIR / "signatures.json"
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[OK] 特征库已生成: {out}")
    print(f"     EICAR MD5    = {md5}")
    print(f"     EICAR SHA256 = {sha256}")
    print(f"     共 {len(signatures)} 条特征")
    return 0


if __name__ == "__main__":
    sys.exit(main())
