# -*- coding: utf-8 -*-
"""YARA 规则引擎接入（v1.1.0）。

* 规则目录：data/yara/*.yar|*.yara，可直接放入 Loki / Neo23x0 的 YARA 规则。
* 首次启动会自动落盘一份基础规则（shieldpy_base.yar），覆盖测试文件、
  勒索行为文案、脚本下载执行等高价值特征。
* 规则按文件 mtime 缓存编译结果，规则变更后自动重新编译。
"""
import os
import time
from pathlib import Path

from . import logger
from .config import DATA_DIR

try:
    import yara
    HAS_YARA = True
except Exception:
    yara = None
    HAS_YARA = False

YARA_DIR = Path(DATA_DIR) / "yara"
YARA_DIR.mkdir(parents=True, exist_ok=True)

BASE_RULE_FILE = YARA_DIR / "shieldpy_base.yar"

BASE_RULES = r"""
/*
  ShieldPy 基础 YARA 规则集（v1.1.0）
  可自由追加/替换为 Loki、Neo23x0 signature-base 等开源规则。
*/
rule EICAR_Test_File
{
    meta:
        description = "EICAR 反病毒测试文件"
        severity = "high"
    strings:
        $e1 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $e2 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    condition:
        any of them
}

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "PowerShell 编码命令（隐藏执行）"
        severity = "high"
    strings:
        $p1 = "powershell" nocase ascii
        $p2 = "-enc" ascii nocase
        $p3 = "-nop" ascii nocase
        $p4 = "-w hidden" ascii nocase
    condition:
        2 of them
}

rule Suspicious_ShadowCopy_Deletion
{
    meta:
        description = "卷影副本删除/备份破坏"
        severity = "high"
    strings:
        $s1 = "vssadmin" ascii nocase
        $s2 = "delete shadows" ascii nocase
        $s3 = "wmic shadowcopy delete" ascii nocase
        $s4 = "wbadmin delete catalog" ascii nocase
        $s5 = "bcdedit" ascii nocase
        $s6 = "recoveryenabled" ascii nocase
    condition:
        ($s1 and $s2) or $s3 or $s4 or ($s5 and $s6)
}

rule Ransomware_Note_Keyword
{
    meta:
        description = "勒索说明文件特征文案"
        severity = "high"
    strings:
        $r1 = "your files have been encrypted" ascii nocase
        $r2 = "all your files" ascii nocase
        $r3 = "to decrypt" ascii nocase
        $r4 = "bitcoin" ascii nocase
        $r5 = "BTC address" ascii nocase
        $r6 = "recover your files" ascii nocase
    condition:
        2 of them
}

rule Script_Download_And_Execute
{
    meta:
        description = "脚本下载并执行载荷"
        severity = "medium"
    strings:
        $d1 = "DownloadFile" ascii nocase
        $d2 = "Invoke-WebRequest" ascii nocase
        $d3 = "XMLHTTP" ascii nocase
        $d4 = "ADODB.Stream" ascii nocase
        $d5 = "ShellExecute" ascii nocase
        $d6 = "WScript.Shell" ascii nocase
        $d7 = "http://" ascii
        $d8 = "https://" ascii
    condition:
        ($d7 or $d8) and any of ($d1,$d2,$d3,$d4,$d5,$d6)
}

rule Credential_Dumping_Tool
{
    meta:
        description = "凭据窃取工具特征"
        severity = "high"
    strings:
        $c1 = "mimikatz" ascii nocase
        $c2 = "sekurlsa" ascii nocase
        $c3 = "lsadump" ascii nocase
        $c4 = "wdigest" ascii nocase
        $c5 = "kerberos::golden" ascii nocase
    condition:
        any of them
}

rule Defense_Evasion_Commands
{
    meta:
        description = "关闭防御/记录清理"
        severity = "medium"
    strings:
        $e1 = "wevtutil cl" ascii nocase
        $e2 = "Set-MpPreference" ascii nocase
        $e3 = "DisableRealtimeMonitoring" ascii nocase
        $e4 = "netsh advfirewall firewall" ascii nocase
        $e5 = "sc stop" ascii nocase
    condition:
        any of them
}
"""

_BASE_RULE_BYTES = len(BASE_RULES.encode("utf-8"))


def ensure_base_rules():
    """基础规则落盘（已存在且非空则不改动）。"""
    try:
        if not BASE_RULE_FILE.exists() or BASE_RULE_FILE.stat().st_size < 100:
            BASE_RULE_FILE.write_text(BASE_RULES.lstrip("\n"), encoding="utf-8")
            logger.info(f"已生成基础 YARA 规则: {BASE_RULE_FILE}")
    except Exception as e:
        logger.warn(f"写入基础 YARA 规则失败: {e}")


class YaraEngine:
    def __init__(self):
        self.rules = None
        self._cache_key = None
        self.last_error = ""
        self.enabled = bool(HAS_YARA) and bool(config_enabled())
        ensure_base_rules()
        self.compile()

    def _rule_files(self):
        out = []
        try:
            for p in sorted(YARA_DIR.glob("*")):
                if p.suffix.lower() in (".yar", ".yara") and p.is_file():
                    out.append(p)
        except Exception:
            pass
        return out

    def _cache_signature(self):
        sig = []
        for p in self._rule_files():
            try:
                sig.append((p.name, p.stat().st_size, int(p.stat().st_mtime)))
            except Exception:
                pass
        return tuple(sig)

    def compile(self):
        """编译规则。返回 (ok, msg)。"""
        if not HAS_YARA:
            self.rules = None
            self.last_error = "未安装 yara-python"
            return False, self.last_error
        files = self._rule_files()
        if not files:
            self.rules = None
            self.last_error = "规则目录为空"
            return False, self.last_error
        sources = {}
        for p in files:
            try:
                sources[p.stem] = str(p)
            except Exception:
                continue
        try:
            self.rules = yara.compile(filepaths=sources)
            self._cache_key = self._cache_signature()
            self.last_error = ""
            logger.info(f"YARA 规则编译成功：{len(sources)} 个规则文件")
            return True, f"已加载 {len(sources)} 个规则文件"
        except Exception as e:
            self.rules = None
            self.last_error = f"编译失败: {e}"
            logger.warn(f"YARA 规则编译失败: {e}")
            return False, self.last_error

    def _ensure_fresh(self):
        if self._cache_key != self._cache_signature():
            self.compile()

    def match_file(self, path, timeout=10):
        """匹配单个文件，返回 [(rule_name, [tags], meta_severity)]。"""
        if not self.enabled or not HAS_YARA:
            return []
        self._ensure_fresh()
        if not self.rules:
            return []
        try:
            matches = self.rules.match(path, timeout=timeout)
        except Exception as e:
            logger.warn(f"YARA 匹配异常 {path}: {e}")
            return []
        out = []
        for m in matches:
            sev = "high"
            try:
                meta = getattr(m, "meta", {}) or {}
                sev = str(meta.get("severity", "high") or "high")
            except Exception:
                sev = "high"
            out.append((getattr(m, "rule", str(m)), list(getattr(m, "tags", []) or []), sev))
        return out

    def match_data(self, data):
        if not self.enabled or not HAS_YARA:
            return []
        self._ensure_fresh()
        if not self.rules:
            return []
        try:
            return [getattr(m, "rule", str(m)) for m in self.rules.match(data=data)]
        except Exception:
            return []

    @property
    def stats(self):
        return {"has_yara": HAS_YARA, "enabled": self.enabled,
                "rule_files": len(self._rule_files()),
                "compiled": self.rules is not None,
                "error": self.last_error}


def config_enabled():
    from .config import config
    return bool(config.get("yara_enabled", True))


# 全局单例（延迟初始化，避免无 yara 环境报错）
_instance = None


def engine():
    global _instance
    if _instance is None:
        _instance = YaraEngine()
    return _instance


def match_file(path):
    return engine().match_file(path)
