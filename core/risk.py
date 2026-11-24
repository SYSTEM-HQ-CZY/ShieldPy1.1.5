# -*- coding: utf-8 -*-
"""风险加权打分层（v1.1.5）。

误报治理三原则：
    1. **单特征不直接判恶意**：任何检出先变成"特征"，累加过阈值（默认 60）才判威胁；
       分数不够的降级为"提示（hint）"，不再当成病毒弹窗。
    2. **数字签名减免**：PE 文件持有有效 Authenticode 签名 → 大幅扣分
       （正常程序模块、加壳库不再被误杀）。
    3. **日志基线白名单**：第三方软件日志（.log/.txt/.json 等文本类文件、
       路径含 \\logs\\ 等）→ 扣分，避免"日志里出现敏感关键词就被判毒"。

强特征（特征库哈希命中）不受减免影响，直接判定威胁。
"""
import ctypes
import os
from ctypes import wintypes

from . import logger
from .config import config

# ---------------- 权重表 ----------------
WEIGHTS = {
    "sig_hash": 100,        # 特征库哈希命中（强特征，直接判威胁）
    "yara_high": 78,
    "yara_medium": 46,
    "yara_low": 18,
    "macro_high": 62,
    "macro_medium": 34,
    "heur_high": 55,
    "heur_medium": 28,
    "heur_low": 12,
    "packer_high": 42,
    "packer_medium": 20,
    "packer_low": 8,
    "risk_ext": 5,
    "archive": 6,
}

# 减免项（负数）
MITIGATIONS = {
    "signed": -52,            # 有效数字签名（内嵌 Authenticode）
    "known_publisher": -10,   # 签名者/厂商名为已知厂商
    "version_info": -10,      # 无签名但版本信息里的厂商可信（弱减免）
    "log_baseline": -42,      # 日志/文本类基线
    "text_small": -8,         # 小体积纯文本
    "system_dir": -6,         # 系统目录（很弱的减免，防止恶意软件借用系统目录洗白）
}

THRESHOLD = 60            # >= 该分数判威胁
HIGH_THRESHOLD = 85       # >= 该分数判高危

PE_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv"}
LOG_EXTS = {".log", ".txt", ".ini", ".cfg", ".conf", ".json", ".xml", ".csv",
            ".md", ".yml", ".yaml", ".bak", ".old", ".tmp"}
# 这些扩展名绝不允许套用"日志基线"减免（恶意样本最爱丢 Temp 并伪装成脚本）
NEVER_BASELINE_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv",
    ".vbs", ".vbe", ".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse",
    ".hta", ".lnk", ".py", ".jar", ".msi", ".docm", ".dotm", ".xlsm",
    ".xltm", ".pptm", ".potm", ".wsf", ".reg", ".pif",
}
# 只认明确的"日志目录"，不用 %TEMP% / AppData 这类过宽路径
LOG_PATH_HINTS = ("\\logs\\", "\\log\\", "\\日志\\", "\\crash\\", "\\crashdumps\\",
                  "\\windowspanther\\", "\\windows\\logs\\")
SYSTEM_DIR_HINTS = ("c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
                    "c:\\windows\\winsxs\\", "c:\\windows\\servicing\\")
KNOWN_PUBLISHERS = (
    "microsoft", "google", "adobe", "nvidia", "intel", "amd", "realtek",
    "apple", "mozilla", "tencent", "alibaba", "bytedance", "huawei", "xiaomi",
    "kaspersky", "eset", "avast", "bitdefender", "sophos", "symantec",
    "mcafee", "trend micro", "360", "qihu", "huorong", "kingsoft", "sogou",
    "baidu", "oracle", "vmware", "jetbrains", "python software foundation",
)


# ---------------- Authenticode 数字签名校验 ----------------
class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", ctypes.c_ulong),
                ("pcwszFilePath", ctypes.c_wchar_p),
                ("hFile", wintypes.HANDLE),
                ("pgKnownSubject", ctypes.POINTER(_GUID))]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", ctypes.c_ulong),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", ctypes.c_ulong),
                ("fdwRevocationChecks", ctypes.c_ulong),
                ("dwUnionChoice", ctypes.c_ulong),
                ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
                ("dwStateAction", ctypes.c_ulong),
                ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", ctypes.c_wchar_p),
                ("dwProvFlags", ctypes.c_ulong),
                ("dwUIContext", ctypes.c_ulong),
                ("pSignatureSettings", ctypes.c_void_p)]


_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATE_VERIFY = 1
_WTD_STATE_CLOSE = 2
_WTD_SAFER_FLAG = 0x100
_WTD_CACHE_ONLY = 0x1000
_TRUST_E_NOSIGNATURE = 0x800B0100
_TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
_TRUST_E_PROVIDER_UNKNOWN = 0x800B0001

_sig_cache = {}


def verify_signature(path):
    """校验 Authenticode 签名。

    返回 {"checked": bool, "valid": bool, "signer": str, "reason": str}
    仅对 PE 扩展名有意义；结果按 (路径, 大小, mtime) 缓存，避免重复开销。
    """
    p = str(path)
    ext = os.path.splitext(p)[1].lower()
    if ext not in PE_EXTS:
        return {"checked": False, "valid": False, "signer": "", "reason": "非 PE 文件"}
    try:
        st = os.stat(p)
        key = (os.path.normcase(p), st.st_size, int(st.st_mtime))
    except Exception:
        return {"checked": False, "valid": False, "signer": "", "reason": "无法读取"}
    if key in _sig_cache:
        return _sig_cache[key]

    out = {"checked": True, "valid": False, "signer": "", "reason": ""}
    try:
        guid = _GUID(0x00AAC56B, 0xCD44, 0x11D0,
                     (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
        file_info = _WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = p
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust = _WINTRUST_DATA()
        trust.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        trust.dwUIChoice = _WTD_UI_NONE
        trust.fdwRevocationChecks = _WTD_REVOKE_NONE
        trust.dwUnionChoice = _WTD_CHOICE_FILE
        trust.pFile = ctypes.pointer(file_info)
        trust.dwStateAction = _WTD_STATE_VERIFY
        trust.dwProvFlags = _WTD_SAFER_FLAG | _WTD_CACHE_ONLY
        trust.pwszURLReference = None
        trust.dwUIContext = 0

        ret = ctypes.windll.wintrust.WinVerifyTrust(
            None, ctypes.byref(guid), ctypes.byref(trust))
        if ret == 0:
            out["valid"] = True
            out["reason"] = "签名有效"
        elif ret in (_TRUST_E_NOSIGNATURE, _TRUST_E_SUBJECT_FORM_UNKNOWN,
                     _TRUST_E_PROVIDER_UNKNOWN):
            out["reason"] = "无数字签名"
        else:
            out["reason"] = f"签名不可信 (0x{ret & 0xFFFFFFFF:08X})"

        # 释放校验状态
        trust.dwStateAction = _WTD_STATE_CLOSE
        try:
            ctypes.windll.wintrust.WinVerifyTrust(
                None, ctypes.byref(guid), ctypes.byref(trust))
        except Exception:
            pass
    except Exception as e:
        out["reason"] = f"校验异常: {e}"
        out["checked"] = False

    if len(_sig_cache) > 4000:
        _sig_cache.clear()
    _sig_cache[key] = out
    return out


# ---------------- 基线判定 ----------------
def is_pext(path):
    return os.path.splitext(str(path))[1].lower() in PE_EXTS


def is_texty(data_sample, text=None):
    """粗判文本：可打印字节占比高、无 PE 头。"""
    if not data_sample:
        return False
    if data_sample[:2] == b"MZ":
        return False
    head = data_sample[:4096]
    if not head:
        return False
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127
                    or b >= 0x80)
    return printable / len(head) >= 0.85


def is_log_baseline(path, data_sample=None):
    """日志/文本类基线：扩展名 + 路径特征 + 内容像文本。

    安全边界：可执行 / 脚本 / 宏文档类扩展名一律不套基线减免，
    避免"恶意脚本放到 Temp 或 logs 目录就被洗白"。
    """
    if not config.get_bool("log_baseline", True):
        return False
    p = str(path)
    ext = os.path.splitext(p)[1].lower()
    if ext in NEVER_BASELINE_EXTS:
        return False
    path_l = p.lower()
    path_hit = any(h in path_l for h in LOG_PATH_HINTS)
    exts = set(config.get("log_baseline_exts") or LOG_EXTS)
    if ext and (ext in exts or ext in LOG_EXTS):
        if not data_sample:
            return True
        return is_texty(data_sample)
    if path_hit and is_texty(data_sample):
        return True
    return False


def is_system_dir(path):
    try:
        p = os.path.normcase(os.path.abspath(str(path))).lower()
    except Exception:
        return False
    return any(p.startswith(s) for s in SYSTEM_DIR_HINTS)


# ---------------- 版本信息（无内嵌签名时的弱减免依据） ----------------
_VER = None
try:
    _VER = ctypes.WinDLL("version.dll")

    class _ULONG(ctypes.Structure):
        _fields_ = [("unused", ctypes.c_ulong)]

    _VER.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p,
                                             ctypes.POINTER(ctypes.c_ulong)]
    _VER.GetFileVersionInfoSizeW.restype = ctypes.c_ulong
    _VER.GetFileVersionInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong,
                                         ctypes.c_ulong, ctypes.c_void_p]
    _VER.GetFileVersionInfoW.restype = wintypes.BOOL
    _VER.VerQueryValueW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                    ctypes.POINTER(ctypes.c_void_p),
                                    ctypes.POINTER(ctypes.c_uint)]
    _VER.VerQueryValueW.restype = wintypes.BOOL
except Exception:
    _VER = None

_vi_cache = {}


def file_company(path):
    """读取 PE 版本信息里的 CompanyName（取不到返回空串）。"""
    if _VER is None:
        return ""
    p = str(path)
    try:
        st = os.stat(p)
        key = (os.path.normcase(p), st.st_size, int(st.st_mtime))
    except Exception:
        return ""
    if key in _vi_cache:
        return _vi_cache[key]
    company = ""
    try:
        dummy = ctypes.c_ulong(0)
        size = _VER.GetFileVersionInfoSizeW(p, ctypes.byref(dummy))
        if size:
            buf = ctypes.create_string_buffer(size)
            if _VER.GetFileVersionInfoW(p, 0, size, buf):
                ptr = ctypes.c_void_p()
                ln = ctypes.c_uint(0)
                if _VER.VerQueryValueW(buf, "\\VarFileInfo\\Translation",
                                       ctypes.byref(ptr), ctypes.byref(ln)) \
                        and ln.value >= 4 and ptr.value:
                    arr = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ushort))
                    lang, cp = arr[0], arr[1]
                    sub = f"\\StringFileInfo\\{lang:04X}{cp:04X}\\CompanyName"
                    val = ctypes.c_void_p()
                    vlen = ctypes.c_uint(0)
                    if _VER.VerQueryValueW(buf, sub, ctypes.byref(val),
                                           ctypes.byref(vlen)) and val.value:
                        company = ctypes.cast(val, ctypes.c_wchar_p).value or ""
    except Exception:
        company = ""
    if len(_vi_cache) > 4000:
        _vi_cache.clear()
    _vi_cache[key] = company
    return company


# ---------------- 特征与评分 ----------------
class Feature:
    """一个检出特征（不再直接等于威胁）。"""

    def __init__(self, fid, severity="medium", desc="", source="", strong=False):
        self.id = fid
        self.severity = severity
        self.desc = desc
        self.source = source
        self.strong = strong or fid == "sig_hash"
        self.weight = WEIGHTS.get(fid, 10)

    def to_dict(self):
        return {"id": self.id, "severity": self.severity, "desc": self.desc,
                "source": self.source, "weight": self.weight, "strong": self.strong}


class Assessment:
    def __init__(self):
        self.features = []
        self.mitigations = []
        self.score = 0
        self.raw_score = 0
        self.verdict = "clean"      # clean / hint / threat
        self.severity = "low"
        self.detection = ""
        self.threat = ""
        self.source = ""
        self.signature = {}
        self.summary = ""

    def to_dict(self):
        return {"score": self.score, "raw": self.raw_score, "verdict": self.verdict,
                "severity": self.severity, "detection": self.detection,
                "threat": self.threat, "source": self.source,
                "features": [f.to_dict() for f in self.features],
                "mitigations": list(self.mitigations),
                "signature": self.signature}


_SEV_ORDER = {"high": 3, "medium": 2, "low": 1, "": 0}


def assess(features, path="", ext="", size=0, data_sample=None,
           check_signature=True, inside_archive=False):
    """把特征列表打分，产出最终判定。

    features: list[Feature]
    返回 Assessment（verdict=clean 时应完全忽略）
    """
    a = Assessment()
    if not features:
        return a
    a.features = list(features)
    a.raw_score = sum(f.weight for f in features)

    strong = any(f.strong for f in a.features)
    mitigations = []

    # 1) 数字签名减免（强特征不减免；只有 PE 才校验）
    if check_signature and not strong and is_pext(path) and size and size < 200 * 1024 * 1024:
        try:
            sig = verify_signature(path)
            a.signature = sig
            if sig.get("valid"):
                mitigations.append("signed")
                signer = (sig.get("signer") or "").lower()
                company = file_company(path)
                a.signature = dict(sig, company=company)
                if any(k in (signer + " " + company.lower()) for k in KNOWN_PUBLISHERS):
                    mitigations.append("known_publisher")
            else:
                # 无内嵌签名（系统文件多为 catalog 签名）→ 退一步看版本信息厂商
                company = file_company(path)
                a.signature = dict(sig, company=company)
                if company and any(k in company.lower() for k in KNOWN_PUBLISHERS):
                    mitigations.append("version_info")
        except Exception:
            pass

    # 2) 日志 / 文本基线
    if not strong and is_log_baseline(path, data_sample):
        mitigations.append("log_baseline")
    elif not strong and data_sample and size and size < 256 * 1024 and is_texty(data_sample):
        mitigations.append("text_small")

    # 3) 系统目录（弱减免）
    if not strong and is_system_dir(path):
        mitigations.append("system_dir")

    a.mitigations = mitigations
    a.score = a.raw_score + sum(MITIGATIONS.get(m, 0) for m in mitigations)
    if a.score < 0:
        a.score = 0

    # ---- 判定 ----
    threshold = config.get_int("risk_threshold", THRESHOLD) or THRESHOLD
    weak_sole = all(f.id in ("risk_ext", "archive") for f in a.features)

    if strong:
        a.verdict = "threat"
        a.severity = "high"
    elif a.score >= HIGH_THRESHOLD:
        a.verdict = "threat"
        a.severity = "high"
    elif a.score >= threshold:
        a.verdict = "threat"
        a.severity = "medium"
    elif weak_sole:
        # 仅"高危扩展名 / 压缩包内容"这类弱特征：永远只提示，不判恶意
        a.verdict = "hint"
        a.severity = "low"
    elif a.score >= 15:
        a.verdict = "hint"
        a.severity = "low"
    else:
        a.verdict = "clean"

    if a.verdict == "clean":
        return a

    # 取最高特征作为展示主特征
    top = max(a.features, key=lambda f: (_SEV_ORDER.get(f.severity, 0), f.weight))
    a.detection = top.source or "Heuristic"
    a.threat = top.desc
    a.source = top.source
    if len(a.features) > 1:
        a.threat = f"{a.threat}（共 {len(a.features)} 项特征，评分 {a.score}）"
    else:
        a.threat = f"{a.threat}（评分 {a.score}）"
    if mitigations:
        names = {"signed": "有效数字签名", "log_baseline": "日志基线白名单",
                 "text_small": "小体积文本", "system_dir": "系统目录",
                 "known_publisher": "已知厂商签名",
                 "version_info": "已知厂商版本信息"}
        a.threat += "；已减免：" + "、".join(names.get(m, m) for m in mitigations)
    a.summary = f"评分 {a.score}（原始 {a.raw_score}），判定 {a.verdict}"
    return a


def stats():
    return {"threshold": THRESHOLD, "high_threshold": HIGH_THRESHOLD,
            "weights": dict(WEIGHTS), "mitigations": dict(MITIGATIONS),
            "signature_cache": len(_sig_cache)}
