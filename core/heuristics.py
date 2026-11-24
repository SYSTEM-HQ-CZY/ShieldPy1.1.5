# -*- coding: utf-8 -*-
"""启发式检测引擎 v2（1.0.2 误报优化）
设计目标：
1. 恶意判定收紧：需 高分(>=5) 或 (>=4 分 且 命中 >=2 类恶意行为)，显著降低误报。
2. 高熵(混淆)只作为加成项，不再独立触发判定。
3. 良性豁免：命中正常开发/维护模式可抵消分数。
4. 风险分级：high(恶意) / medium(可疑) / low(提示)。
5. 扩展名高危与 UPX 加壳降级为 low 提示，不再直接当作威胁。
"""
import math
import re
from pathlib import Path

# ---------------- 脚本恶意模式库 ----------------
# 权重含义: 1=中性特征 2=可疑 3=强恶意 4=确定恶意
SCRIPT_PATTERNS = {
    ".vbs": [
        (r"(?i)createobject\(\s*[\"']wscript\.shell[\"']\s*\)", 3, "创建 WScript.Shell"),
        (r"(?i)createobject\(\s*[\"']scripting\.filesystemobject[\"']\s*\)", 2, "创建 FileSystemObject"),
        (r"(?i)\.run\s+[\"']?(cmd|powershell|mshta|regsvr32)", 3, "执行系统命令/下载器"),
        (r"(?i)\.exec\s*\(.*(wget|curl|bitsadmin|certutil|powershell)", 3, "调用下载工具"),
        (r"(?i)adodb\.stream", 3, "使用 ADODB.Stream 落盘"),
        (r"(?i)\.copyfile", 1, "复制文件"),
        (r"(?i)regwrite.*(run|runonce)", 4, "写入自启动注册表"),
        (r"(?i)winmgmts", 2, "调用 WMI"),
        (r"(?i)shell\.run.*\-\-", 2, "带参数执行"),
        (r"(?i)(encode|chr\s*\(|eval\s*\()", 2, "编码混淆"),
        (r"(?i)taskkill|shutdown", 1, "结束进程/关机"),
        (r"(?i)deletefile|deletefolder", 1, "删除文件/目录"),
    ],
    ".vbe": [
        (r"(?i)createobject\(\s*[\"']wscript\.shell", 4, "VBE 创建 WScript.Shell"),
        (r"(?i)\.run\s+[\"']?(cmd|powershell|mshta)", 4, "VBE 执行命令"),
        (r"(?i)adodb\.stream|bitsadmin|certutil", 4, "VBE 下载落盘"),
    ],
    ".ps1": [
        (r"(?i)invoke-expression|iex\s*\(", 3, "Invoke-Expression 动态执行"),
        (r"(?i)downloadstring|downloadfile|net\.webclient", 3, "PowerShell 下载执行"),
        (r"(?i)add-mppreference\s+-exclusionpath", 4, "关闭 Defender 排除项"),
        (r"(?i)bypass\s+-enc|\-enc\s", 3, "编码载荷绕过"),
        (r"(?i)mimikatz|sekurlsa|logonpasswords", 4, "凭据窃取工具"),
        (r"(?i)stop-process.*(defend|winlogon|explorer)", 3, "终止关键进程"),
        (r"(?i)start-process.*(hidden|windowstyle\s+hidden)", 2, "隐藏窗口执行"),
        (r"(?i)new-object system\.net\.sockets\.tcpclient", 4, "反向连接"),
        (r"(?i)reg\s+add.*(run|runonce)", 4, "写自启动"),
        (r"(?i)invoke-mimikatz|invoke-powershell.*-windowstyle", 3, "渗透工具特征"),
        (r"(?i)(compressed|gzip|deflate|base64)", 1, "压缩/编码特征"),
    ],
    ".bat": [
        (r"(?i)reg\s+add.*(run|runonce)", 4, "写自启动注册表"),
        (r"(?i)schtasks\s+/create", 4, "创建计划任务"),
        (r"(?i)format\s+[a-z]:", 4, "格式化磁盘"),
        (r"(?i)certutil\s+.*-decode", 4, "certutil 解码"),
        (r"(?i)bitsadmin\s+/transfer", 4, "bitsadmin 下载"),
        (r"(?i)powershell\s+.*\-(w|enc|bypass|hidden)", 3, "调用 PowerShell 隐藏执行"),
        (r"(?i)wmic\s+process\s+call\s+create", 2, "WMI 创建进程"),
        (r"(?i)taskkill\s+/f.*(defender|360|huorong|qqpctray)", 3, "结束杀软进程"),
        (r"(?i)net\s+user\s+\w+\s+\w+", 2, "添加/改用户"),
        (r"(?i)del\s+/[fq]", 1, "删除文件"),
        (r"(?i)shutdown\s+/[rs]?\s*/t", 1, "关机/重启"),
        (r"(?i)attrib\s+-r\s+-s\s+-h", 1, "修改文件属性"),
    ],
    ".cmd": [
        (r"(?i)reg\s+add.*(run|runonce)", 4, "写自启动注册表"),
        (r"(?i)schtasks\s+/create", 4, "创建计划任务"),
        (r"(?i)certutil|bitsadmin|powershell\s+-w", 3, "下载执行特征"),
        (r"(?i)del\s+/[fq]", 1, "删除文件"),
    ],
    ".js": [
        (r"(?i)activexobject\(\s*[\"']wscript\.shell[\"']", 3, "JS 创建 WScript.Shell"),
        (r"(?i)activexobject\(\s*[\"']adodb\.stream[\"']", 3, "JS 使用 ADODB.Stream"),
        (r"(?i)\.run\s*\(|\.exec\s*\(", 3, "JS 执行命令"),
        (r"(?i)mshta|wsh\.run", 3, "mshta/wsh 执行"),
        (r"(?i)fromcharcode|eval\s*\(", 3, "JS 编码混淆"),
    ],
    ".jse": [
        (r"(?i)activexobject\(\s*[\"']wscript\.shell[\"']", 4, "JSE 创建 WScript.Shell"),
        (r"(?i)\.run\s*\(.*(cmd|powershell|mshta)", 4, "JSE 执行命令"),
    ],
    ".hta": [
        (r"(?i)mshta|wscript\.shell", 3, "HTA 调用 shell"),
        (r"(?i)\.run\s*\(.*(cmd|powershell)", 3, "HTA 执行命令"),
    ],
    ".html": [
        (r"(?i)<script[^>]*>\s*eval|fromcharcode", 2, "HTML 内嵌混淆脚本"),
        (r"(?i)activexobject\s*\(", 2, "HTML ActiveX"),
        (r"(?i)document\.write.*<iframe", 2, "HTML 注入 iframe"),
    ],
    ".py": [
        (r"(?i)subprocess\.(popen|call|run).*(cmd|powershell|/c)", 2, "Python 调用系统命令"),
        (r"(?i)requests?\.(get|post)\(.*\.(exe|scr|bat|ps1)", 3, "Python 下载可执行文件"),
        (r"(?i)ctypes\.windll", 1, "Python 调用 Win32 API"),
        (r"(?i)__import__\(\s*[\"']os[\"']\s*\)", 1, "动态导入 os"),
        (r"(?i)base64\.b64decode.*(exec|eval|pickle\.loads)", 2, "Python 解码执行"),
    ],
    ".lnk": [
        (r"(?i)(cmd\.exe|powershell\.exe|mshta\.exe|wscript\.exe)\s+/", 3, "LNK 指向命令行"),
    ],
}

# 通用恶意模式（任意脚本）
GENERIC_PATTERNS = [
    (r"(?i)http[s]?://\S+\.(exe|scr|bat|ps1|vbs|dll)", 2, "下载远程可执行文件"),
    (r"(?i)(?:bitsadmin|certutil|powershell)\s+.*(?:/transfer|-decode|-download)", 3, "利用系统工具下载"),
    (r"(?i)wscript\.shell|powershell\.exe\s+-e", 2, "隐蔽脚本执行"),
]

# 良性豁免模式：命中可抵消分数，避免正常开发/维护脚本误报
EXEMPT_PATTERNS = [
    (r"(?i)if\s+__name__\s*==\s*[\"']__main__[\"']", 1, "标准 Python 入口"),
    (r"(?i)^\s*(rem|::|#)\s", 1, "脚本含大量注释"),
    (r"(?i)def\s+main\s*\(", 1, "main 函数结构"),
    (r"(?i)print\s*\(|echo\s+off|Write-Host", 1, "正常输出/调试"),
]

# 高危扩展名 -> 改为"低风险提示"级别（不再直接当威胁）
RISK_EXT_HINT = {
    ".scr": ("ScreenSaver.SCR", "屏幕保护程序文件（可能被利用，建议人工确认）"),
    ".vbe": ("Script.VBE", "编码 VBS 脚本（可能被利用，建议人工确认）"),
    ".jse": ("Script.JSE", "编码 JS 脚本（可能被利用，建议人工确认）"),
}

_PATTERN_CACHE = {}


def _compiled(p):
    if p not in _PATTERN_CACHE:
        try:
            _PATTERN_CACHE[p] = re.compile(p)
        except re.error:
            _PATTERN_CACHE[p] = None
    return _PATTERN_CACHE[p]


def _score_by_patterns(text, patterns):
    total = 0
    hits = []
    for pattern, weight, desc in patterns:
        rx = _compiled(pattern)
        if rx and rx.search(text):
            total += weight
            hits.append(desc)
    return total, hits


def _shannon_entropy(data):
    if not data:
        return 0.0
    from collections import Counter
    freq = Counter(data)
    length = len(data)
    ent = 0.0
    for c, n in freq.items():
        p = n / length
        ent -= p * math.log2(p)
    return ent


def detect_script_threat(path, text, ext):
    """
    脚本内容启发式。返回 (威胁名 or None, 描述, 级别)。
    级别: high=恶意 / medium=可疑 / low=提示
    恶意判定（收紧）：
      - score >= 5  （存在强恶意特征）
      - 或 score >= 4 且 独立命中 >= 2 类恶意行为
    低风险提示: score >= 2
    高熵只作为加成，不独立触发。
    """
    if not text:
        return None, "", ""
    patterns = SCRIPT_PATTERNS.get(ext, [])
    score, hits = _score_by_patterns(text, patterns)
    gen_score, gen_hits = _score_by_patterns(text, GENERIC_PATTERNS)
    score += gen_score
    hits += gen_hits

    # 良性豁免：抵消分数（最多抵消 2 分）
    ex_score, _ = _score_by_patterns(text, EXEMPT_PATTERNS)
    score -= min(2, ex_score)

    # 混淆熵加成（仅当已有可疑分时）
    entropy = _shannon_entropy(text)
    high_entropy = len(text) > 300 and entropy > 5.8
    if high_entropy and score >= 3:
        score += 1
        hits.append("高熵混淆内容")

    if score <= 0:
        return None, "", ""

    unique_hits = sorted(set(hits))
    desc = f"命中 {len(unique_hits)} 类行为特征: " + "; ".join(unique_hits)

    # 恶意（收紧阈值）
    if score >= 5 or (score >= 4 and len(unique_hits) >= 2):
        return f"Script.Heuristic.{ext.lstrip('.').upper()}", desc, "high"

    # 可疑（中等）
    if score >= 3:
        return f"Script.Suspicious.{ext.lstrip('.').upper()}", desc, "medium"

    # 低风险提示
    if score >= 2:
        return f"Script.Hint.{ext.lstrip('.').upper()}", desc, "low"

    return None, "", ""


def detect_packer(path, head):
    """
    文件头 / 加壳检测。返回 (威胁名 or None, 描述, 级别)。
    UPX 加壳本身不是恶意（正常软件也可能加壳），降为 low 提示。
    """
    if head[:2] == b"MZ":
        if b"UPX0" in head or b"UPX!" in head:
            return "Packed.UPX", "可执行文件为 UPX 加壳（合法软件也可能使用，建议人工确认）", "low"
    if head[:4] == b"\x7fELF":
        if b"UPX" in head[:4096]:
            return "Packed.UPX", "ELF 文件为 UPX 加壳", "low"
    return None, "", ""


def read_text_safe(path, max_bytes=512 * 1024, data=None):
    """安全读取文本内容（尝试常见编码，限制大小）。
    可传入已读取的 bytes(data) 避免二次读盘。"""
    try:
        if data is None:
            size = path.stat().st_size
            if size > max_bytes:
                return ""
            data = path.read_bytes()
        elif len(data) > max_bytes:
            return ""
        for enc in ("utf-8", "gb18030", "utf-16", "latin-1"):
            try:
                return data.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
        return data.decode("latin-1", errors="ignore")
    except Exception:
        return ""
