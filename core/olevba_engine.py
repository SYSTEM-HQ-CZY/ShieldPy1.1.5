# -*- coding: utf-8 -*-
"""Office 宏分析（olevba 接入，v1.1.0）。

用于识别"文档型"恶意载荷：启用宏的 docm/xlsm/pptm、以及老式 doc/xls 中的
VBA 工程。分析内容包括可疑关键字（AutoOpen、Shell、CreateObject、
PowerShell、下载执行、写自启动等），给出综合评分。
"""
import os

from . import logger

try:
    from oletools.olevba import VBA_Parser
    HAS_OLEVBA = True
except Exception:
    VBA_Parser = None
    HAS_OLEVBA = False

OFFICE_EXTS = {".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb",
               ".xlt", ".xltm", ".ppt", ".pptm", ".pot", ".potm",
               ".pub", ".rtf"}

# 可疑关键字权重
KEYWORDS = [
    (("autoopen", "auto_open", "workbook_open", "document_open"), 25, "文档打开即执行"),
    (("shell",), 20, "调用 Shell"),
    (("wscript.shell", "createobject"), 20, "创建 WScript.Shell"),
    (("powershell",), 25, "调用 PowerShell"),
    (("downloadfile", "urldownloadtofile", "msxml2.xmlhttp"), 30, "下载远程载荷"),
    (("environ(\"appdata\")", "environ(\"temp\")"), 10, "写入用户目录"),
    (("chr(", "chrw("), 10, "字符拼接混淆"),
    (("base64", "frombase64string"), 15, "Base64 解码"),
    (("regwrite", "currentversion\\run"), 25, "写自启动项"),
    (("declare ptrsafe", "kernel32", "virtualalloc"), 30, "调用 Win32 API"),
    (("cmd.exe", "/c "), 15, "调用命令行"),
    (("vbaform", "userform"), 5, "窗体（可能伪装）"),
    (("document.write", "script"), 10, "写入脚本"),
]


def is_office_file(path):
    return os.path.splitext(str(path or ""))[1].lower() in OFFICE_EXTS


def analyze(path):
    """分析单个 Office 文件的宏。返回 dict：
       {"has_macro":bool,"score":int,"severity":"high"/"medium"/"low"/"",
        "keywords":[...],"detail":"","ok":bool}
    """
    out = {"has_macro": False, "score": 0, "severity": "", "keywords": [],
           "detail": "", "ok": False}
    if not HAS_OLEVBA:
        out["detail"] = "未安装 oletools"
        return out
    if not is_office_file(path) or not os.path.isfile(path):
        return out
    try:
        try:
            size = os.path.getsize(path)
        except Exception:
            size = 0
        if size <= 0 or size > 200 * 1024 * 1024:
            return out
        parser = VBA_Parser(path)
        try:
            if not parser.detect_macro():
                out["ok"] = True
                out["detail"] = "未检测到宏"
                return out
            out["has_macro"] = True
            macro_text_parts = []
            for (_, _, vba_name, vba_code) in parser.extract_macros():
                try:
                    if vba_code:
                        macro_text_parts.append(str(vba_code))
                except Exception:
                    continue
            text = "\n".join(macro_text_parts).lower()
            score, hits = 0, []
            for pats, w, desc in KEYWORDS:
                if any(p in text for p in pats):
                    score += w
                    hits.append(desc)
            out["score"] = score
            out["keywords"] = hits
            if score >= 50:
                out["severity"] = "high"
            elif score >= 25:
                out["severity"] = "medium"
            elif score > 0:
                out["severity"] = "low"
            out["detail"] = ("发现宏；可疑行为：" + "、".join(hits)) if hits else "发现宏（未命中可疑关键字）"
            out["ok"] = True
            if out["severity"] in ("high", "medium"):
                logger.warning(f"[olevba] {path}: 宏评分 {score}（{'、'.join(hits)}）")
            return out
        finally:
            try:
                parser.close()
            except Exception:
                pass
    except AttributeError:
        # 常见于截断/伪造的 OLE 头：olevba 内部拿不到流名，属"无法解析"，不是威胁
        out["detail"] = "文件头不规范或非标准 OLE 文档，已跳过宏分析"
        return out
    except Exception as e:
        out["detail"] = f"分析异常: {e}"
        return out


def stats():
    return {"has_olevba": HAS_OLEVBA, "office_exts": len(OFFICE_EXTS)}
