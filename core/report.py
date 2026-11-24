# -*- coding: utf-8 -*-
"""扫描报告生成：HTML + TXT，输出到 reports/。"""
import html
import time
from pathlib import Path

from .config import REPORTS_DIR
from . import logger


def _timestamp():
    return time.strftime("%Y%m%d_%H%M%S")


def _human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def generate_report(scan_type, root, stats, threats, whitelisted=0):
    """生成 HTML 与 TXT 报告。返回 (html_path, txt_path)。"""
    ts = _timestamp()
    base_name = f"scan_{scan_type}_{ts}"
    html_path = Path(REPORTS_DIR) / f"{base_name}.html"
    txt_path = Path(REPORTS_DIR) / f"{base_name}.txt"

    lines = []
    lines.append("=" * 60)
    lines.append("ShieldPy 玄盾卫士 - 扫描报告")
    lines.append(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"扫描类型: {scan_type}")
    lines.append(f"扫描范围: {root}")
    lines.append("-" * 60)
    lines.append(f"已扫描文件: {stats.get('scanned', 0)}")
    lines.append(f"发现威胁:   {stats.get('threats', 0)}")
    lines.append(f"跳过(白名单/异常): {stats.get('skipped', 0)}")
    lines.append(f"耗时:       {stats.get('elapsed', 0)} 秒")
    lines.append("-" * 60)
    if threats:
        lines.append("威胁明细:")
        for i, t in enumerate(threats, 1):
            lines.append(f"  [{i}] {t.threat}")
            lines.append(f"      路径: {t.path}")
            lines.append(f"      检测: {t.detection} | MD5: {t.md5} | 大小: {_human_size(t.size)}")
    else:
        lines.append("未发现威胁。")
    lines.append("=" * 60)
    txt_path.write_text("\n".join(lines), encoding="utf-8")

    # ---- HTML ----
    sev_map = {"high": "恶意", "medium": "可疑", "low": "提示"}
    sev_color = {"high": "#e24c3b", "medium": "#f0b429", "low": "#8b94a7"}
    threat_rows = ""
    for t in threats:
        sev = t.severity if hasattr(t, "severity") else "medium"
        sev_label = sev_map.get(sev, "可疑")
        sev_c = sev_color.get(sev, "#f0b429")
        threat_rows += f"""
        <tr>
          <td class="det">{html.escape(t.detection)}</td>
          <td class="tname">{html.escape(t.threat[:80])}</td>
          <td class="path" title="{html.escape(t.path)}">{html.escape(t.path)}</td>
          <td>{_human_size(t.size)}</td>
          <td style="color:{sev_c};font-weight:600">{sev_label}</td>
          <td class="st">{html.escape(t.action)}</td>
        </tr>"""
    color = "#e24c3b" if threats else "#2e9e6b"
    title_icon = "⚠" if threats else "✓"
    summary = f"{len(threats)} 项威胁" if threats else "系统安全"

    html_content = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>ShieldPy 扫描报告</title>
<style>
 body{{font-family:'Segoe UI','Microsoft YaHei',sans-serif;background:#0f1420;color:#e6e9f0;margin:0;padding:24px}}
 .card{{background:#1a2233;border-radius:14px;padding:24px;max-width:980px;margin:0 auto}}
 h1{{margin:0 0 6px}} .sub{{color:#8b94a7;font-size:13px}}
 .big{{font-size:44px;font-weight:800;color:{color};margin:18px 0 4px}}
 .meta{{display:flex;gap:28px;flex-wrap:wrap;margin:16px 0;padding:14px 0;border-top:1px solid #26304a;border-bottom:1px solid #26304a}}
 .meta div b{{display:block;font-size:22px}} .meta div span{{color:#8b94a7;font-size:12px}}
 table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:13px}}
 th{{text-align:left;color:#8b94a7;font-weight:600;padding:8px;border-bottom:1px solid #2a3450}}
 td{{padding:8px;border-bottom:1px solid #222c45;word-break:break-all}}
 .det{{color:#5aa2ff}} .tname{{color:{color};font-weight:600}} .path{{color:#aab3c5;font-size:12px}} .st{{color:#f0b429}}
 .clean{{text-align:center;padding:30px;color:#2e9e6b;font-size:18px}}
</style></head><body><div class="card">
 <h1>🛡 ShieldPy 玄盾卫士 · 扫描报告</h1>
 <div class="sub">生成时间 {html.escape(time.strftime('%Y-%m-%d %H:%M:%S'))} ｜ 扫描类型 {html.escape(scan_type)} ｜ 范围 {html.escape(root)}</div>
 <div class="big">{title_icon} {summary}</div>
 <div class="meta">
  <div><b>{stats.get('scanned', 0)}</b><span>已扫描文件</span></div>
  <div><b style="color:{color}">{stats.get('threats', 0)}</b><span>发现威胁</span></div>
  <div><b>{whitelisted}</b><span>白名单跳过</span></div>
  <div><b>{stats.get('elapsed', 0)}s</b><span>耗时</span></div>
 </div>
 {'<table><tr><th>检测方式</th><th>威胁</th><th>路径</th><th>大小</th><th>级别</th><th>状态</th></tr>' + threat_rows + '</table>'
  if threats else '<div class="clean">✓ 未发现威胁，您的系统很安全</div>'}
</div></body></html>"""
    html_path.write_text(html_content, encoding="utf-8")
    logger.success(f"已生成报告: {html_path.name}")
    return str(html_path), str(txt_path)
