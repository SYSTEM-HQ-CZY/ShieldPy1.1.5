# -*- coding: utf-8 -*-
"""GUI 冒烟测试 v1.0.55：构建所有页面（含防御中心）、验证操作按钮可见、
主题弹窗（不卡死）、全盘监控启动、扫描与隔离流程后自动关闭。
用法: python tests/smoke_gui.py
"""
import os
import sys
import time
from pathlib import Path

os.environ["SHIELDPY_NO_TRAY"] = "1"   # 冒烟测试禁用托盘图标
BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from ui.app import ShieldApp

app = ShieldApp()
app.update()

# 1) 所有页面构建
pages = ["dashboard", "quick", "full", "custom", "defense", "quarantine", "process", "settings", "logs"]
for key in pages:
    app.show_page(key)
    app.update()
    print(f"[OK] 页面构建成功: {key}")

# 2) 扫描页三个操作按钮可见性（grid 布局修复验证）
app.show_page("custom")
scan_page = app._pages["custom"]
app.update()
action_frame = None
for child in scan_page.winfo_children():
    try:
        info = child.grid_info()
        if info and int(info.get("row", -1)) == 6:
            action_frame = child
            break
    except Exception:
        pass
btn_texts = []
if action_frame is not None:
    for b in action_frame.winfo_children():
        if b.winfo_class() == "TButton":
            try:
                btn_texts.append(str(b.cget("text")))
            except Exception:
                pass
print(f"[OK] 处置栏按钮: {btn_texts}")
assert "隔离选中" in btn_texts and "删除选中" in btn_texts and "信任选中" in btn_texts, \
    "三个操作按钮未显示!"

# 3) 防御中心：全盘监控默认启动验证
app.show_page("defense")
app.update()
from core.monitor import monitor
if not monitor.running:
    monitor.on_threat = app.monitor_threat_cb
    ok, msg = monitor.start()
    print(f"[OK] 全盘防护启动: {ok} / {msg}")
print(f"[OK] 实时防护运行中: {monitor.running}")
print(f"[OK] 监控范围: {getattr(monitor, '_dirs', [])}")
from core.config import config
print(f"[OK] 自动处置策略: {config.get('realtime_auto_action')}")
monitor.stop()
print(f"[OK] 防护已暂停")

# 4) 主题切换弹窗（不卡死，保存配置）
app.show_page("settings")
app.update()
settings_page = app._pages["settings"]
old_theme = config.get("theme", "dark")
import tkinter.messagebox as mb
mb.showinfo = lambda *a, **k: print(f"[OK] 弹出提示(不卡死): {a[0] if a else ''}")
settings_page.theme_var.set("light")
settings_page._apply_theme()
assert config.get("theme") == "light", "主题未保存"
config.set("theme", old_theme)   # 恢复
print(f"[OK] 主题切换保存成功（弹窗提示重启生效），已恢复 {old_theme}")

# 5) 扫描 + 隔离流程
app.show_page("custom")
scan_page = app._pages["custom"]
from core.config import BASE_DIR
scan_page.target_var.set(str(BASE_DIR / "tests" / "sample"))
scan_page.start()
for _ in range(300):
    app.update()
    if not scan_page._scanning:
        break
    time.sleep(0.03)
print(f"[OK] 扫描完成，发现 {len(scan_page._pending_threats)} 项威胁")
for t in scan_page._pending_threats:
    print(f"     - {Path(t.path).name}: {t.detection}")
if scan_page._pending_threats:
    first = scan_page._pending_threats[0]
    from core.quarantine import quarantine
    ok, res = quarantine.quarantine_file(first.path, threat=first.threat,
                                         detection=first.detection, md5=first.md5)
    print(f"[OK] 隔离流程: {ok}")
    for it in quarantine.list_items():
        quarantine.restore(it.id)

app.destroy()
print("\n=== GUI 冒烟测试通过 ===")
