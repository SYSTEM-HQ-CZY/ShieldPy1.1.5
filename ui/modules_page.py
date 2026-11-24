# -*- coding: utf-8 -*-
"""防护模块页（v1.1.0）：按卡巴斯基方式分组展示与开关各防护模块。"""
from tkinter import messagebox

import customtkinter as ctk

from core import nsudo, yara_engine, olevba_engine
from core.config import config
from core.protected import protected
from core.snapshot import snapshot
from core.systemwatcher import watcher

from .ctk_base import BRAND, DANGER, BasePage, Card, tok

MODULES = [
    ("file_av", "文件反病毒",
     "扫描文件、启发式、特征库、YARA 规则、Office 宏分析。",
     "常驻 · 扫描时占用 CPU（可在设置中选择性能档）"),
    ("network", "反网络攻击",
     "识别可疑网络行为的命令行特征（下载载荷、远程执行等）并告警。",
     "仅告警，不主动断网（用户态无法接管防火墙）"),
    ("system_watcher", "System Watcher 行为监控",
     "采集文件/进程/命令行/注册表/VSS 行为并按权重打分。",
     "用户态存在延迟，驱动级 Rootkit 无法拦截，需转 PE 处理"),
    ("protected", "受控文件夹防护",
     "监控受保护目录的批量篡改，弹窗告警但不杀进程。",
     "只拦截文件操作并告警 + 可从快照还原"),
    ("ransomware", "勒索防护",
     "高危评分触发告警，配合快照备份与一键回滚。",
     "预置快照不会自动回滚，需手动确认"),
    ("advanced_clear", "高级清除",
     "借 NSudo 获取 TrustedInstaller 权限强制清除顽固文件。",
     "NSudo 可能被其他安全软件判为风险工具；需显式开启"),
]


class ModulesPage(BasePage):
    title = "防护模块"
    subtitle = "模块分组 · 开关 · 引擎状态"

    def build(self):
        root = self.content
        root.grid_columnconfigure(0, weight=1)

        self.card = Card(root, title="防护模块分组",
                         subtitle="对标卡巴斯基的模块化开关；关闭立即生效")
        self.card.grid(row=0, column=0, sticky="new", pady=(0, 10))
        body = ctk.CTkFrame(self.card.body, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=2, pady=2)

        self.switches = {}
        for key, name, desc, limit in MODULES:
            row = ctk.CTkFrame(body, fg_color=tok("card2"), corner_radius=10)
            row.pack(fill="x", pady=4)
            row.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(row, text=name, anchor="w",
                         font=ctk.CTkFont(size=13, weight="bold")).grid(
                row=0, column=0, sticky="w", padx=14, pady=(10, 0))
            ctk.CTkLabel(row, text=desc, anchor="w", font=ctk.CTkFont(size=11),
                         text_color=tok("dim"), wraplength=760,
                         justify="left").grid(row=1, column=0, sticky="w",
                                              padx=14, pady=(0, 2))
            ctk.CTkLabel(row, text=f"限制：{limit}", anchor="w",
                         font=ctk.CTkFont(size=10), text_color="#e0a955",
                         wraplength=760, justify="left").grid(
                row=2, column=0, sticky="w", padx=14, pady=(0, 10))
            sw = ctk.CTkSwitch(row, text="", width=46, progress_color=BRAND,
                               command=lambda k=key: self._on_toggle(k))
            sw.grid(row=0, column=1, rowspan=3, padx=14)
            self.switches[key] = sw

        self.engine_card = Card(root, title="引擎状态")
        self.engine_card.grid(row=1, column=0, sticky="new")
        self.engine_lbl = ctk.CTkLabel(self.engine_card.body, text="",
                                       anchor="w", justify="left",
                                       font=ctk.CTkFont(size=11),
                                       text_color=tok("dim"), wraplength=940)
        self.engine_lbl.pack(anchor="w", padx=6, pady=6)

        self._sync()
        self.refresh()

    def _sync(self):
        mods = config.get("modules_enabled") or {}
        for key, sw in self.switches.items():
            enabled = bool(mods.get(key, False))
            if enabled:
                sw.select()
            else:
                sw.deselect()

    def _on_toggle(self, key):
        enabled = bool(self.switches[key].get())
        if key == "advanced_clear" and enabled:
            if not messagebox.askyesno(
                    "⚠ 高风险模块",
                    "高级清除依赖 NSudo 提权到 TrustedInstaller 权限：\n\n"
                    "· 会被部分安全软件标记为风险工具；\n"
                    "· 提权删除不可回滚；\n"
                    "· 每次操作都会写入 data/advanced_clear.log。\n\n"
                    "确认开启？"):
                self.switches[key].deselect()
                return
            config.set("advanced_clear_ack", True)
        config.set_module(key, enabled)
        if key == "system_watcher":
            watcher.enabled = enabled
        self.refresh()

    def refresh(self):
        try:
            y = yara_engine.engine().stats
            o = olevba_engine.stats()
            ns = nsudo.find_nsudo()
            self.engine_lbl.configure(text=(
                f"YARA：{'已编译 ' + str(y.get('rule_files')) + ' 个规则文件' if y.get('compiled') else '不可用（' + str(y.get('error')) + '）'}"
                f"    |    olevba：{'可用' if o.get('has_olevba') else '不可用'}"
                f"    |    NSudo：{('可用 ' + ns) if ns else '未找到'}\n"
                f"受保护文件夹：{len(protected.folders)} 个，窗口 {protected.window_sec}s / "
                f"阈值 {protected.threshold} 次    |    快照：{len(snapshot.list_snapshots())} 个\n"
                f"System Watcher：{'启用' if watcher.enabled else '停用'}，"
                f"评分阈值 {watcher.threshold}，已记录事件 {len(watcher.events)}，"
                f"高危告警 {len(watcher.alerts)}"
            ))
        except Exception:
            pass

    def on_show(self):
        self._sync()
        self.refresh()
