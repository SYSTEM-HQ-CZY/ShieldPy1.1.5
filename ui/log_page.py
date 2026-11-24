# -*- coding: utf-8 -*-
"""日志页：滚动显示运行日志。"""
import os
import subprocess

import customtkinter as ctk

from core import logger
from core.config import LOGS_DIR

from .ctk_base import BRAND, BasePage, Card, tok


class LogPage(BasePage):
    title = "日志"
    subtitle = "运行日志 · 防护事件 · 高级清除记录"

    def build(self):
        root = self.content
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)

        card = Card(root)
        card.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        self.box = ctk.CTkTextbox(card.body, corner_radius=8, wrap="none",
                                  font=ctk.CTkFont(size=11, family="Consolas"),
                                  fg_color=tok("card2"))
        self.box.pack(fill="both", expand=True, padx=6, pady=6)
        self.box.configure(state="disabled")

        bar = Card(root, height=60)
        bar.grid(row=1, column=0, sticky="ew")
        ctk.CTkButton(bar.body, text="刷新", width=80, height=30, corner_radius=8,
                      fg_color=BRAND, command=self.refresh).pack(
            side="left", padx=(6, 8), pady=14)
        ctk.CTkButton(bar.body, text="打开日志目录", width=120, height=30,
                      corner_radius=8, fg_color=tok("card2"),
                      command=self._open_dir).pack(side="left", padx=8, pady=14)
        ctk.CTkButton(bar.body, text="查看高级清除日志", width=150, height=30,
                      corner_radius=8, fg_color=tok("card2"),
                      command=self._show_advanced).pack(side="left", padx=8, pady=14)

        self.refresh()

    def _open_dir(self):
        try:
            subprocess.Popen(["explorer", str(LOGS_DIR)])
        except Exception:
            pass

    def _show_advanced(self):
        try:
            from core.nsudo import read_advanced_log
            lines = read_advanced_log(200)
            self.box.configure(state="normal")
            self.box.delete("1.0", "end")
            self.box.insert("1.0", "\n".join(lines) if lines else "（暂无高级清除记录）")
            self.box.configure(state="disabled")
        except Exception as e:
            self.box.configure(state="normal")
            self.box.insert("end", f"\n读取失败：{e}\n")
            self.box.configure(state="disabled")

    def refresh(self):
        try:
            lines = logger.recent(400)
            self.box.configure(state="normal")
            self.box.delete("1.0", "end")
            self.box.insert("1.0", "\n".join(lines) if lines else "（暂无日志）")
            self.box.see("end")
            self.box.configure(state="disabled")
        except Exception:
            pass

    def on_show(self):
        self.refresh()
