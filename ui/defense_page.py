# -*- coding: utf-8 -*-
"""防御中心页（v1.1.0）：实时防护状态 + 自动处置策略 + 防御开关 + 事件日志。"""
from tkinter import messagebox

import customtkinter as ctk

from core.config import config
from core.monitor import monitor
from core.protected import protected
from core.systemwatcher import watcher

from .ctk_base import BRAND, DANGER, BasePage, Card, make_tree, tok

ACTION_MAP = {"自动隔离": "quarantine", "自动删除": "delete", "仅告警": "alert"}
ACTION_REV = {v: k for k, v in ACTION_MAP.items()}


class DefensePage(BasePage):
    title = "防御中心"
    subtitle = "实时防护 · 自动处置 · System Watcher"

    def build(self):
        root = self.content
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(1, weight=1)

        # ---- 状态 + 控制 ----
        top = Card(root, height=170)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        top.grid_columnconfigure(1, weight=1)

        self.lbl_state = ctk.CTkLabel(top, text="● 实时防护", anchor="w",
                                      font=ctk.CTkFont(size=16, weight="bold"),
                                      text_color=BRAND)
        self.lbl_state.grid(row=0, column=0, sticky="w", padx=16, pady=(14, 2))
        self.lbl_detail = ctk.CTkLabel(top, text="", anchor="w",
                                       font=ctk.CTkFont(size=11), text_color=tok("dim"))
        self.lbl_detail.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 8))

        btnrow = ctk.CTkFrame(top, fg_color="transparent")
        btnrow.grid(row=0, column=1, rowspan=2, sticky="e", padx=16, pady=(14, 4))
        self.btn_toggle = ctk.CTkButton(btnrow, text="暂停防护", width=110, height=32,
                                        corner_radius=8, fg_color=tok("card2"),
                                        command=self._toggle)
        self.btn_toggle.grid(row=0, column=0, padx=6)
        ctk.CTkButton(btnrow, text="清空事件", width=100, height=32, corner_radius=8,
                      fg_color=tok("card2"), command=self._clear).grid(
            row=0, column=1, padx=6)

        # 自动处置策略
        ctl = ctk.CTkFrame(top, fg_color="transparent")
        ctl.grid(row=2, column=0, columnspan=2, sticky="ew", padx=16, pady=(2, 14))
        ctk.CTkLabel(ctl, text="实时威胁自动处置：",
                     font=ctk.CTkFont(size=12)).grid(row=0, column=0, padx=(0, 8))
        self.action_menu = ctk.CTkOptionMenu(
            ctl, values=list(ACTION_MAP.keys()), width=140, height=30,
            corner_radius=8, fg_color=tok("card2"), button_color=tok("card2"),
            command=self._set_action)
        self.action_menu.grid(row=0, column=1, padx=(0, 18))
        self.action_menu.set(ACTION_REV.get(
            str(config.get("realtime_auto_action", "quarantine")), "自动隔离"))

        self.sw_startup = ctk.CTkSwitch(ctl, text="自启动项监控",
                                        command=self._toggle_startup,
                                        progress_color=BRAND)
        self.sw_startup.grid(row=0, column=2, padx=(0, 16))
        self.sw_hosts = ctk.CTkSwitch(ctl, text="hosts 保护",
                                      command=self._toggle_hosts,
                                      progress_color=BRAND)
        self.sw_hosts.grid(row=0, column=3, padx=(0, 16))
        self.sw_sw = ctk.CTkSwitch(ctl, text="System Watcher",
                                   command=self._toggle_watcher,
                                   progress_color=BRAND)
        self.sw_sw.grid(row=0, column=4, padx=(0, 0))

        # ---- 事件表 ----
        tree = make_tree(root, ["时间", "级别", "类型", "标题", "详情"],
                         widths=[150, 70, 90, 240, 520], height=12)
        tree._frame.grid(row=1, column=0, sticky="nsew")
        self.tree = tree._frame
        self.tree.grid_propagate(False)
        self.tt = tree

        self._sync_switches()
        self.refresh()

    def _sync_switches(self):
        try:
            self.sw_startup.select() if config.get("defense_startup", True) else self.sw_startup.deselect()
            self.sw_hosts.select() if config.get("defense_hosts", True) else self.sw_hosts.deselect()
            mods = config.get("modules_enabled") or {}
            self.sw_sw.select() if mods.get("system_watcher", True) else self.sw_sw.deselect()
        except Exception:
            pass

    # ---------- 控制 ----------
    def _toggle(self):
        try:
            if monitor.paused or not monitor.running:
                ok = monitor.resume() if monitor.running else monitor.start()[0]
                if not monitor.running:
                    monitor.start()
            else:
                monitor.pause()
            self.refresh()
        except Exception as e:
            messagebox.showerror("操作失败", str(e))

    def _set_action(self, label):
        config.set("realtime_auto_action", ACTION_MAP.get(label, "quarantine"))

    def _toggle_startup(self):
        config.set("defense_startup", bool(self.sw_startup.get()))

    def _toggle_hosts(self):
        config.set("defense_hosts", bool(self.sw_hosts.get()))

    def _toggle_watcher(self):
        enabled = bool(self.sw_sw.get())
        config.set_module("system_watcher", enabled)
        watcher.enabled = enabled

    def _clear(self):
        monitor.clear_events()
        watcher.clear()
        protected.clear_alerts()
        self.refresh()

    def refresh(self):
        try:
            st = monitor.status
            if st.get("paused"):
                self.lbl_state.configure(text="● 实时防护 已暂停", text_color="#e0a955")
                self.btn_toggle.configure(text="恢复防护")
            elif st.get("running"):
                self.lbl_state.configure(text="● 实时防护 运行中", text_color=BRAND)
                self.btn_toggle.configure(text="暂停防护")
            else:
                self.lbl_state.configure(text="● 实时防护 已停止", text_color=DANGER)
                self.btn_toggle.configure(text="启动防护")
            self.lbl_detail.configure(
                text=f"范围 {'全盘' if st.get('scope') == 'full' else '自定义'} · "
                     f"{len(st.get('dirs') or [])} 个位置 · 引擎 {st.get('engine')} · "
                     f"统计 {st.get('stats')} · "
                     f"System Watcher 事件 {len(watcher.events)} / 告警 {len(watcher.alerts)}")

            for i in self.tt.get_children():
                self.tt.delete(i)
            for ev in monitor.recent(60):
                iid = self.tt.insert("", "end", values=(
                    ev.time, {"info": "信息", "warn": "警告", "high": "高危"}.get(
                        ev.level, ev.level), ev.kind, ev.title, ev.detail))
                if ev.level == "high":
                    self.tt.item(iid, tags=("hi",))
                    self.tt.tag_configure("hi", foreground=DANGER)
                elif ev.level == "warn":
                    self.tt.item(iid, tags=("wn",))
                    self.tt.tag_configure("wn", foreground="#e0a955")
        except Exception:
            pass

    def on_show(self):
        self.refresh()
