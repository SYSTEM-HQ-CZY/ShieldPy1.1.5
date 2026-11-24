# -*- coding: utf-8 -*-
"""设置页（v1.1.0）：扫描 / 防护 / 信任项 / 界面 / 高级清除 / 关于。"""
import os
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core import __version__, nsudo
from core.config import config, DATA_DIR, LOGS_DIR
from core.monitor import monitor
from core.protected import protected
from core.trust import trust

from .ctk_base import BRAND, DANGER, BasePage, Card, tok

PERF_MODES = {"low": "低占用（最省 CPU）", "balanced": "均衡（推荐）",
              "high": "高速（占用较高）"}
PERF_REV = {v: k for k, v in PERF_MODES.items()}


class SettingsPage(BasePage):
    title = "设置"
    subtitle = "扫描性能 · 防护 · 信任项 · 界面 · 高级清除"

    def build(self):
        outer = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        outer.pack(fill="both", expand=True)
        outer.grid_columnconfigure(0, weight=1)

        # ---- 扫描 ----
        c1 = Card(outer, title="扫描设置")
        c1.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        body = c1.body
        body.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(body, text="性能档位", anchor="w",
                     font=ctk.CTkFont(size=12)).grid(row=0, column=0, sticky="w",
                                                     padx=6, pady=6)
        self.perf_menu = ctk.CTkOptionMenu(body, values=list(PERF_MODES.values()),
                                           width=200, height=30, corner_radius=8,
                                           fg_color=tok("card2"),
                                           button_color=tok("card2"),
                                           command=self._set_perf)
        self.perf_menu.grid(row=0, column=1, sticky="w", padx=6, pady=6)
        self.perf_menu.set(PERF_MODES.get(
            str(config.get("scan_perf_mode", "balanced")), "均衡（推荐）"))

        ctk.CTkLabel(body, text="单文件上限 (MB)", anchor="w",
                     font=ctk.CTkFont(size=12)).grid(row=1, column=0, sticky="w",
                                                     padx=6, pady=6)
        self.maxmb = ctk.CTkEntry(body, width=90, height=30, corner_radius=8)
        self.maxmb.grid(row=1, column=1, sticky="w", padx=6, pady=6)
        self.maxmb.insert(0, str(config.get_int("max_file_mb", 100)))

        self.sw_arch = ctk.CTkSwitch(body, text="扫描压缩包内部", progress_color=BRAND,
                                     command=lambda: config.set(
                                         "scan_archives", bool(self.sw_arch.get())))
        self.sw_arch.grid(row=2, column=0, columnspan=2, sticky="w", padx=6, pady=6)
        self.sw_deep = ctk.CTkSwitch(body, text="深度启发式（更准但更慢）",
                                     progress_color=BRAND,
                                     command=lambda: config.set(
                                         "deep_heuristic", bool(self.sw_deep.get())))
        self.sw_deep.grid(row=3, column=0, columnspan=2, sticky="w", padx=6, pady=6)
        ctk.CTkButton(body, text="保存扫描设置", width=130, height=30,
                      corner_radius=8, fg_color=BRAND, command=self._save_scan).grid(
            row=4, column=1, sticky="w", padx=6, pady=(6, 10))

        # ---- 实时防护 ----
        c2 = Card(outer, title="实时防护")
        c2.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        b2 = c2.body
        b2.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(b2, text="监控范围", anchor="w",
                     font=ctk.CTkFont(size=12)).grid(row=0, column=0, sticky="w",
                                                     padx=6, pady=6)
        self.scope_menu = ctk.CTkOptionMenu(
            b2, values=["全盘防护（推荐）", "自定义目录"], width=200, height=30,
            corner_radius=8, fg_color=tok("card2"), button_color=tok("card2"),
            command=self._set_scope)
        self.scope_menu.grid(row=0, column=1, sticky="w", padx=6, pady=6)
        self.scope_menu.set("全盘防护（推荐）" if str(
            config.get("realtime_scope", "full")) == "full" else "自定义目录")

        self.sw_rt = ctk.CTkSwitch(b2, text="开机自动启动 + 随程序启动实时防护",
                                   progress_color=BRAND,
                                   command=lambda: config.set(
                                       "realtime_monitor", bool(self.sw_rt.get())))
        self.sw_rt.grid(row=1, column=0, columnspan=2, sticky="w", padx=6, pady=6)
        self.sw_borderless = ctk.CTkSwitch(
            b2, text="无边框窗口（自制标题栏，重启生效）", progress_color=BRAND,
            command=lambda: config.set("ui_borderless", bool(self.sw_borderless.get())))
        self.sw_borderless.grid(row=2, column=0, columnspan=2, sticky="w",
                                padx=6, pady=6)

        # ---- 信任项 ----
        c3 = Card(outer, title="信任项（路径 + SHA256 双哈希）",
                  subtitle="文件内容一旦变化，信任自动失效")
        c3.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        b3 = c3.body
        for i, f in enumerate(trust.list_items()[:8]):
            r = ctk.CTkFrame(b3, fg_color="transparent")
            r.pack(fill="x", pady=1)
            ctk.CTkLabel(r, text=("✕ 失效 " if f.invalid else "✓ ") + f.path,
                         anchor="w", font=ctk.CTkFont(size=11),
                         text_color=DANGER if f.invalid else tok("text")).pack(
                side="left", padx=6)
            ctk.CTkButton(r, text="移除", width=56, height=22, corner_radius=6,
                          fg_color=tok("card2"),
                          command=lambda p=f.path: self._trust_remove(p)).pack(
                side="right", padx=6)
        self.trust_sum = ctk.CTkLabel(b3, text="", anchor="w",
                                      font=ctk.CTkFont(size=11),
                                      text_color=tok("dim"))
        self.trust_sum.pack(anchor="w", padx=6, pady=(4, 6))
        row3 = ctk.CTkFrame(b3, fg_color="transparent")
        row3.pack(fill="x", padx=6, pady=(0, 10))
        ctk.CTkButton(row3, text="添加信任文件…", width=130, height=30,
                      corner_radius=8, fg_color=BRAND,
                      command=self._trust_add).pack(side="left")
        ctk.CTkButton(row3, text="校验全部信任项", width=140, height=30,
                      corner_radius=8, fg_color=tok("card2"),
                      command=self._trust_verify).pack(side="left", padx=8)

        # ---- 高级清除 ----
        c4 = Card(outer, title="高级清除（NSudo 提权）")
        c4.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        b4 = c4.body
        b4.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(b4, text="NSudo 路径", anchor="w",
                     font=ctk.CTkFont(size=12)).grid(row=0, column=0, sticky="w",
                                                     padx=6, pady=6)
        self.nsudo_entry = ctk.CTkEntry(b4, width=520, height=30, corner_radius=8)
        self.nsudo_entry.grid(row=0, column=1, sticky="w", padx=6, pady=6)
        self.nsudo_entry.insert(0, str(config.get("nsudo_path", "") or
                                      (nsudo.find_nsudo() or "")))
        ctk.CTkButton(b4, text="保存", width=80, height=30, corner_radius=8,
                      fg_color=BRAND, command=self._save_nsudo).grid(
            row=0, column=2, padx=6, pady=6)
        ctk.CTkButton(b4, text="浏览…", width=80, height=30, corner_radius=8,
                      fg_color=tok("card2"), command=self._browse_nsudo).grid(
            row=0, column=3, padx=6, pady=6)
        self.nsudo_state = ctk.CTkLabel(b4, text="", anchor="w",
                                        font=ctk.CTkFont(size=11),
                                        text_color=DANGER)
        self.nsudo_state.grid(row=1, column=0, columnspan=4, sticky="w",
                              padx=6, pady=(0, 6))
        ctk.CTkLabel(
            b4, text="⚠ 风险提示：高级清除借 NSudo 获取 TrustedInstaller 权限，"
                     "可能被其他安全软件标记为风险工具；删除不可回滚；"
                     "每次操作都会写入 data/advanced_clear.log。",
            anchor="w", justify="left", wraplength=900,
            font=ctk.CTkFont(size=11), text_color=DANGER).grid(
            row=2, column=0, columnspan=4, sticky="w", padx=6, pady=(0, 10))
        self.sw_ack = ctk.CTkSwitch(b4, text="我已了解风险，允许开启高级清除",
                                    progress_color=BRAND,
                                    command=self._toggle_ack)
        self.sw_ack.grid(row=3, column=0, columnspan=2, sticky="w", padx=6, pady=(0, 10))
        if config.get_bool("advanced_clear_ack", False):
            self.sw_ack.select()

        # ---- 界面 ----
        c5 = Card(outer, title="界面与外观")
        c5.grid(row=4, column=0, sticky="ew", pady=(0, 10))
        b5 = c5.body
        ctk.CTkLabel(b5, text="主题", anchor="w",
                     font=ctk.CTkFont(size=12)).pack(anchor="w", padx=6, pady=(6, 2))
        self.theme_menu = ctk.CTkOptionMenu(b5, values=["深色", "浅色"], width=140,
                                            height=30, corner_radius=8,
                                            fg_color=tok("card2"),
                                            button_color=tok("card2"),
                                            command=self._set_theme)
        self.theme_menu.pack(anchor="w", padx=6, pady=(0, 6))
        self.theme_menu.set("深色" if str(config.get("theme", "dark")) == "dark" else "浅色")
        ctk.CTkButton(b5, text="重新运行初次向导", width=150, height=30,
                      corner_radius=8, fg_color=tok("card2"),
                      command=self._rerun_wizard).pack(anchor="w", padx=6, pady=(0, 8))

        # ---- 关于 ----
        c6 = Card(outer, title="关于")
        c6.grid(row=5, column=0, sticky="ew")
        ctk.CTkLabel(
            c6.body,
            text=f"玄盾卫士（ShieldPy）v{__version__}\n"
                 f"数据目录：{DATA_DIR}\n日志目录：{LOGS_DIR}\n\n"
                 f"核心定位：对标卡巴斯基查杀流程，纯用户态实现，无内核驱动，"
                 f"借 NSudo 提权完成高级清除。\n"
                 f"已知限制：用户态监控存在延迟；驱动级 Rootkit 无法处理，"
                 f"需转入 PE 环境清除。",
            anchor="w", justify="left", wraplength=900,
            font=ctk.CTkFont(size=11), text_color=tok("dim")).pack(
            anchor="w", padx=8, pady=8)

        self._sync()
        self._refresh_nsudo()

    # ---------- 控件同步 ----------
    def _sync(self):
        try:
            if config.get("scan_archives", True):
                self.sw_arch.select()
            if config.get("deep_heuristic", True):
                self.sw_deep.select()
            if config.get("realtime_monitor", True):
                self.sw_rt.select()
            if config.get("ui_borderless", True):
                self.sw_borderless.select()
        except Exception:
            pass

    def _refresh_nsudo(self):
        path = nsudo.find_nsudo()
        if path:
            self.nsudo_state.configure(
                text=f"状态：可用 · {path}", text_color=BRAND)
        else:
            self.nsudo_state.configure(
                text="状态：未找到 NSudoLC.exe，高级清除将不可用。"
                     "请把 NSudo 放到 tools/nsudo/ 或在此指定路径。",
                text_color=DANGER)

    # ---------- 动作 ----------
    def _set_perf(self, label):
        config.set("scan_perf_mode", PERF_REV.get(label, "balanced"))
        config.save()

    def _save_scan(self):
        try:
            mb = int(self.maxmb.get().strip())
            if mb < 1:
                raise ValueError
        except Exception:
            messagebox.showerror("错误", "单文件上限必须是正整数")
            return
        config.set("max_file_mb", mb)
        config.set("scan_archives", bool(self.sw_arch.get()))
        config.set("deep_heuristic", bool(self.sw_deep.get()))
        config.save()
        messagebox.showinfo("已保存", "扫描设置已保存")

    def _set_scope(self, label):
        config.set("realtime_scope", "full" if label.startswith("全盘") else "custom")
        config.save()
        if monitor.running:
            try:
                monitor.restart()
            except Exception:
                pass

    def _trust_add(self):
        f = filedialog.askopenfilename(title="选择要信任的文件")
        if not f:
            return
        ok, msg = trust.add(f, reason="设置页手动信任")
        messagebox.showinfo("信任", msg if ok else f"失败：{msg}")
        self.refresh()

    def _trust_remove(self, path):
        trust.remove(path)
        self.refresh()

    def _trust_verify(self):
        bad = trust.refresh_all()
        messagebox.showinfo("校验完成", f"共 {trust.count} 项，"
                                       f"失效 {bad} 项（文件已被改动）")
        self.refresh()

    def _save_nsudo(self):
        config.set("nsudo_path", self.nsudo_entry.get().strip())
        config.save()
        self._refresh_nsudo()

    def _browse_nsudo(self):
        f = filedialog.askopenfilename(
            title="选择 NSudoLC.exe",
            filetypes=[("NSudoLC", "NSudoLC.exe"), ("可执行文件", "*.exe")])
        if f:
            self.nsudo_entry.delete(0, "end")
            self.nsudo_entry.insert(0, f)
            config.set("nsudo_path", f)
            config.save()
            self._refresh_nsudo()

    def _toggle_ack(self):
        ack = bool(self.sw_ack.get())
        config.set("advanced_clear_ack", ack)
        config.save()
        if not ack:
            config.set_module("advanced_clear", False)

    def _set_theme(self, label):
        mode = "dark" if label == "深色" else "light"
        if mode == str(config.get("theme", "dark")):
            return
        config.set("theme", mode)
        config.save()
        messagebox.showinfo(
            "需要重启",
            "主题切换将在重启玄盾卫士后生效。\n请退出程序后重新打开（托盘图标右键 → 退出）。")

    def _rerun_wizard(self):
        config.set("wizard_done", False)
        config.save()
        messagebox.showinfo("下一步", "向导将在下次启动时自动弹出。")

    def refresh(self):
        try:
            self.trust_sum.configure(
                text=f"共 {trust.count} 项信任，失效 {trust.invalid_count} 项")
            self._refresh_nsudo()
        except Exception:
            pass

    def on_show(self):
        self.refresh()
