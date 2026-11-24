# -*- coding: utf-8 -*-
"""主窗口（CustomTkinter 版，v1.1.0）。

界面规范：
    * 移除原生 Windows 标题栏，自制顶部栏（图标 + 标题 + 最小化/最大化/关闭）
    * 顶部栏可拖动窗口，双击最大化
    * 全局圆角卡片、深浅色主题、高 DPI 适配
    * 侧边栏导航按"防护模块"分组组织
"""
import os
import threading

import customtkinter as ctk

from core import __version__, __app_name__
from core import logger
from core.config import config
from core.monitor import monitor
from core.trust import trust
from core.quarantine import quarantine
from core.lockdown import lockdown
from core.snapshot import snapshot

from . import ctk_base
from .ctk_base import (BRAND, DANGER, TitleBar, tok, apply_dpi_awareness, set_theme)

NAV_GROUPS = [
    ("总览", [
        ("dashboard", "◈  仪表盘"),
    ]),
    ("扫描与查杀", [
        ("scan", "⌕  病毒扫描"),
        ("quarantine", "▤  隔离区"),
        ("lock", "⚿  原地锁定"),
    ]),
    ("防护模块", [
        ("modules", "◫  防护模块"),
        ("defense", "♜  防御中心"),
        ("ransomware", "⛊  勒索防护"),
        ("process", "⚙  进程体检"),
    ]),
    ("系统", [
        ("log", "☰  日志"),
        ("settings", "⚒  设置"),
    ]),
]


class ShieldApp(ctk.CTk):
    def __init__(self, no_tray=False):
        apply_dpi_awareness()
        set_theme(config.get("theme", "dark"))
        super().__init__()

        self.app_name = __app_name__
        self.version = __version__
        self.no_tray = no_tray or os.environ.get("SHIELDPY_NO_TRAY") == "1"
        self._is_max = False
        self._restore_geo = "1200x780"
        self._pages = {}
        self._nav_buttons = {}
        self._current = None
        self.tray = None
        self._wizard_open = False

        self.title(f"{self.app_name} v{self.version}")
        self.geometry("1200x780")
        self.minsize(980, 660)
        self.configure(fg_color=tok("bg"))
        if config.get("ui_borderless", True):
            try:
                self.overrideredirect(True)
            except Exception:
                pass

        self._build()
        self._init_core()
        self._bind_hotkeys()
        self._start_tray()

        self.protocol("WM_DELETE_WINDOW", self.close_window)
        self.after(400, self._maybe_wizard)
        self.after(1500, self._tick)

    # ---------------- 布局 ----------------
    def _build(self):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.titlebar = TitleBar(self, title=f"玄盾卫士 v{self.version}",
                                 subtitle="用户态 · 无内核驱动 · System Watcher 已启用")
        self.titlebar.configure(fg_color=tok("card"))
        self.titlebar.grid(row=0, column=0, columnspan=2, sticky="ew")

        self.sidebar = ctk.CTkFrame(self, width=210, corner_radius=0,
                                    fg_color=tok("card"))
        self.sidebar.grid(row=1, column=0, sticky="nsw")
        self.sidebar.grid_propagate(False)
        self._build_sidebar()

        self.body = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.body.grid(row=1, column=1, sticky="nsew")
        self.body.grid_rowconfigure(0, weight=1)
        self.body.grid_columnconfigure(0, weight=1)

        self.statusbar = ctk.CTkFrame(self, height=26, corner_radius=0,
                                      fg_color=tok("card"))
        self.statusbar.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.statusbar.grid_propagate(False)
        self.status_label = ctk.CTkLabel(
            self.statusbar, text="就绪", anchor="w",
            font=ctk.CTkFont(size=11), text_color=tok("dim"))
        self.status_label.grid(row=0, column=0, sticky="w", padx=14, pady=3)
        self.status_right = ctk.CTkLabel(
            self.statusbar, text="", anchor="e", font=ctk.CTkFont(size=11),
            text_color=tok("dim"))
        self.status_right.grid(row=0, column=1, sticky="e", padx=14, pady=3)
        self.statusbar.grid_columnconfigure(1, weight=1)

        self.after(120, self._apply_region)

    def _build_sidebar(self):
        row = 0
        ctk.CTkLabel(self.sidebar, text="", height=4).grid(row=row, column=0)
        row += 1
        for group, items in NAV_GROUPS:
            ctk.CTkLabel(self.sidebar, text=group, anchor="w",
                         font=ctk.CTkFont(size=10, weight="bold"),
                         text_color=tok("dim")).grid(
                row=row, column=0, sticky="w", padx=16, pady=(10, 2))
            row += 1
            for key, label in items:
                btn = ctk.CTkButton(
                    self.sidebar, text=label, anchor="w", height=34,
                    corner_radius=8, fg_color="transparent",
                    hover_color=tok("card2"), font=ctk.CTkFont(size=12),
                    command=lambda k=key: self.show_page(k))
                btn.grid(row=row, column=0, sticky="ew", padx=10, pady=1)
                self._nav_buttons[key] = btn
                row += 1
        self.sidebar.grid_columnconfigure(0, weight=1)

        self.side_state = ctk.CTkLabel(
            self.sidebar, text="● 实时防护 启动中", anchor="w",
            font=ctk.CTkFont(size=11), text_color=BRAND)
        self.side_state.grid(row=row, column=0, sticky="w", padx=16, pady=(14, 2))
        row += 1
        self.side_threat = ctk.CTkLabel(
            self.sidebar, text="", anchor="w", font=ctk.CTkFont(size=10),
            text_color=tok("dim"))
        self.side_threat.grid(row=row, column=0, sticky="w", padx=16, pady=(0, 10))

    # ---------------- 核心启动 ----------------
    def _init_core(self):
        def boot():
            try:
                if config.get("realtime_monitor", True):
                    ok, msg = monitor.start()
                    logger.info(f"实时防护: {msg}")
                from core import yara_engine, olevba_engine, nsudo
                logger.info(f"YARA: {yara_engine.engine().stats}")
                logger.info(f"olevba: {olevba_engine.stats()}")
                logger.info(f"NSudo: "
                            f"{'可用 ' + nsudo.find_nsudo() if nsudo.available() else '未找到'}")
                monitor.on_event = self._on_defense_event
            except Exception as e:
                logger.error(f"核心启动异常: {e}")
        threading.Thread(target=boot, daemon=True).start()

    def _on_defense_event(self, ev):
        """实时防护事件 → 状态栏提示（线程安全地转回主线程）。"""
        try:
            msg = f"[{ev.title}] {ev.detail}"
            self.after(0, lambda: self._notify(msg[:120]))
            if ev.level == "high":
                self.after(0, lambda: self._flash_alert(ev))
        except Exception:
            pass

    def _flash_alert(self, ev):
        try:
            self.side_threat.configure(
                text=f"⚠ {ev.title}", text_color=DANGER)
        except Exception:
            pass

    def _bind_hotkeys(self):
        self.bind("<F5>", lambda e: self._tick(force=True))
        self.bind("<Control-q>", lambda e: self.real_quit())

    # ---------------- 页面管理 ----------------
    def register_pages(self, pages):
        self._pages.update(pages)
        for p in pages.values():
            p.grid(row=0, column=0, sticky="nsew")
            p.grid_remove()
        self.show_page("dashboard")

    def show_page(self, key):
        page = self._pages.get(key)
        if not page:
            return
        for k, p in self._pages.items():
            if k != key:
                p.grid_remove()
        page.grid()
        page.tkraise()
        for k, btn in self._nav_buttons.items():
            btn.configure(fg_color=BRAND if k == key else "transparent",
                          text_color="#ffffff" if k == key else tok("text"))
        self._current = key
        try:
            page.on_show()
        except Exception:
            pass

    # ---------------- 窗口控制 ----------------
    def minimize(self):
        if self.no_tray:
            try:
                self.iconify()
            except Exception:
                self.withdraw()
        else:
            self.withdraw()
            self._notify("玄盾卫士仍在后台防护（点击托盘图标恢复）")

    def toggle_maximize(self):
        if self._is_max:
            self.geometry(self._restore_geo)
            self._is_max = False
        else:
            self._restore_geo = self.geometry()
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
            self.geometry(f"{sw}x{sh - 48}+0+0")
            self._is_max = True
        self.after(60, self._apply_region)

    def _apply_region(self):
        try:
            self.update_idletasks()
            w, h = self.winfo_width(), self.winfo_height()
            radius = 14 if (config.get("ui_borderless", True) and not self._is_max) else 0
            ctk_base.round_region(self.winfo_id(), w, h, radius)
        except Exception:
            pass

    def close_window(self):
        if self.no_tray:
            self.real_quit()
            return
        self.withdraw()

    def _notify(self, msg):
        try:
            self.status_label.configure(text=msg)
        except Exception:
            pass

    # ---------------- 托盘 ----------------
    def _start_tray(self):
        if self.no_tray:
            return
        try:
            from .tray import TrayIcon, HAS_TRAY
            if not HAS_TRAY:
                logger.warn("托盘组件不可用（缺 pystray/Pillow），跳过")
                return
            self.tray = TrayIcon(self)
            self.tray.start()
            logger.info("系统托盘已启动")
        except Exception as e:
            logger.warn(f"托盘启动失败: {e}")
            self.tray = None

    def show_from_tray(self):
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
            self.after(40, self._apply_region)
        except Exception:
            pass

    def tray_toggle_protection(self):
        try:
            if monitor.paused:
                monitor.resume()
                self._notify("实时防护已恢复")
            else:
                monitor.pause()
                self._notify("实时防护已暂停")
        except Exception as e:
            logger.warn(f"托盘切换防护失败: {e}")

    def real_quit(self):
        try:
            monitor.stop()
        except Exception:
            pass
        try:
            if self.tray:
                self.tray.stop()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass
        os._exit(0)

    # ---------------- 定时刷新 ----------------
    def _tick(self, force=False):
        try:
            st = monitor.status
            if st.get("paused"):
                self.side_state.configure(text="● 实时防护 已暂停", text_color="#e0a955")
            elif st.get("running"):
                self.side_state.configure(text="● 实时防护 运行中", text_color=BRAND)
            else:
                self.side_state.configure(text="● 实时防护 已停止", text_color=DANGER)
            self.side_threat.configure(
                text=f"事件 {st.get('events', 0)} · 处置 "
                     f"{st.get('stats', {}).get('disposed', 0)}")
            self.status_right.configure(
                text=f"信任 {trust.count} · 隔离 {quarantine.count} · "
                     f"锁定 {lockdown.count} · 快照 {len(snapshot.list_snapshots())}")
            page = self._pages.get(self._current)
            if page:
                page.refresh()
        except Exception:
            pass
        self.after(3000, self._tick)

    # ---------------- 初次启动向导 ----------------
    def _maybe_wizard(self):
        if config.get_bool("wizard_done", False) or self._wizard_open:
            return
        try:
            from .wizard import run_wizard
            self._wizard_open = True
            run_wizard(self, on_done=self._wizard_done)
        except Exception as e:
            logger.warn(f"向导打开失败: {e}")
            config.set("wizard_done", True)

    def _wizard_done(self):
        self._wizard_open = False
        config.set("wizard_done", True)
        try:
            set_theme(config.get("theme", "dark"))
        except Exception:
            pass
        self.show_page("dashboard")


def run(scan_target=None):
    """程序入口：创建主窗口、注册页面、进入事件循环。

    scan_target 非空时（右键菜单"自定义查杀"），进入扫描页并直接开扫。
    """
    app = ShieldApp()
    from . import register_all
    pages = register_all(app)
    if scan_target:
        try:
            sp = pages.get("scan")
            sp._custom_dirs = [os.path.abspath(scan_target)]
            app.show_page("scan")
            app.after(2000, lambda: sp.start_mode("custom"))
        except Exception:
            logger.warn(f"自定义查杀启动失败: {scan_target}")
    app.mainloop()

