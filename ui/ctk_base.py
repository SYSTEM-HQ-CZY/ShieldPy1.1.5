# -*- coding: utf-8 -*-
"""CustomTkinter 基础层（v1.1.0 UI 规范）。

提供：
  * 高 DPI 适配（SetProcessDpiAwareness）
  * 无原生标题栏窗口：overrideredirect + 自制顶部栏（拖动 / 最小化 / 最大化 / 关闭）
  * 窗口圆角（SetWindowRgn 圆角区域，最大化时自动取消）
  * 统一样式：圆角卡片、主色、深浅色主题
"""
import ctypes
import sys

import customtkinter as ctk

# -------- 配色 --------
BRAND = "#0d9e6e"          # 主色（玄盾绿）
BRAND_HOVER = "#0b8760"
DANGER = "#e05555"
DARK_BG = "#1a1d21"
DARK_CARD = "#24282d"
DARK_CARD_2 = "#2c3137"
DARK_TEXT = "#e8eaed"
DARK_TEXT_DIM = "#9aa1a9"
LIGHT_BG = "#f2f4f7"
LIGHT_CARD = "#ffffff"
LIGHT_CARD_2 = "#e9edf2"
LIGHT_TEXT = "#1a1d21"
LIGHT_TEXT_DIM = "#5b6371"

CORNER = 12
TITLE_H = 40


def apply_dpi_awareness():
    """让窗口在高 DPI 屏幕上不发虚。"""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)   # PER_MONITOR_DPI_AWARE
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def set_theme(theme):
    ctk.set_appearance_mode("dark" if str(theme).lower() != "light" else "light")


def is_dark():
    return ctk.get_appearance_mode().lower() == "dark"


def tok(name):
    """取当前主题颜色 token：bg/card/card2/text/dim"""
    dark = is_dark()
    return {
        "bg": DARK_BG if dark else LIGHT_BG,
        "card": DARK_CARD if dark else LIGHT_CARD,
        "card2": DARK_CARD_2 if dark else LIGHT_CARD_2,
        "text": DARK_TEXT if dark else LIGHT_TEXT,
        "dim": DARK_TEXT_DIM if dark else LIGHT_TEXT_DIM,
    }[name]


def round_region(hwnd, w, h, radius=16):
    """给窗口设置圆角区域（最大化时由调用方跳过）。"""
    try:
        rgn = ctypes.windll.gdi32.CreateRoundRectRgn(
            0, 0, w + 1, h + 1, radius * 2, radius * 2)
        ctypes.windll.user32.SetWindowRgn(hwnd, rgn, True)
    except Exception:
        pass


class TitleBar(ctk.CTkFrame):
    """自制顶部栏：图标 + 标题 + 最小化/最大化/关闭 + 拖动。"""

    def __init__(self, master, title="玄盾卫士", subtitle="", icon_path=""):
        super().__init__(master, height=TITLE_H, corner_radius=0, fg_color="transparent")
        self.app = master
        self.grid_propagate(False)
        self._drag_x = 0
        self._drag_y = 0

        self.icon_label = ctk.CTkLabel(self, text="🛡", font=ctk.CTkFont(size=18),
                                       width=28)
        # 注意：🛡 属 emoji(U+1F6E1)，Tcl 8.6 无法渲染色板，改用 BMP 内符号
        self.icon_label.configure(text="♜")
        self.icon_label.grid(row=0, column=0, padx=(14, 4), pady=6)

        self.title_label = ctk.CTkLabel(
            self, text=title, anchor="w", font=ctk.CTkFont(size=13, weight="bold"))
        self.title_label.grid(row=0, column=1, sticky="w", padx=(0, 8))

        self.subtitle_label = ctk.CTkLabel(
            self, text=subtitle, anchor="w", font=ctk.CTkFont(size=11),
            text_color=tok("dim"))
        self.subtitle_label.grid(row=0, column=2, sticky="w")

        self.grid_columnconfigure(2, weight=1)

        self.btn_min = ctk.CTkButton(
            self, text="—", width=34, height=26, corner_radius=6,
            fg_color="transparent", hover_color=tok("card2"),
            font=ctk.CTkFont(size=14), command=self.app.minimize)
        self.btn_min.grid(row=0, column=3, padx=2, pady=6)

        self.btn_max = ctk.CTkButton(
            self, text="▢", width=34, height=26, corner_radius=6,
            fg_color="transparent", hover_color=tok("card2"),
            font=ctk.CTkFont(size=13), command=self.app.toggle_maximize)
        self.btn_max.grid(row=0, column=4, padx=2, pady=6)

        self.btn_close = ctk.CTkButton(
            self, text="✕", width=34, height=26, corner_radius=6,
            fg_color="transparent", hover_color="#e05555",
            font=ctk.CTkFont(size=13), command=self.app.close_window)
        self.btn_close.grid(row=0, column=5, padx=(2, 10), pady=6)

        for w in (self, self.title_label, self.subtitle_label, self.icon_label):
            w.bind("<Button-1>", self._start_drag)
            w.bind("<B1-Motion>", self._do_drag)
            w.bind("<Double-Button-1>", lambda e: self.app.toggle_maximize())

    def _start_drag(self, event):
        self._drag_x = event.x_root - self.app.winfo_x()
        self._drag_y = event.y_root - self.app.winfo_y()

    def _do_drag(self, event):
        if getattr(self.app, "_is_max", False):
            return
        x = event.x_root - self._drag_x
        y = event.y_root - self._drag_y
        self.app.geometry(f"+{x}+{y}")


class Card(ctk.CTkFrame):
    """圆角卡片容器。可带标题。"""

    def __init__(self, master, title="", subtitle="", height=None, **kw):
        kw.setdefault("corner_radius", CORNER)
        kw.setdefault("fg_color", tok("card"))
        super().__init__(master, **kw)
        self._title = title
        if height:
            self.configure(height=height)
        if title:
            head = ctk.CTkLabel(self, text=title, anchor="w",
                                font=ctk.CTkFont(size=13, weight="bold"),
                                text_color=tok("text"))
            head.grid(row=0, column=0, sticky="w", padx=14, pady=(10, 0))
            if subtitle:
                sub = ctk.CTkLabel(self, text=subtitle, anchor="w",
                                   font=ctk.CTkFont(size=11), text_color=tok("dim"))
                sub.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 4))
            self.body = ctk.CTkFrame(self, fg_color="transparent")
            self.body.grid(row=2, column=0, sticky="nsew", padx=10, pady=(2, 10))
            self.grid_columnconfigure(0, weight=1)
            self.grid_rowconfigure(2, weight=1)
        else:
            self.body = self

    def add(self, widget, **grid_kw):
        widget.master = self.body if self.body is not self else self
        return widget


class ScrollPage(ctk.CTkScrollableFrame):
    """可滚动页面基类。"""

    def __init__(self, master, **kw):
        kw.setdefault("corner_radius", 0)
        kw.setdefault("fg_color", "transparent")
        super().__init__(master, **kw)


class BasePage(ctk.CTkFrame):
    """所有功能页的基类：统一背景 / 标题区 / 内容区。"""

    title = "页面"
    subtitle = ""

    def __init__(self, master, app):
        super().__init__(master, corner_radius=0, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        head = ctk.CTkFrame(self, fg_color="transparent", height=44)
        head.grid(row=0, column=0, sticky="ew", padx=16, pady=(10, 2))
        head.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(head, text=self.title, anchor="w",
                     font=ctk.CTkFont(size=18, weight="bold")).grid(
            row=0, column=0, sticky="w")
        if self.subtitle:
            ctk.CTkLabel(head, text=self.subtitle, anchor="w",
                         font=ctk.CTkFont(size=11), text_color=tok("dim")).grid(
                row=1, column=0, sticky="w")

        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 12))
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.build()

    def build(self):
        """子类实现。"""

    def on_show(self):
        """页面被切换到前台时调用（用于刷新数据）。"""

    def refresh(self):
        """定时刷新钩子。"""


def make_tree(parent, columns, widths=None, height=10):
    """统一风格的 ttk.Treeview（CTk 没有表格控件，嵌入 Treeview 是官方推荐做法）。"""
    import tkinter.ttk as ttk
    style = ttk.Style()
    dark = is_dark()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    bg = tok("card")
    fg = tok("text")
    style.configure("SP.Treeview", background=bg, fieldbackground=bg,
                    foreground=fg, rowheight=26, borderwidth=0,
                    font=("Microsoft YaHei UI", 10))
    style.configure("SP.Treeview.Heading", background=tok("card2"),
                    foreground=fg, relief="flat",
                    font=("Microsoft YaHei UI", 9, "bold"))
    style.map("SP.Treeview", background=[("selected", BRAND)],
              foreground=[("selected", "#ffffff")])

    frame = ctk.CTkFrame(parent, corner_radius=CORNER, fg_color=tok("card"))
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=height,
                        style="SP.Treeview")
    if widths:
        for c, w in zip(columns, widths):
            tree.heading(c, text=c)
            tree.column(c, width=w, anchor="w", stretch=True)
    else:
        for c in columns:
            tree.heading(c, text=c)
            tree.column(c, width=140, anchor="w", stretch=True)
    sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=sb.set)
    tree.grid(row=0, column=0, sticky="nsew", padx=(10, 0), pady=10)
    sb.grid(row=0, column=1, sticky="ns", padx=(0, 8), pady=10)
    frame.grid_columnconfigure(0, weight=1)
    frame.grid_rowconfigure(0, weight=1)
    tree._frame = frame
    return tree
