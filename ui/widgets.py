# -*- coding: utf-8 -*-
"""UI 主题与通用控件。"""
import tkinter as tk
from tkinter import ttk

FONT = "Microsoft YaHei UI"

THEMES = {
    "dark": {
        "bg": "#0f1420",
        "sidebar": "#141a29",
        "card": "#1a2233",
        "card2": "#212c44",
        "border": "#26304a",
        "text": "#e6e9f0",
        "muted": "#8b94a7",
        "accent": "#3b82f6",
        "accent_hover": "#2f6ed6",
        "success": "#2e9e6b",
        "danger": "#e24c3b",
        "warn": "#f0b429",
        "tree_sel": "#2a3550",
        "entry_bg": "#141b2c",
    },
    "light": {
        "bg": "#f4f6fb",
        "sidebar": "#ffffff",
        "card": "#ffffff",
        "card2": "#eef1f8",
        "border": "#dde3f0",
        "text": "#1c2433",
        "muted": "#6b7688",
        "accent": "#2f6ed6",
        "accent_hover": "#1f5cc0",
        "success": "#1f8a5a",
        "danger": "#d64541",
        "warn": "#b8860b",
        "tree_sel": "#dbe6fb",
        "entry_bg": "#fafbfe",
    },
}


def apply_theme(root, theme_name="dark"):
    theme = THEMES.get(theme_name, THEMES["dark"])
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure(".", font=(FONT, 10))
    style.configure("TFrame", background=theme["bg"])
    style.configure("Card.TFrame", background=theme["card"])
    style.configure("TLabel", background=theme["bg"], foreground=theme["text"], font=(FONT, 10))
    style.configure("Card.TLabel", background=theme["card"], foreground=theme["text"])
    style.configure("Muted.TLabel", background=theme["card"], foreground=theme["muted"], font=(FONT, 9))
    style.configure("Title.TLabel", background=theme["card"], foreground=theme["text"], font=(FONT, 18, "bold"))
    style.configure("H2.TLabel", background=theme["card"], foreground=theme["text"], font=(FONT, 13, "bold"))
    style.configure("Accent.TLabel", background=theme["card"], foreground=theme["accent"], font=(FONT, 11, "bold"))

    style.configure("TButton", font=(FONT, 10), padding=(14, 7), background=theme["card2"],
                    foreground=theme["text"], borderwidth=0)
    style.map("TButton", background=[("active", theme["accent_hover"]),
                                     ("pressed", theme["accent"])])
    style.configure("Accent.TButton", background=theme["accent"], foreground="#ffffff")
    style.map("Accent.TButton", background=[("active", theme["accent_hover"])])
    style.configure("Danger.TButton", background=theme["danger"], foreground="#ffffff")
    style.map("Danger.TButton", background=[("active", "#c0392b")])
    style.configure("Ghost.TButton", background=theme["card2"], foreground=theme["muted"])
    style.map("Ghost.TButton", background=[("active", theme["border"])])

    style.configure("TProgressbar", troughcolor=theme["card2"], background=theme["accent"],
                    borderwidth=0, thickness=12)
    style.configure("Vertical.TScrollbar", background=theme["card2"], troughcolor=theme["bg"],
                    arrowcolor=theme["muted"], borderwidth=0)
    style.configure("Horizontal.TScrollbar", background=theme["card2"], troughcolor=theme["bg"],
                    arrowcolor=theme["muted"], borderwidth=0)

    style.configure("Treeview", background=theme["card"], fieldbackground=theme["card"],
                    foreground=theme["text"], borderwidth=0, rowheight=30,
                    font=(FONT, 9))
    style.configure("Treeview.Heading", background=theme["card2"], foreground=theme["muted"],
                    font=(FONT, 9, "bold"), borderwidth=0, relief="flat")
    style.map("Treeview", background=[("selected", theme["tree_sel"])],
              foreground=[("selected", theme["text"])])
    style.configure("TNotebook", background=theme["bg"], borderwidth=0)
    style.configure("TNotebook.Tab", background=theme["card2"], foreground=theme["muted"],
                    padding=(16, 8), font=(FONT, 10))
    style.map("TNotebook.Tab", background=[("selected", theme["card"])],
              foreground=[("selected", theme["accent"])])

    style.configure("TCheckbutton", background=theme["card"], foreground=theme["text"], font=(FONT, 10))
    style.map("TCheckbutton", background=[("active", theme["card"])])
    return theme


class SidebarButton(tk.Canvas):
    """侧边栏导航按钮（Canvas 实现高亮与悬停）。"""

    def __init__(self, master, text, icon="", command=None, theme=None, **kw):
        super().__init__(master, bd=0, highlightthickness=0, bg=theme["sidebar"], height=44, **kw)
        self.theme = theme
        self.command = command
        self.active = False
        self._text = f"{icon}  {text}"
        self.bind("<Button-1>", self._on_click)
        self.bind("<Enter>", lambda e: self._redraw(hover=True))
        self.bind("<Leave>", lambda e: self._redraw(hover=False))
        self.bind("<Configure>", lambda e: self._redraw())

    def _on_click(self, _e):
        if self.command:
            self.command()

    def set_active(self, active):
        self.active = active
        self._redraw()

    def _redraw(self, hover=False):
        w = self.winfo_width()
        if w < 10:
            return
        self.delete("all")
        bg = self.theme["accent"] if self.active else (self.theme["card2"] if hover else self.theme["sidebar"])
        if self.active:
            self.create_rectangle(0, 0, 3, 44, fill=self.theme["accent"], outline="")
            self.create_rectangle(3, 0, w, 44, fill=self.theme["card2"], outline="")
        else:
            self.create_rectangle(0, 0, w, 44, fill=bg, outline="")
        fg = self.theme["text"] if self.active else self.theme["muted"]
        self.create_text(20, 22, text=self._text, anchor="w", fill=fg, font=("Microsoft YaHei UI", 10))
