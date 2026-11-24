# -*- coding: utf-8 -*-
"""隔离区页：查看、恢复、彻底删除已隔离的威胁文件。"""
import os
import time
from tkinter import messagebox

import customtkinter as ctk

from core.quarantine import quarantine

from .ctk_base import BRAND, DANGER, BasePage, Card, make_tree, tok


def _fmt_size(n):
    try:
        n = float(n)
    except Exception:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class QuarantinePage(BasePage):
    title = "隔离区"
    subtitle = "已隔离的威胁文件（可恢复 / 彻底删除）"

    def build(self):
        root = self.content
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)

        tree = make_tree(root, ["时间", "威胁名称", "检测引擎", "原始路径", "大小"],
                         widths=[150, 220, 120, 460, 90], height=14)
        tree._frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        self.tree = tree._frame
        self.tree.grid_propagate(False)
        self.tt = tree
        self._items = {}

        bar = Card(root, height=64)
        bar.grid(row=1, column=0, sticky="ew")
        ctk.CTkButton(bar.body, text="恢复选中", width=110, height=32, corner_radius=8,
                      fg_color=BRAND, command=self._restore).grid(
            row=0, column=0, padx=(6, 8), pady=14)
        ctk.CTkButton(bar.body, text="彻底删除", width=110, height=32, corner_radius=8,
                      fg_color=DANGER, hover_color="#b84343",
                      command=self._delete).grid(row=0, column=1, padx=8, pady=14)
        ctk.CTkButton(bar.body, text="刷新", width=80, height=32, corner_radius=8,
                      fg_color=tok("card2"), command=self.refresh).grid(
            row=0, column=2, padx=8, pady=14)
        self.lbl = ctk.CTkLabel(bar.body, text="", anchor="e",
                                font=ctk.CTkFont(size=11), text_color=tok("dim"))
        self.lbl.grid(row=0, column=3, sticky="e", padx=(8, 14), pady=14)
        bar.body.grid_columnconfigure(3, weight=1)

    def refresh(self):
        try:
            for i in self.tt.get_children():
                self.tt.delete(i)
            items = quarantine.list_items()
            self._items = {}
            for it in items:
                iid = self.tt.insert("", "end", values=(
                    it.time, it.threat, it.detection, it.orig_path,
                    _fmt_size(it.size)))
                self._items[iid] = it
            total = sum(int(getattr(i, "size", 0) or 0) for i in items)
            self.lbl.configure(text=f"共 {len(items)} 个 · 占用 {_fmt_size(total)}")
        except Exception:
            pass

    def _selected(self):
        return [self._items[i] for i in self.tt.selection() if i in self._items]

    def _restore(self):
        sel = self._selected()
        if not sel:
            messagebox.showinfo("提示", "请选择要恢复的条目")
            return
        ok_n, fails = 0, []
        for it in sel:
            ok, msg = quarantine.restore(it.id)
            if ok:
                ok_n += 1
            else:
                fails.append(f"{os.path.basename(it.orig_path)}: {msg}")
        self.refresh()
        result = f"已恢复 {ok_n} 个文件"
        if fails:
            result += "\n\n失败：\n" + "\n".join(fails[:6])
        messagebox.showinfo("恢复结果", result)

    def _delete(self):
        sel = self._selected()
        if not sel:
            messagebox.showinfo("提示", "请选择要彻底删除的条目")
            return
        if not messagebox.askyesno("确认", f"彻底删除 {len(sel)} 个隔离文件？不可恢复。"):
            return
        n = 0
        for it in sel:
            ok, _ = quarantine.delete_forever(it.id)
            if ok:
                n += 1
        self.refresh()
        messagebox.showinfo("删除结果", f"已彻底删除 {n} 个文件")

    def on_show(self):
        self.refresh()
