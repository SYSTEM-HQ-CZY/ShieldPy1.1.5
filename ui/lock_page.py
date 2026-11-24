# -*- coding: utf-8 -*-
"""原地锁定页（v1.1.0 新增）。

可疑文件"只许存在、不许运行"：
    改所有者 → SYSTEM，ACL 拒绝 Everyone 执行；
    锁定前保存权限快照，放行时原样还原。
仅对用户目录生效，系统目录禁用。
"""
import os
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core.lockdown import lockdown, can_lock, user_dirs

from .ctk_base import BRAND, DANGER, BasePage, Card, make_tree, tok


class LockPage(BasePage):
    title = "原地锁定"
    subtitle = "改所有者+拒绝执行，锁定前保存权限快照（仅用户目录）"

    def build(self):
        root = self.content
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)

        tree = make_tree(root, ["锁定时间", "文件路径", "原始所有者", "大小", "原因"],
                         widths=[150, 460, 200, 90, 200], height=13)
        tree._frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        self.tree = tree._frame
        self.tree.grid_propagate(False)
        self.tt = tree
        self._items = {}

        bar = Card(root, height=64)
        bar.grid(row=1, column=0, sticky="ew")
        ctk.CTkButton(bar.body, text="锁定文件…", width=110, height=32, corner_radius=8,
                      fg_color=BRAND, command=self._pick_lock).grid(
            row=0, column=0, padx=(6, 8), pady=14)
        ctk.CTkButton(bar.body, text="放行（还原权限）", width=140, height=32,
                      corner_radius=8, fg_color=tok("card2"),
                      command=self._unlock).grid(row=0, column=1, padx=8, pady=14)
        ctk.CTkButton(bar.body, text="刷新", width=80, height=32, corner_radius=8,
                      fg_color=tok("card2"), command=self.refresh).grid(
            row=0, column=2, padx=8, pady=14)
        self.lbl = ctk.CTkLabel(bar.body, text="", anchor="e",
                                font=ctk.CTkFont(size=11), text_color=tok("dim"))
        self.lbl.grid(row=0, column=3, sticky="e", padx=(8, 14), pady=14)
        bar.body.grid_columnconfigure(3, weight=1)

        tip = ctk.CTkLabel(
            root, text="说明：锁定会把文件所有者改为 NT AUTHORITY\\SYSTEM，"
                       "并拒绝 Everyone 执行权限；文件仍在原位，双击无法运行。"
                       "系统目录（Windows / Program Files）禁止锁定。",
            anchor="w", font=ctk.CTkFont(size=11), text_color=tok("dim"),
            wraplength=980, justify="left")
        tip.grid(row=2, column=0, sticky="w", pady=(2, 0))

    def refresh(self):
        try:
            for i in self.tt.get_children():
                self.tt.delete(i)
            self._items = {}
            recs = lockdown.list_records()
            for r in recs:
                iid = self.tt.insert("", "end", values=(
                    r.locked_at, r.path, r.owner_before or "(未知)",
                    _size(r.size), r.reason))
                self._items[iid] = r
            self.lbl.configure(text=f"共 {len(recs)} 个已锁定文件")
        except Exception:
            pass

    def _pick_lock(self):
        d = filedialog.askopenfilename(title="选择要原地锁定的可疑文件")
        if not d:
            return
        ok, why = can_lock(d)
        if not ok:
            messagebox.showerror("不可锁定", why)
            return
        if not messagebox.askyesno(
                "确认锁定",
                f"将锁定：\n{d}\n\n锁定后该文件无法运行（双击无效），"
                f"权限快照会保存在 data/locks/ 下，可随时放行还原。\n继续？"):
            return
        ok, res = lockdown.lock(d, reason="用户手动锁定")
        if ok:
            messagebox.showinfo("锁定成功",
                                f"已锁定：{os.path.basename(d)}\n"
                                f"所有者→System，已拒绝普通用户执行")
        else:
            messagebox.showerror("锁定失败", str(res))
        self.refresh()

    def _unlock(self):
        sel = self.tt.selection()
        if not sel:
            messagebox.showinfo("提示", "请选择要放行的文件")
            return
        rec = self._items.get(sel[0])
        if not rec:
            return
        if not messagebox.askyesno("确认放行",
                                   f"将还原权限并恢复所有者：\n{rec.path}\n继续？"):
            return
        ok, msg = lockdown.unlock(rec.id)
        if ok:
            messagebox.showinfo("已放行", msg)
        else:
            messagebox.showerror("放行失败", msg)
        self.refresh()

    def on_show(self):
        self.refresh()


def _size(n):
    try:
        n = float(n)
    except Exception:
        return "?"
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{u}"
        n /= 1024
    return f"{n:.1f}TB"
