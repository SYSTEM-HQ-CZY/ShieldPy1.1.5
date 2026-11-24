# -*- coding: utf-8 -*-
"""进程体检页：枚举进程、识别可疑进程、结束进程树。"""
import os
from tkinter import messagebox

import customtkinter as ctk

from core import logger
from core.process import scan_processes, kill_process, list_processes
from core.terminator import kill_tree

from .ctk_base import BRAND, DANGER, BasePage, Card, make_tree, tok


class ProcessPage(BasePage):
    title = "进程体检"
    subtitle = "枚举运行中的进程，识别可疑进程并支持结束进程树"

    def build(self):
        root = self.content
        root.grid_columnconfigure(0, weight=1)
        root.grid_rowconfigure(0, weight=1)

        tree = make_tree(root, ["PID", "进程名", "可执行路径", "判定"],
                         widths=[80, 200, 560, 200], height=13)
        tree._frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))
        self.tree = tree._frame
        self.tree.grid_propagate(False)
        self.tt = tree
        self._procs = {}

        bar = Card(root, height=64)
        bar.grid(row=1, column=0, sticky="ew")
        ctk.CTkButton(bar.body, text="全面体检", width=110, height=32, corner_radius=8,
                      fg_color=BRAND, command=self._inspect).grid(
            row=0, column=0, padx=(6, 8), pady=14)
        ctk.CTkButton(bar.body, text="结束进程树", width=120, height=32, corner_radius=8,
                      fg_color=DANGER, hover_color="#b84343",
                      command=self._kill).grid(row=0, column=1, padx=8, pady=14)
        ctk.CTkButton(bar.body, text="刷新", width=80, height=32, corner_radius=8,
                      fg_color=tok("card2"), command=self._list_all).grid(
            row=0, column=2, padx=8, pady=14)
        self.lbl = ctk.CTkLabel(bar.body, text="", anchor="e",
                                font=ctk.CTkFont(size=11), text_color=tok("dim"))
        self.lbl.grid(row=0, column=3, sticky="e", padx=(8, 14), pady=14)
        bar.body.grid_columnconfigure(3, weight=1)

    def _list_all(self):
        try:
            for i in self.tt.get_children():
                self.tt.delete(i)
            self._procs = {}
            procs = list_processes()
            for pid, name, path in procs:
                iid = self.tt.insert("", "end", values=(pid, name, path, ""))
                self._procs[iid] = (pid, name, path)
            self.lbl.configure(text=f"共 {len(procs)} 个进程")
        except Exception as e:
            logger.warn(f"枚举进程失败: {e}")

    def _inspect(self):
        self._list_all()
        try:
            total, threats = scan_processes()
        except Exception as e:
            messagebox.showerror("体检失败", str(e))
            return
        for iid, (pid, name, path) in list(self._procs.items()):
            for t in threats:
                if t.get("pid") == pid:
                    try:
                        self.tt.set(iid, "判定", t.get("threat", "可疑"))
                        self.tt.item(iid, tags=("bad",))
                        self.tt.tag_configure("bad", foreground=DANGER)
                    except Exception:
                        pass
        if threats:
            messagebox.showwarning(
                "体检结果",
                f"共检查 {total} 个进程，发现 {len(threats)} 个可疑进程：\n\n"
                + "\n".join(f"· PID {t.get('pid')} {t.get('name')} — {t.get('threat')}"
                            for t in threats[:10]))
        else:
            messagebox.showinfo("体检结果", f"共检查 {total} 个进程，未发现可疑进程")

    def _kill(self):
        sel = self.tt.selection()
        if not sel:
            messagebox.showinfo("提示", "请选择要结束的进程")
            return
        pid, name, path = self._procs.get(sel[0], (None, "", ""))
        if not pid:
            return
        if not messagebox.askyesno(
                "确认",
                f"将结束进程树：PID {pid} {name}\n(会先结束其所有子进程)\n继续？"):
            return
        killed, msgs = kill_tree(int(pid))
        messagebox.showinfo("已结束",
                            f"共结束 {killed} 个进程\n" + "\n".join(msgs[:6]))
        self._list_all()

    def on_show(self):
        self._list_all()
