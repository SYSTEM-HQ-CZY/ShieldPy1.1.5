# -*- coding: utf-8 -*-
"""初次启动向导（v1.1.5 修复版）。

四步：欢迎 → 防护模块 → 默认处置策略 → 性能与信任 → 完成。

v1.1.5 针对"点下一步黑屏卡死 / 按钮无响应 / 无法关闭"的修复：
    1. **异步渲染**：切换步骤不再同步销毁+重建控件，而是先画"加载占位"，
       再 after(50) 在事件循环空闲时渲染，避免 Tk 主循环被长任务堵死。
    2. **加载占位**：每次切换先显示"正在准备下一步…"，用户立刻看到反馈，
       不会出现黑屏。
    3. **异常兜底**：渲染过程整体 try/except，出错时显示错误页（含关闭与重试），
       绝不让窗口卡在半成品状态。
    4. **防重入**：切换期间禁用上一步/下一步，避免连点导致控件重复创建。
    5. **可关闭**：标题栏关闭、Esc、底部「关闭」按钮三处出口；关闭即视为
       使用当前/默认配置完成向导，不会每次启动都弹。
    6. **耗时逻辑丢后台线程**：完成页的防勒索快照创建放到 worker 线程，
       期间界面显示"正在创建快照"，完成后才关闭窗口。
"""
import threading
import traceback

import customtkinter as ctk

from core import __version__, logger
from core.config import config
from core.protected import protected
from core.snapshot import snapshot

from .ctk_base import BRAND, BRAND_HOVER, DANGER, tok

MODULE_ITEMS = [
    ("file_av", "文件反病毒", "扫描文件、特征库、启发式、YARA、Office 宏", True),
    ("network", "反网络攻击", "可疑网络行为告警（不主动断网）", True),
    ("system_watcher", "System Watcher", "行为采集 + 加权评分，勒索防护核心", True),
    ("protected", "受控文件夹防护", "监控文档/桌面等目录的批量篡改", True),
    ("ransomware", "勒索防护", "高危评分 + 快照备份 + 回滚", True),
    ("advanced_clear", "高级清除", "NSudo 提权强制清除（高风险，默认关闭）", False),
]

LEVEL_ITEMS = [
    ("quarantine", "隔离（推荐）", "移入隔离区，可随时恢复"),
    ("delete", "删除", "抹除文件并清理启动项/服务残留"),
    ("advanced", "高级清除", "NSudo 提权强制删除，不可回滚（高风险）"),
]


class Wizard(ctk.CTkToplevel):
    def __init__(self, master, on_done=None):
        super().__init__(master)
        self.on_done = on_done
        self.step = 0
        self.module_vars = {}
        self.level = str(config.get("dispose_level", "quarantine"))
        self._switching = False
        self._closed = False
        self._render_ok = False

        self.title("玄盾卫士 初次启动向导")
        self.geometry("760x540")
        self.resizable(False, False)
        self.configure(fg_color=tok("bg"))
        try:
            self.protocol("WM_DELETE_WINDOW", self._close)
            self.bind("<Escape>", lambda e: self._close())
            # 注：不再 transient(master)。主窗口是无边框（overrideredirect）窗口，
        # 其 transient 子窗口在部分系统上不绘制 → 表现为"黑屏"。
        except Exception:
            pass
        try:
            self.after(260, lambda: self.attributes("-topmost", False))
        except Exception:
            pass

        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.pack(fill="both", expand=True, padx=24, pady=(20, 8))

        self.nav = ctk.CTkFrame(self, fg_color="transparent")
        self.nav.pack(fill="x", padx=24, pady=(0, 18))
        self.btn_close = ctk.CTkButton(self.nav, text="关闭", width=80, height=34,
                                       corner_radius=8, fg_color=tok("card2"),
                                       command=self._close)
        self.btn_close.pack(side="left")
        self.btn_back = ctk.CTkButton(self.nav, text="上一步", width=100, height=34,
                                      corner_radius=8, fg_color=tok("card2"),
                                      command=self._back)
        self.btn_back.pack(side="left", padx=(8, 0))
        self.btn_next = ctk.CTkButton(self.nav, text="下一步", width=110, height=34,
                                      corner_radius=8, fg_color=BRAND,
                                      command=self._next)
        self.btn_next.pack(side="right")

        # 首帧先给占位，避免白屏/黑屏；渲染延后到事件循环空闲时
        self._token = 1
        self._render_loading("正在启动向导…")
        self.after(80, lambda: self._do_render(self._token))
        # 兜底：万一 after 回调被长任务拖延，700ms 后强制同步渲染一次
        self.after(700, lambda: self._force_render(self._token))

        try:
            self.lift()
            self.focus_force()
        except Exception:
            pass

    # ---------------- 渲染驱动（异步 + 兜底） ----------------
    def _clear(self):
        try:
            for w in self.body.winfo_children():
                w.destroy()
        except Exception:
            pass

    def _set_nav_enabled(self, enabled):
        try:
            self.btn_close.configure(state="normal")
            self.btn_back.configure(state="normal" if (enabled and self.step > 0)
                                    else "disabled")
            self.btn_next.configure(state="normal" if enabled else "disabled")
        except Exception:
            pass

    def _render_loading(self, text="正在准备下一步…"):
        """加载占位：立刻显示反馈，绝不留黑屏。"""
        self._clear()
        try:
            wrap = ctk.CTkFrame(self.body, fg_color="transparent")
            wrap.pack(expand=True)
            ctk.CTkLabel(wrap, text="⏳", font=ctk.CTkFont(size=30),
                         text_color=BRAND).pack(pady=(0, 10))
            ctk.CTkLabel(wrap, text=text, font=ctk.CTkFont(size=14)).pack()
            bar = ctk.CTkProgressBar(wrap, width=260, height=8, corner_radius=4,
                                     progress_color=BRAND)
            bar.pack(pady=(14, 0))
            try:
                bar.configure(mode="indeterminate")
                bar.start()
            except Exception:
                bar.set(0.5)
            self._loading_bar = bar
        except Exception:
            pass
        self._set_nav_enabled(False)

    def _render_error(self, detail):
        """异常兜底页：告诉用户可以关闭或重试，窗口不会卡死。"""
        self._clear()
        try:
            ctk.CTkLabel(self.body, text="⚠ 向导渲染出错", anchor="w",
                         font=ctk.CTkFont(size=18, weight="bold"),
                         text_color=DANGER).pack(anchor="w", pady=(0, 8))
            ctk.CTkLabel(self.body,
                         text="这一步的界面没能正常生成，但窗口仍可关闭。\n"
                              "你可以点「重试」再渲染一次，或点「关闭」使用默认配置进入主界面。",
                         anchor="w", justify="left", wraplength=680,
                         font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(0, 10))
            box = ctk.CTkTextbox(self.body, height=200, corner_radius=10,
                                 font=ctk.CTkFont(size=10))
            box.pack(fill="both", expand=True)
            box.insert("1.0", str(detail)[-2000:])
            box.configure(state="disabled")
            row = ctk.CTkFrame(self.body, fg_color="transparent")
            row.pack(fill="x", pady=(10, 0))
            ctk.CTkButton(row, text="重试", width=100, height=32, corner_radius=8,
                          fg_color=BRAND, command=self._do_render).pack(side="left")
            ctk.CTkButton(row, text="关闭", width=100, height=32, corner_radius=8,
                          fg_color=tok("card2"), command=self._close).pack(
                side="left", padx=8)
        except Exception:
            pass
        logger.error(f"向导渲染异常: {detail}")
        self._set_nav_enabled(True)

    def _do_render(self, token=None):
        """真实渲染（带兜底）。"""
        if self._closed:
            return
        if token is not None and token != self._token:
            return
        try:
            self._render()
            self._render_ok = True
        except Exception:
            self._render_ok = False
            self._render_error(traceback.format_exc())
        finally:
            self._switching = False
            if not self._closed and self._render_ok:
                self._set_nav_enabled(True)

    def _force_render(self, token):
        """兜底渲染：若仍停在加载占位，直接同步渲染，避免永远卡住。"""
        if self._closed or token != self._token:
            return
        if not self._render_ok:
            logger.warn(f"向导步骤 {self.step} 渲染超时，触发兜底同步渲染")
            self._do_render(token)

    def _go(self, new_step):
        """异步切步：先占位，再空闲时渲染（另设兜底）。"""
        if self._switching or self._closed:
            return
        self._switching = True
        self._render_ok = False
        self.step = max(0, min(3, int(new_step)))
        self._token = getattr(self, "_token", 0) + 1
        tok = self._token
        self._render_loading()
        self.after(50, lambda: self._do_render(tok))
        self.after(700, lambda: self._force_render(tok))

    def _render(self):
        self._clear()
        if self.step == 0:
            self._render_welcome()
        elif self.step == 1:
            self._render_modules()
        elif self.step == 2:
            self._render_level()
        else:
            self._render_finish()
        try:
            self.btn_next.configure(text="开始使用" if self.step == 3 else "下一步")
        except Exception:
            pass

    def _title(self, text, sub=""):
        ctk.CTkLabel(self.body, text=text, anchor="w",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(
            anchor="w", pady=(0, 6))
        if sub:
            ctk.CTkLabel(self.body, text=sub, anchor="w", justify="left",
                         font=ctk.CTkFont(size=11), text_color=tok("dim"),
                         wraplength=680).pack(anchor="w", pady=(0, 14))

    # ---------------- 四步内容 ----------------
    def _render_welcome(self):
        self._title(f"欢迎使用玄盾卫士 v{__version__}",
                    "对标卡巴斯基查杀流程的纯用户态杀毒软件：无内核驱动，"
                    "平时以普通权限运行，只有在高级清除等高危操作时才借 NSudo 提权。\n"
                    "接下来用一分钟完成基础配置。")
        items = [
            "① 选择你需要启用的防护模块",
            "② 配置威胁的默认处置策略（隔离 / 删除 / 高级清除）",
            "③ 选择扫描性能档位，并创建第一份防勒索快照",
        ]
        for t in items:
            ctk.CTkLabel(self.body, text=t, anchor="w",
                         font=ctk.CTkFont(size=13)).pack(anchor="w", pady=4)
        ctk.CTkLabel(self.body,
                     text="提示：受保护文件夹默认覆盖文档、桌面、图片、视频、下载目录；"
                          "所有限制（用户态延迟、驱动级 Rootkit 需转 PE 处理）都会在"
                          "对应模块页明确标注。随时可以点「关闭」跳过向导，后续在设置页调整。",
                     anchor="w", justify="left", wraplength=680,
                     font=ctk.CTkFont(size=11), text_color=tok("dim")).pack(
            anchor="w", pady=(16, 0))

    def _render_modules(self):
        self._title("选择防护模块",
                    "默认全部启用，只有「高级清除」因涉及提权风险需要你主动确认。")
        mods = config.get("modules_enabled") or {}
        for key, name, desc, default in MODULE_ITEMS:
            row = ctk.CTkFrame(self.body, fg_color=tok("card"), corner_radius=10)
            row.pack(fill="x", pady=3)
            var = ctk.BooleanVar(value=bool(mods.get(key, default)))
            if key == "advanced_clear" and not config.get_bool("advanced_clear_ack", False):
                var.set(False)
            self.module_vars[key] = var
            chk = ctk.CTkCheckBox(row, text=name, variable=var, width=180,
                                  font=ctk.CTkFont(size=13, weight="bold"),
                                  fg_color=BRAND, hover_color=BRAND_HOVER,
                                  checkmark_color="#ffffff",
                                  command=lambda k=key: self._on_module(k))
            chk.pack(side="left", padx=12, pady=8)
            ctk.CTkLabel(row, text=desc, anchor="w", font=ctk.CTkFont(size=11),
                         text_color=tok("dim")).pack(side="left", padx=(0, 12))

    def _on_module(self, key):
        if key == "advanced_clear" and self.module_vars[key].get():
            from tkinter import messagebox
            ok = messagebox.askyesno(
                "⚠ 高风险",
                "高级清除依赖 NSudo 提权到 TrustedInstaller 权限：\n"
                "· 可能被其他安全软件标记为风险工具；\n"
                "· 删除不可回滚；\n· 全程写入 data/advanced_clear.log。\n\n确认启用？")
            if not ok:
                self.module_vars[key].set(False)
                return
            config.set("advanced_clear_ack", True)

    def _render_level(self):
        self._title("默认处置策略",
                    "扫描或实时防护命中威胁时，默认采用哪种处置方式。"
                    "所有档位都会先终止占用进程（提示「进程已终止」），再执行处置。")
        self.level_var = ctk.StringVar(value=self.level)
        for key, name, desc in LEVEL_ITEMS:
            row = ctk.CTkFrame(self.body, fg_color=tok("card"), corner_radius=10)
            row.pack(fill="x", pady=4)
            rb = ctk.CTkRadioButton(row, text=name, variable=self.level_var,
                                    value=key, width=160,
                                    font=ctk.CTkFont(size=13, weight="bold"),
                                    fg_color=BRAND, hover_color=BRAND_HOVER)
            rb.pack(side="left", padx=12, pady=10)
            ctk.CTkLabel(row, text=desc, anchor="w", font=ctk.CTkFont(size=11),
                         text_color=DANGER if key == "advanced" else tok("dim")).pack(
                side="left")
        ctk.CTkLabel(self.body,
                     text="建议先用「隔离」观察一段时间，确认无误报后再使用删除或高级清除。",
                     anchor="w", font=ctk.CTkFont(size=11),
                     text_color=tok("dim")).pack(anchor="w", pady=(12, 0))

    def _render_finish(self):
        self._title("准备就绪",
                    "点击「开始使用」保存配置并进入主界面。")
        ctk.CTkLabel(self.body, text="扫描性能档位", anchor="w",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", pady=(0, 4))
        self.perf_var = ctk.StringVar(value=str(config.get("scan_perf_mode", "balanced")))
        rowp = ctk.CTkFrame(self.body, fg_color="transparent")
        rowp.pack(anchor="w", pady=(0, 14))
        for val, label in [("low", "低占用"), ("balanced", "均衡（推荐）"),
                           ("high", "高速")]:
            ctk.CTkRadioButton(rowp, text=label, variable=self.perf_var, value=val,
                               fg_color=BRAND, hover_color=BRAND_HOVER,
                               font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 16))
        self.perf_log_var = ctk.BooleanVar(value=config.get_bool("perf_log", True))
        ctk.CTkCheckBox(self.body, text="记录性能日志（便于排查 CPU 占用问题）",
                        variable=self.perf_log_var, fg_color=BRAND,
                        hover_color=BRAND_HOVER, checkmark_color="#ffffff",
                        font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(0, 14))
        self.snap_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(self.body, text="立即创建第一份防勒索快照（推荐）",
                        variable=self.snap_var, fg_color=BRAND,
                        hover_color=BRAND_HOVER, checkmark_color="#ffffff",
                        font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(0, 8))
        ctk.CTkLabel(self.body,
                     text=f"当前受保护文件夹：{len(protected.folders)} 个"
                          f"（可在「勒索防护」页调整）",
                     anchor="w", font=ctk.CTkFont(size=11),
                     text_color=tok("dim")).pack(anchor="w", pady=(6, 0))

    # ---------------- 导航 ----------------
    def _back(self):
        if self._switching or self.step <= 0:
            return
        self._go(self.step - 1)

    def _next(self):
        if self._switching or self._closed:
            return
        try:
            if self.step == 1:
                self._save_modules()
            elif self.step == 2:
                self._save_level()
            elif self.step == 3:
                self._finish()
                return
        except Exception:
            logger.error(f"向导保存失败: {traceback.format_exc()}")
        self._go(self.step + 1)

    def _save_modules(self):
        merged = dict(config.get("modules_enabled") or {})
        for key, var in self.module_vars.items():
            try:
                merged[key] = bool(var.get())
            except Exception:
                pass
        # 一次写入，避免多次 IO 造成切换卡顿
        config.set_many(modules_enabled=merged)

    def _save_level(self):
        try:
            level = self.level_var.get()
        except Exception:
            level = self.level
        config.set("dispose_level", level)

    # ---------------- 完成（耗时逻辑丢后台线程） ----------------
    def _finish(self):
        try:
            config.set_many(
                scan_perf_mode=self.perf_var.get(),
                perf_log=bool(self.perf_log_var.get()),
            )
        except Exception:
            pass
        want_snapshot = False
        try:
            want_snapshot = bool(self.snap_var.get())
        except Exception:
            want_snapshot = False

        if want_snapshot:
            self._switching = True
            self._render_loading("正在创建第一份防勒索快照…（大文件较多时需要几十秒）")

            def work():
                try:
                    snapshot.create(
                        label="初次启动快照",
                        max_file_mb=config.get_int("snapshot_max_file_mb", 20),
                        max_total_mb=config.get_int("snapshot_max_total_mb", 500))
                except Exception:
                    logger.warn(f"首次快照创建失败: {traceback.format_exc()}")
                try:
                    self.after(0, self._finish_done)
                except Exception:
                    pass

            threading.Thread(target=work, daemon=True).start()
        else:
            self._finish_done()

    def _finish_done(self):
        try:
            config.set("wizard_done", True)
            config.save()
        except Exception:
            pass
        self._close(mark_done=False)

    def _close(self, mark_done=True):
        """关闭向导。关闭即视为完成（使用当前/默认配置），下次启动不再弹出。"""
        if self._closed:
            return
        self._closed = True
        try:
            if mark_done:
                config.set("wizard_done", True)
                config.save()
        except Exception:
            pass
        try:
            self.grab_release()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass
        if self.on_done:
            try:
                self.on_done()
            except Exception:
                logger.error(f"向导完成回调异常: {traceback.format_exc()}")


def run_wizard(app, on_done=None):
    """创建并显示向导（app 为 ShieldApp，on_done 在关闭/完成后回调）。"""
    wiz = Wizard(app, on_done=on_done)
    try:
        wiz.grab_set()
    except Exception:
        pass
    return wiz
