# -*- coding: utf-8 -*-
"""
玄盾卫士 ShieldPy v1.1.5 —— 纯 Python 用户态杀毒软件
=====================================================
核心定位：对标卡巴斯基查杀流程，纯用户态实现，无内核驱动。

main.py 的职责（v1.1.5 按项目文件拆分要求）：
    * 程序入口（命令行参数、环境准备、异常落盘）
    * 主窗口装配（ShieldApp 的创建与启动、初次向导调度）
    * 权限模型（主程序默认普通权限；仅高级清除等高危机能才调 NSudo 提权）

其余拆分落点：
    config.py       配置、白名单、路径（core/config.py）
    engine.py       扫描引擎、风险打分、处置逻辑（core/engine.py）
    scan_panel.py   扫描页面、结果列表、复选框批量处置（ui/scan_panel.py）
    wizard.py       初次启动向导（ui/wizard.py）

主要功能：
  * 四种扫描模式：快速 / 全盘 / 可移动驱动器 / 后台低优先级
  * 风险加权打分：数字签名减免 + 日志基线白名单，单特征不直接判恶意
  * 处置链路：先终止进程树（提示"进程已终止"）→ 隔离/删除 → 清启动项/服务残留
  * 三档处置：隔离（可恢复）/ 删除 / 高级清除（点击时才 NSudo 提权）
  * 信任项：路径 + SHA256 双哈希；原地锁定：ACL 拒绝执行
  * 受保护文件夹、System Watcher、YARA/pefile/olevba、快照回滚、托盘常驻

运行:  python main.py                  （源码方式）
       python main.py --scan 目标路径     （右键菜单"自定义查杀"入口）
       ShieldPy.exe                     （PyInstaller 单文件，普通权限启动）
"""
import ctypes
import os
import shutil
import sys
import traceback
from pathlib import Path


def _ensure_sys_path():
    base = Path(__file__).resolve().parent
    if str(base) not in sys.path:
        sys.path.insert(0, str(base))
    return base


def check_tkinter():
    try:
        import tkinter  # noqa: F401
        return True
    except Exception:
        return False


def is_admin():
    """当前进程是否管理员（v1.1.5：主程序默认普通权限，仅在需要时提权）。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ensure_data_files():
    """单文件 EXE 首次运行：把内嵌初始资源复制到 data 目录。

    v1.1.5：主程序以普通权限运行，安装到 Program Files 时 exe 旁的 data 无法写入，
    core.config 已自动回退到 %LOCALAPPDATA%\\ShieldPy\\data；这里跟随同一目录，
    避免出现两份数据。
    """
    if not getattr(sys, "frozen", False):
        return
    try:
        from core.config import DATA_DIR
        data_dir = Path(DATA_DIR)
    except Exception:
        data_dir = Path(sys.executable).resolve().parent / "data"
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return

    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        src_root = Path(meipass) / "data"
        for name in ("signatures.json",):
            target = data_dir / name
            if not target.exists():
                src = src_root / name
                if src.exists():
                    try:
                        shutil.copy2(src, target)
                    except Exception:
                        pass
    for sub in ("quarantine", "logs", "yara", "snapshots", "locks", "reports"):
        try:
            (data_dir / sub).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass


def parse_args(argv):
    """--scan "路径" → 自定义查杀（右键菜单入口）。"""
    scan_target = None
    i = 0
    while i < len(argv):
        if argv[i] in ("--scan", "-s"):
            if i + 1 < len(argv) and argv[i + 1]:
                scan_target = argv[i + 1]
                i += 2
            else:
                i += 1
        else:
            i += 1
    return scan_target


def create_main_window(scan_target=None):
    """主窗口装配入口。

    主窗口类 ShieldApp 定义在 ui/app.py（无边框 + 自制标题栏 + 十页 + 托盘），
    这里负责：设置主题 → 构造窗口 → 调度初次向导 → 进入事件循环。
    """
    from core.config import config
    from ui.ctk_base import apply_dpi_awareness, set_theme

    apply_dpi_awareness()
    set_theme(config.get("theme", "dark"))

    from ui.app import ShieldApp
    return ShieldApp(scan_target=scan_target)


def run_app(scan_target=None):
    """启动主窗口（供 ui.app.run 复用）。"""
    app = create_main_window(scan_target=scan_target)
    app.run(scan_target=scan_target)
    return app


def main():
    scan_target = parse_args(sys.argv[1:])
    if sys.version_info < (3, 8):
        print("需要 Python 3.8 及以上版本")
        return 1
    if not check_tkinter():
        print("未找到 tkinter（图形界面库）")
        return 1

    _ensure_sys_path()
    ensure_data_files()

    try:
        from ui.app import run
        run(scan_target=scan_target)
        return 0
    except Exception:
        traceback.print_exc()
        try:
            from core.config import DATA_DIR
            err = Path(DATA_DIR) / "logs" / "startup_error.txt"
            err.parent.mkdir(parents=True, exist_ok=True)
            err.write_text(traceback.format_exc(), encoding="utf-8")
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
