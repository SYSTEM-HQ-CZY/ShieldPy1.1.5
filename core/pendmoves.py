# -*- coding: utf-8 -*-
"""占用文件"重启删除"（PendingFileRenameOperations / MoveFileEx DELAY_UNTIL_REBOOT）。

原理：调用 kernel32.MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)，
系统会把该路径登记到：
  HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations
下次开机由 Smss/Ntfs 在卷挂载早期删除（此时文件不会被任何进程占用）。
需要管理员权限；失败时返回 False，由调用方回退到其他处置策略。
"""
import ctypes
import os
import winreg

from . import logger

MOVEFILE_DELAY_UNTIL_REBOOT = 0x4
SM_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager"
SM_VALUE = "PendingFileRenameOperations"


def schedule_delete(path):
    """登记"重启后删除"。返回 (ok, msg)。"""
    try:
        if not path:
            return False, "空路径"
        abs_path = os.path.abspath(path)
        if not os.path.exists(abs_path):
            return True, "文件已不存在"
        kernel32 = ctypes.windll.kernel32
        kernel32.MoveFileExW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        kernel32.MoveFileExW.restype = ctypes.c_int
        ok = kernel32.MoveFileExW(abs_path, None, MOVEFILE_DELAY_UNTIL_REBOOT)
        if ok:
            logger.warning(f"已登记重启删除（PendMoves）: {abs_path}")
            return True, "已登记，将在重启时删除"
        err = ctypes.get_last_error()
        logger.warn(f"登记重启删除失败 {abs_path} (WinError={err})")
        if err == 5:
            return False, "权限不足（需要管理员权限）"
        return False, f"登记失败（WinError={err}）"
    except Exception as e:
        logger.error(f"PendMoves 异常: {e}")
        return False, str(e)


def list_pending():
    """读取当前 PendingFileRenameOperations 中的删除项（dest 为空表示删除）。"""
    out = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SM_KEY, 0, winreg.KEY_READ) as k:
            try:
                val, vtype = winreg.QueryValueEx(k, SM_VALUE)
            except FileNotFoundError:
                return out
        if not isinstance(val, (list, tuple)):
            return out
        # 元素成对出现：source, destination（destination 空串 = 删除）
        for i in range(0, len(val) - 1, 2):
            src, dst = val[i], val[i + 1]
            if not dst and src:
                out.append(src.replace("\\??\\", ""))
    except Exception:
        pass
    return out


def clear_pending():
    """清空整个 PendingFileRenameOperations 值（慎用，会丢弃其他软件的登记）。"""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SM_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, SM_VALUE)
        logger.warning("已清空 PendingFileRenameOperations")
        return True
    except Exception as e:
        return False
