# -*- coding: utf-8 -*-
"""启动项 / 服务 / 注册表残留清理（v1.1.0 处置链路最后一环）。

处置一个恶意文件后，必须把它留下的"自动复活"痕迹一并清掉：
  1) 注册表 Run / RunOnce（HKCU + HKLM + WOW6432Node）
  2) 启动文件夹里的快捷方式 / 脚本
  3) 服务注册表项里 ImagePath 指向该文件的恶意服务（尝试 sc delete）
  4) 常见注册表位置中记录该文件路径的残留值
"""
import os
import subprocess
import winreg

from . import logger

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
]

RESIDUE_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"),
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\App Paths"),
]

SERVICES_KEY = r"SYSTEM\CurrentControlSet\Services"


def _startup_dirs():
    out = []
    appdata = os.environ.get("APPDATA", "")
    programdata = os.environ.get("ProgramData", "C:\\ProgramData")
    if appdata:
        out.append(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    out.append(os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\StartUp"))
    return [d for d in out if os.path.isdir(d)]


def list_startup_entries():
    """列出全部启动项：[{'type','location','name','command'}]"""
    out = []
    for hive, sub in RUN_KEYS:
        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    out.append({"type": "registry", "location": f"{hive_name}\\{sub}",
                                "name": name, "command": str(val)})
                    i += 1
        except Exception:
            continue
    for d in _startup_dirs():
        try:
            for fn in os.listdir(d):
                out.append({"type": "startup_folder", "location": d,
                            "name": fn, "command": os.path.join(d, fn)})
        except Exception:
            continue
    return out


def _match(command, target_path, target_name):
    c = (command or "").lower()
    if target_path and target_path.lower() in c:
        return True
    if target_name and target_name.lower() in c:
        return True
    return False


def clean_startup(target_path, target_name=None):
    """清理指向目标的注册表 Run 项与启动文件夹项。返回清理列表。"""
    target_name = target_name or os.path.basename(target_path or "")
    removed = []
    for hive, sub in RUN_KEYS:
        hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ) as k:
                i = 0
                victims = []
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    if _match(str(val), target_path, target_name):
                        victims.append((name, str(val)))
                    i += 1
            for name, val in victims:
                try:
                    with winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE) as kw:
                        winreg.DeleteValue(kw, name)
                    removed.append({"type": "启动项", "location": f"{hive_name}\\{sub}",
                                    "detail": f"{name} = {val}"})
                    logger.warning(f"已清理启动项: {hive_name}\\{sub}\\{name}")
                except Exception as e:
                    logger.warn(f"清理启动项失败 {name}: {e}")
        except Exception:
            continue

    for d in _startup_dirs():
        try:
            for fn in os.listdir(d):
                full = os.path.join(d, fn)
                hit = _match(fn, target_path, target_name)
                if not hit and fn.lower().endswith((".url", ".lnk")):
                    try:
                        with open(full, "rb") as f:
                            blob = f.read(4096)
                        if target_name.lower().encode("utf-16-le") in blob or \
                           target_name.lower().encode("mbcs", "ignore") in blob:
                            hit = True
                    except Exception:
                        pass
                if hit:
                    try:
                        os.remove(full)
                        removed.append({"type": "启动文件夹", "location": d, "detail": fn})
                        logger.warning(f"已删除启动文件夹项: {full}")
                    except Exception as e:
                        logger.warn(f"删除启动项文件失败 {full}: {e}")
        except Exception:
            continue
    return removed


def clean_services(target_path, target_name=None):
    """查找 ImagePath 指向目标的服务并删除。返回清理列表。"""
    target_name = target_name or os.path.basename(target_path or "")
    removed = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICES_KEY, 0, winreg.KEY_READ) as root:
            i = 0
            while True:
                try:
                    svc = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, svc, 0, winreg.KEY_READ) as k:
                        try:
                            img, _ = winreg.QueryValueEx(k, "ImagePath")
                        except OSError:
                            continue
                    if _match(str(img), target_path, target_name):
                        r = subprocess.run(["sc", "delete", svc], capture_output=True,
                                           timeout=20, universal_newlines=True,
                                           creationflags=0x08000000)
                        ok = r.returncode == 0
                        removed.append({
                            "type": "服务", "location": f"{SERVICES_KEY}\\{svc}",
                            "detail": f"{svc} -> {img} ({'已删除' if ok else '删除失败'})",
                        })
                        if ok:
                            logger.warning(f"已删除恶意服务: {svc} ({img})")
                        else:
                            logger.warn(f"删除服务失败 {svc}: {r.stdout}{r.stderr}")
                except Exception:
                    continue
    except Exception:
        pass
    return removed


def scan_residue(target_path, target_name=None, depth_search=True):
    """登记（不删除）与目标相关的残留项，供 UI 展示。”
    返回 [{type, location, detail}]。"""
    target_name = target_name or os.path.basename(target_path or "")
    found = []
    for e in list_startup_entries():
        if _match(e.get("command"), target_path, target_name):
            found.append({"type": "启动项", "location": e["location"],
                          "detail": f"{e['name']} = {e['command']}"})
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICES_KEY, 0, winreg.KEY_READ) as root:
            i = 0
            while True:
                try:
                    svc = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, svc, 0, winreg.KEY_READ) as k:
                        try:
                            img, _ = winreg.QueryValueEx(k, "ImagePath")
                        except OSError:
                            continue
                    if _match(str(img), target_path, target_name):
                        found.append({"type": "服务", "location": f"{SERVICES_KEY}\\{svc}",
                                      "detail": f"{svc} -> {img}"})
                except Exception:
                    continue
    except Exception:
        pass
    if depth_search:
        for hive, sub in RESIDUE_KEYS:
            hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
            try:
                with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ) as k:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(k, i)
                        except OSError:
                            break
                        i += 1
                        if _match(str(val), target_path, target_name):
                            found.append({"type": "注册表", "location": f"{hive_name}\\{sub}",
                                          "detail": f"{name} = {val}"})
            except Exception:
                continue
    return found


def clean_all(target_path, target_name=None):
    """处置链路用：清理启动项 + 服务。返回 (removed_list, count)。"""
    removed = []
    removed.extend(clean_startup(target_path, target_name))
    removed.extend(clean_services(target_path, target_name))
    if removed:
        logger.warning(f"残留清理：共 {len(removed)} 项来自 {target_path}")
    return removed, len(removed)
