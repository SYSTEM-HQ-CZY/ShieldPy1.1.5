@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================
echo   ShieldPy 玄盾卫士  -  正在启动...
echo   使用 Python: D:\python\python.exe
echo ============================================
D:\python\python.exe main.py
if errorlevel 1 (
  echo.
  echo 启动失败。请确认 D:\python\python.exe 存在。
  pause
)
