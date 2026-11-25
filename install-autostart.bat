@echo off
cd /d "%~dp0"
schtasks /create /tn "AgainERP" /tr "\"%~dp0start.bat\" auto" /sc onlogon /f
if errorlevel 1 (echo Failed. Right-click this file and choose Run as administrator.) else (echo Done. The server will start automatically when you sign in to Windows.)
pause
