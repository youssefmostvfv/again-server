@echo off
title Again ERP Server
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo Node.js is not installed on this computer.
  echo Download the LTS version from https://nodejs.org , install it, then run this file again.
  echo.
  pause
  exit /b 1
)
if not "%1"=="auto" start "" /min cmd /c "timeout /t 3 >nul & start http://localhost:3000"
:loop
echo Starting Again ERP server... keep this window open.
node server.js
if errorlevel 1 (
  echo.
  echo The server stopped unexpectedly. Restarting in 5 seconds... ^(close this window to stop^)
  timeout /t 5 >nul
  goto loop
)
echo.
echo The server stopped. Press any key to close this window.
pause >nul
