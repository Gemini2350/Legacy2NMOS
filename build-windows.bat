@echo off
rem Build Legacy2NMOS.exe for Windows. Requires: pip install pyinstaller
cd /d "%~dp0"
pyinstaller --noconfirm --clean --windowed ^
  --name "Legacy2NMOS" ^
  --add-data "legacy2nmos/ui;legacy2nmos/ui" ^
  app.py
echo Done: dist\Legacy2NMOS\Legacy2NMOS.exe
