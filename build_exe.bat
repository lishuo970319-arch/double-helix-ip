@echo off
chcp 65001 >nul
echo [1/2] Installing dependencies and PyInstaller...
pip install -r requirements.txt pyinstaller

echo [2/2] Building standalone single-file executable...
pyinstaller --noconfirm --clean --onefile --console ^
  --name "双螺旋究极缝合测ip（ip好纯我好爱）" ^
  --icon "icon.ico" ^
  --add-data "index.html;." ^
  --add-data "land110.txt;." ^
  --hidden-import socks ^
  --hidden-import urllib3.contrib.socks ^
  app.py

echo.
echo Build complete! Output: dist\双螺旋究极缝合测ip（ip好纯我好爱）.exe
pause
