@echo off
echo ============================================================
echo   CrackVault v2.0 - Netanix lab - Windows Build
echo ============================================================

echo [1/3] Installing dependencies...
pip install -r requirements.txt
pip install pyinstaller

echo [2/3] Building yescrypt DLL...
where gcc >nul 2>&1
if %errorlevel% equ 0 (
    cd yescrypt_src
    gcc -shared -O2 -o ..\libyescrypt.dll yescrypt_wrapper.c yescrypt-common.c yescrypt-ref.c sha256.c insecure_memzero.c -I. -DSKIP_MEMZERO
    cd ..
    if exist libyescrypt.dll echo   libyescrypt.dll built!
) else (
    echo   [!] gcc not found. Install MinGW-w64 for yescrypt support.
)

echo [3/3] Building CrackVault.exe...
set YLIB=
if exist libyescrypt.dll set YLIB=--add-data "libyescrypt.dll;."
pyinstaller --onefile --windowed --name CrackVault %YLIB% crackvault_v2.py
if exist libyescrypt.dll copy /Y libyescrypt.dll dist\ >nul

echo.
echo   Done! Run: dist\CrackVault.exe
pause
