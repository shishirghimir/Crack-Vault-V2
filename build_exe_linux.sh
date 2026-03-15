#!/bin/bash
echo "============================================================"
echo "  CrackVault v2.0 - Netanix lab - Linux Build"
echo "============================================================"

echo "[1/3] Installing dependencies..."
pip install -r requirements.txt --break-system-packages 2>/dev/null || pip install -r requirements.txt
pip install pyinstaller --break-system-packages 2>/dev/null || pip install pyinstaller

echo "[2/3] Building yescrypt library..."
if command -v gcc &>/dev/null; then
    cd yescrypt_src
    gcc -shared -fPIC -O2 -o ../libyescrypt.so yescrypt_wrapper.c yescrypt-common.c yescrypt-opt.c sha256.c insecure_memzero.c -I. -DSKIP_MEMZERO 2>/dev/null || \
    gcc -shared -fPIC -O2 -o ../libyescrypt.so yescrypt_wrapper.c yescrypt-common.c yescrypt-ref.c sha256.c insecure_memzero.c -I. -DSKIP_MEMZERO
    cd ..
    [ -f libyescrypt.so ] && echo "  libyescrypt.so built!"
else
    echo "  [!] gcc not found. Install: sudo apt install gcc"
fi

echo "[3/3] Building executable..."
YLIB=""; [ -f libyescrypt.so ] && YLIB="--add-data libyescrypt.so:."
pyinstaller --onefile --name CrackVault $YLIB crackvault_v2.py
[ -f libyescrypt.so ] && cp libyescrypt.so dist/
chmod +x dist/CrackVault 2>/dev/null

echo ""
echo "  Done! Run: ./dist/CrackVault"
