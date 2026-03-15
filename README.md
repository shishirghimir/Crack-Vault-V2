<p align="center">
  <img src="assets/banner.png" alt="CrackVault" width="600"/>
</p>

<h1 align="center">CrackVault v2.0</h1>

<p align="center">
  <b>Advanced Password Cracker for Ethical Hacking & Penetration Testing</b><br>
  <i>Built by Netanix lab</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-00bfff?style=flat-square" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.8%2B-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-00e676?style=flat-square" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License"/>
  <img src="https://img.shields.io/badge/tests-131%20passed-00e676?style=flat-square" alt="Tests"/>
</p>

<p align="center">
  <img src="assets/screenshot.png" alt="CrackVault Screenshot" width="800"/>
</p>

---

## What is CrackVault?

CrackVault is a multi-purpose password cracking tool with a sleek dark-themed GUI. It cracks password hashes, shadow files, and encrypted archives — all from one interface. Built with custom data structures (HashMap, Queue, Trie) and a smart **Keyword Priority System** that tries the most likely passwords first.

**Not just another cracker** — CrackVault's keyword engine generates thousands of intelligent mutations from your hints and tries them before touching the wordlist. This turns hours of brute-forcing into seconds of targeted cracking.

---

## Features

### Hash Cracking
| Algorithm | Speed |
|-----------|-------|
| MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | ~50,000+ pwd/s |
| SHA3-256, SHA3-384, SHA3-512 | ~30,000+ pwd/s |
| BLAKE2b, BLAKE2s | ~40,000+ pwd/s |
| NTLM (Windows) | ~40,000+ pwd/s |

**Attack Modes:** Wordlist, Brute Force (configurable charset and length), Rule-Based (leet speak, case mutations, common suffixes)

### Shadow / Crypt Hash Cracking
| Hash Type | Prefix | Speed |
|-----------|--------|-------|
| yescrypt | `$y$` | ~20-40 pwd/s |
| bcrypt | `$2b$` | ~5-20 pwd/s |
| SHA-512-crypt | `$6$` | ~100-500 pwd/s |
| SHA-256-crypt | `$5$` | ~200-600 pwd/s |
| MD5-crypt | `$1$` | ~5,000+ pwd/s |
| scrypt | `$7$` | ~10-50 pwd/s |

**Modes:** Single Hash or entire Shadow File (auto-parses `/etc/shadow`, cracks all users)

### Encrypted File Cracking
| File Type | Library Required |
|-----------|-----------------|
| ZIP | Built-in |
| RAR | `rarfile` + `unrar` |
| 7-Zip | `py7zr` |
| PDF | `pikepdf` |
| Office (.docx/.xlsx/.pptx) | `msoffcrypto-tool` |
| KeePass (.kdbx) | `pykeepass` |

### Keyword Priority System
The killer feature. Enter keywords like `admin`, `forensic`, `defensive` and CrackVault:

1. **Generates 9,000+ mutations per keyword** — leet speak (`@dm1n`, `f0r3n$1c`), case variants, all suffixes 01-99, years (2020-2026), symbols, **trailing spaces**, reverse, doubled
2. **Multi-keyword combos** — `adminroot`, `Admin_Root`, `ADMIN.ROOT`, etc.
3. **Username-derived guesses** — auto-generates passwords from the target username
4. **Wordlist grep** — scans the wordlist and bumps keyword-matching words to the front, plus adds space variants

**Result:** On rockyou.txt (14M words), a password like `forensic07` gets found in ~600 attempts instead of millions.

### Utilities
- **Hash Generator** — generates all 13 hash types (incl. NTLM) from any text
- **Hash Identifier** — paste any hash, get the algorithm (supports crypt-style `$y$`, `$2b$`, `$6$`, etc.)
- **Session History** — tracks all cracking attempts with timing and speed stats

---

## Quick Start

### Option A: Run with Python
```bash
git clone https://github.com/YOUR_USERNAME/CrackVault.git
cd CrackVault
pip install -r requirements.txt
python crackvault_v2.py
```

### Option B: Download Standalone EXE
Download from [Releases](../../releases) — no Python needed. Just run `CrackVault_v2.exe`.

> **Note:** Keep `libyescrypt.dll` (Windows) or `libyescrypt.so` (Linux) in the same folder as the EXE for yescrypt support.

---

## Yescrypt Support

CrackVault ships with pre-built yescrypt libraries for both Windows and Linux. The `libyescrypt.dll` / `.so` is bundled with the EXE and loads automatically.

If you need to rebuild from source:

**Windows (MinGW):**
```cmd
cd yescrypt_src
gcc -shared -O2 -o ..\libyescrypt.dll yescrypt_wrapper.c yescrypt-common.c yescrypt-ref.c sha256.c insecure_memzero.c -I. -DSKIP_MEMZERO
```

**Linux:**
```bash
cd yescrypt_src
gcc -shared -fPIC -O2 -o ../libyescrypt.so yescrypt_wrapper.c yescrypt-common.c yescrypt-opt.c sha256.c insecure_memzero.c -I. -DSKIP_MEMZERO
```

---

## Building the EXE

### Windows
```batch
build_exe_windows.bat
```
Output: `dist\CrackVault_v2.exe`

### Linux
```bash
chmod +x build_exe_linux.sh
./build_exe_linux.sh
```
Output: `dist/CrackVault_v2`

---

## Unit Tests

```bash
python test_crackvault_unit.py
```

```
════════════════════════════════════════════════════════════
  CRACKVAULT v2.0 — UNIT TEST RESULTS
  Netanix lab
════════════════════════════════════════════════════════════
  Total:  131
  Passed: 131
  Failed: 0

  ★ ALL TESTS PASSED ★
════════════════════════════════════════════════════════════
```

**Test Coverage:** Data Structures, Hash Engine, NTLM, Shadow Parser, Hash Identifier, Keyword Filter (mutations, spaces, combos), all Attack Modules, Crypt Crackers (MD5/SHA/bcrypt/yescrypt), File Crackers, Hash Generator, Session Log, Branding, Wordlist Loader.

---

## Project Structure

```
CrackVault/
├── crackvault_v2.py              # Main application (2,194 lines, 26 classes)
├── crackvault.ico                # Application icon
├── libyescrypt.dll               # Pre-built Windows yescrypt library
├── libyescrypt.so                # Pre-built Linux yescrypt library
├── requirements.txt              # Python dependencies
├── test_crackvault_unit.py       # 131 unit tests
├── test_crackvault.py            # Test hash generator
├── build_exe_windows.bat         # Windows EXE builder
├── build_exe_linux.sh            # Linux binary builder
├── build_scripts/
│   ├── build_yescrypt_windows.bat
│   └── build_yescrypt_linux.sh
└── yescrypt_src/                 # Yescrypt C source (openwall)
    ├── yescrypt_wrapper.c        # CrackVault bridge
    ├── yescrypt.h
    ├── yescrypt-common.c
    ├── yescrypt-opt.c / -ref.c
    ├── sha256.c / sha256.h
    └── insecure_memzero.c / .h
```

---

## Architecture

CrackVault is built from scratch with **custom data structures** for educational value:

- **HashMap** — open-chaining hash table with djb2 hashing and dynamic resizing at 75% load
- **Queue** — singly-linked list FIFO queue for managing word candidates  
- **Trie** — prefix tree for keyword matching and search

The codebase follows a layered architecture:
```
┌─────────────────────────┐
│     Tkinter GUI         │  Dark-themed, tabbed interface
├─────────────────────────┤
│    Attack Modules       │  Wordlist, BruteForce, RuleBased, NTLM
├─────────────────────────┤
│  Keyword Priority Filter│  Trie-based mutation engine
├─────────────────────────┤
│  Hash / Crypt Engines   │  hashlib, crypt, bcrypt, passlib, yescrypt (ctypes)
├─────────────────────────┤
│  Custom Data Structures │  HashMap, Queue, Trie
└─────────────────────────┘
```

---

## Dependencies

### Required
```
bcrypt>=4.0.0
passlib>=1.7.4
```

### Optional (for file crackers)
```bash
pip install pikepdf        # PDF
pip install rarfile         # RAR (+ unrar binary)
pip install py7zr           # 7-Zip
pip install msoffcrypto-tool # Office
pip install pykeepass       # KeePass
```

---

## Usage Examples

### Crack an MD5 hash
1. **Hash Crack** tab → paste hash → select `md5` → browse wordlist → **START CRACK**

### Crack a yescrypt shadow hash
1. **Shadow Crack** tab → Mode: `Single Hash`
2. Paste: `$y$j9T$salt$hash...`
3. Keywords: `defensive` (or any hints about the password)
4. Browse wordlist → **CRACK SHADOW**

### Crack an entire /etc/shadow file
1. **Shadow Crack** tab → Mode: `Shadow File`
2. Browse to the shadow file
3. Target Users: `root, admin` (optional)
4. Keywords: `password admin root`
5. **CRACK SHADOW** → cracks all users

### Crack a password-protected ZIP
1. **File Crack** tab → Type: `ZIP`
2. Browse target file and wordlist
3. Keywords: any hints → **CRACK FILE**

---

## Disclaimer

> **This tool is for authorized security testing and educational purposes only.**
> Only use CrackVault on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal under the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and similar laws worldwide.

---

## Credits

**Netanix lab** — Design, Development, Testing

Built with:
- [Python](https://python.org) + [Tkinter](https://docs.python.org/3/library/tkinter.html)
- [openwall/yescrypt](https://github.com/openwall/yescrypt) — yescrypt reference implementation
- [passlib](https://passlib.readthedocs.io/) — password hashing library
- [bcrypt](https://github.com/pyca/bcrypt) — bcrypt implementation

---

<p align="center">
  <b>CrackVault v2.0</b> — <i>Netanix lab</i><br>
  Star this repo if you find it useful!
</p>
