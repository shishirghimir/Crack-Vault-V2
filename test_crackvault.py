#!/usr/bin/env python3
"""
CrackVault v2.0 — Test Hash Generator
======================================
Run this script to generate test hashes for every supported type.
Then use CrackVault to crack them and verify everything works.

Usage:
    python3 test_crackvault.py

It will create:
    - test_wordlist.txt     (small wordlist with the passwords)
    - test_shadow.txt       (multi-user shadow file)
    - Print all test hashes you can paste into CrackVault
"""

import hashlib
import struct
import os

# ========================================
# Pure Python MD4 for NTLM
# ========================================
def md4_hash(data):
    def _f(x,y,z): return (x&y)|(~x&z)
    def _g(x,y,z): return (x&y)|(x&z)|(y&z)
    def _h(x,y,z): return x^y^z
    def _lr(n,b): return ((n<<b)|(n>>(32-b)))&0xFFFFFFFF
    msg=bytearray(data); ol=len(msg); msg.append(0x80)
    while len(msg)%64!=56: msg.append(0)
    msg+=struct.pack('<Q',ol*8)
    a,b,c,d=0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476
    for i in range(0,len(msg),64):
        X=list(struct.unpack('<16I',msg[i:i+64])); aa,bb,cc,dd=a,b,c,d
        for k,s in [(0,3),(1,7),(2,11),(3,19),(4,3),(5,7),(6,11),(7,19),(8,3),(9,7),(10,11),(11,19),(12,3),(13,7),(14,11),(15,19)]:
            a=_lr((a+_f(b,c,d)+X[k])&0xFFFFFFFF,s); a,b,c,d=d,a,b,c
        for k,s in [(0,3),(4,5),(8,9),(12,13),(1,3),(5,5),(9,9),(13,13),(2,3),(6,5),(10,9),(14,13),(3,3),(7,5),(11,9),(15,13)]:
            a=_lr((a+_g(b,c,d)+X[k]+0x5A827999)&0xFFFFFFFF,s); a,b,c,d=d,a,b,c
        for k,s in [(0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),(1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15)]:
            a=_lr((a+_h(b,c,d)+X[k]+0x6ED9EBA1)&0xFFFFFFFF,s); a,b,c,d=d,a,b,c
        a=(a+aa)&0xFFFFFFFF; b=(b+bb)&0xFFFFFFFF; c=(c+cc)&0xFFFFFFFF; d=(d+dd)&0xFFFFFFFF
    return struct.pack('<4I',a,b,c,d).hex()

# ========================================
# Config
# ========================================
PASSWORD = "test123"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

print()
print("=" * 70)
print("  CrackVault v2.0 — TEST HASH GENERATOR")
print(f"  Password for all hashes: '{PASSWORD}'")
print("=" * 70)

# ========================================
# 1. Create test wordlist
# ========================================
wordlist_path = os.path.join(SCRIPT_DIR, "test_wordlist.txt")
words = [
    "password", "admin", "123456", "test", "hello", "world",
    "test123", "admin123", "password1", "letmein", "welcome",
    "alice123", "bob!", "toor", "root", "monkey", "dragon",
    "master", "qwerty", "login", "abc123", "starwars",
    "iloveyou", "shadow", "sunshine", "princess", "football"
]
with open(wordlist_path, 'w') as f:
    f.write('\n'.join(words))
print(f"\n  Created: {wordlist_path} ({len(words)} words)")

# ========================================
# 2. Hash Crack Tab — Plain Hashes
# ========================================
print(f"\n{'─' * 70}")
print("  HASH CRACK TAB — Copy hash, select algorithm, click START CRACK")
print(f"  Wordlist: {wordlist_path}")
print(f"{'─' * 70}")

tests_hash = [
    ("MD5",      "md5",      hashlib.md5(PASSWORD.encode()).hexdigest()),
    ("SHA-1",    "sha1",     hashlib.sha1(PASSWORD.encode()).hexdigest()),
    ("SHA-256",  "sha256",   hashlib.sha256(PASSWORD.encode()).hexdigest()),
    ("SHA-512",  "sha512",   hashlib.sha512(PASSWORD.encode()).hexdigest()),
    ("SHA3-256", "sha3_256", hashlib.sha3_256(PASSWORD.encode()).hexdigest()),
    ("BLAKE2b",  "blake2b",  hashlib.blake2b(PASSWORD.encode()).hexdigest()),
    ("BLAKE2s",  "blake2s",  hashlib.blake2s(PASSWORD.encode()).hexdigest()),
    ("NTLM",     "ntlm",     md4_hash(PASSWORD.encode('utf-16-le'))),
]

for name, algo, h in tests_hash:
    print(f"\n  {name} (select '{algo}' in Algorithm dropdown):")
    print(f"  {h}")

# ========================================
# 3. Shadow Crack Tab — Crypt Hashes
# ========================================
print(f"\n{'─' * 70}")
print("  SHADOW CRACK TAB — Paste hash in 'Hash / File', Mode: Single Hash")
print(f"  Wordlist: {wordlist_path}")
print(f"{'─' * 70}")

shadow_hashes = []

# MD5-crypt
try:
    from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt
    h = md5_crypt.using(salt='testsalt').hash(PASSWORD)
    print(f"\n  MD5-crypt ($1$):")
    print(f"  {h}")
    shadow_hashes.append(('md5-crypt', h))

    h = sha256_crypt.using(salt='testsalt', rounds=5000).hash(PASSWORD)
    print(f"\n  SHA-256-crypt ($5$):")
    print(f"  {h}")
    shadow_hashes.append(('sha256-crypt', h))

    h = sha512_crypt.using(salt='testsalt', rounds=5000).hash(PASSWORD)
    print(f"\n  SHA-512-crypt ($6$):")
    print(f"  {h}")
    shadow_hashes.append(('sha512-crypt', h))
except ImportError:
    print("\n  [!] passlib not installed. Run: pip install passlib")
    print("      Then re-run this script for $1$, $5$, $6$ test hashes.")

    # Fallback: use crypt module if on Linux
    try:
        import crypt
        h = crypt.crypt(PASSWORD, '$6$testsalt$')
        print(f"\n  SHA-512-crypt ($6$) via crypt module:")
        print(f"  {h}")
        shadow_hashes.append(('sha512-crypt', h))

        h = crypt.crypt(PASSWORD, '$5$testsalt$')
        print(f"\n  SHA-256-crypt ($5$) via crypt module:")
        print(f"  {h}")
        shadow_hashes.append(('sha256-crypt', h))

        h = crypt.crypt(PASSWORD, '$1$testsalt$')
        print(f"\n  MD5-crypt ($1$) via crypt module:")
        print(f"  {h}")
        shadow_hashes.append(('md5-crypt', h))
    except ImportError:
        print("  [!] crypt module also unavailable (Windows?). Install passlib.")

# bcrypt
try:
    import bcrypt
    h = bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()
    print(f"\n  bcrypt ($2b$) — NOTE: cracking is SLOW (~5-20 pwd/sec):")
    print(f"  {h}")
    shadow_hashes.append(('bcrypt', h))
except ImportError:
    print("\n  [!] bcrypt not installed. Run: pip install bcrypt")

# yescrypt (Linux only)
try:
    import crypt
    h = crypt.crypt(PASSWORD, '$y$j9T$testsalt$')
    if h.startswith('$y$'):
        print(f"\n  yescrypt ($y$) — NOTE: cracking is SLOW (~2-10 pwd/sec):")
        print(f"  {h}")
        shadow_hashes.append(('yescrypt', h))
    else:
        print(f"\n  yescrypt: Not supported on this system (needs libxcrypt)")
except (ImportError, Exception):
    print(f"\n  yescrypt: Only available on Linux with libxcrypt")

# ========================================
# 4. Shadow File Test
# ========================================
print(f"\n{'─' * 70}")
print("  SHADOW FILE TEST — Mode: Shadow File, browse to test_shadow.txt")
print(f"  Keywords: alice bob toor")
print(f"{'─' * 70}")

shadow_path = os.path.join(SCRIPT_DIR, "test_shadow.txt")
shadow_lines = []
users = [("alice", "alice123"), ("bob", "bob!"), ("root", "toor")]

try:
    from passlib.hash import sha512_crypt
    for user, pw in users:
        h = sha512_crypt.using(salt='test1234', rounds=5000).hash(pw)
        shadow_lines.append(f"{user}:{h}:19900:0:99999:7:::")
except ImportError:
    try:
        import crypt
        for user, pw in users:
            h = crypt.crypt(pw, '$6$test1234$')
            shadow_lines.append(f"{user}:{h}:19900:0:99999:7:::")
    except ImportError:
        print("  [!] Cannot generate shadow file without passlib or crypt module")

if shadow_lines:
    with open(shadow_path, 'w') as f:
        f.write('\n'.join(shadow_lines))
    print(f"\n  Created: {shadow_path}")
    print(f"  Users & passwords:")
    for user, pw in users:
        print(f"    {user:10s} -> {pw}")
    print(f"\n  Use Keywords: 'alice bob toor' to crack faster!")

# ========================================
# 5. Quick Test Guide
# ========================================
print(f"\n{'=' * 70}")
print("  HOW TO TEST")
print("=" * 70)
print(f"""
  1. Run CrackVault:
     python3 crackvault_v2.py

  2. HASH CRACK TAB (fast hashes):
     - Paste any MD5/SHA/NTLM hash from above
     - Select the matching algorithm
     - Browse to: {wordlist_path}
     - Click START CRACK
     - Should find '{PASSWORD}' in under 1 second

  3. SHADOW CRACK TAB — Single Hash:
     - Set Mode to 'Single Hash'
     - Paste a $1$/$5$/$6$/$2b$ hash from above
     - Browse to: {wordlist_path}
     - Click CRACK SHADOW
     - bcrypt will be slow (~5-20 pwd/sec) — be patient

  4. SHADOW CRACK TAB — Shadow File:
     - Set Mode to 'Shadow File'
     - Browse Hash/File to: {shadow_path}
     - Browse Wordlist to: {wordlist_path}
     - Type Keywords: alice bob toor
     - Click CRACK SHADOW
     - Should crack all 3 users

  5. KEYWORD PRIORITY TEST:
     - Use any hash above
     - Type the password as a keyword (e.g., 'test')
     - It should crack in the FIRST few attempts

  6. HASH GENERATOR TAB:
     - Type any text, click GENERATE
     - Should show all 13 hash types including NTLM

  7. IDENTIFY HASH TAB:
     - Paste any hash, click IDENTIFY
     - Should correctly identify the algorithm
""")
print("=" * 70)
print("  Happy testing!")
print("=" * 70)
