#!/usr/bin/env python3
"""
CrackVault v2.0 — Unit Tests
=============================
Netanix lab

Run: python test_crackvault_unit.py

Tests all modules:
  - Custom Data Structures (HashMap, Queue, Trie)
  - Hash Engine (MD5, SHA, BLAKE2)
  - NTLM Engine (pure Python MD4)
  - Shadow Parser (all crypt formats)
  - Hash Identifier
  - Keyword Filter (mutations, priority, spaces)
  - Attack Modules (Wordlist, BruteForce, RuleBased, NTLM)
  - Crypt Crackers (MD5-crypt, SHA-crypt, bcrypt)
  - Yescrypt (if libyescrypt available)
  - File Crackers (ZIP)
  - Hash Generator
  - Session Log
"""

import hashlib
import os
import sys
import time
import zipfile
import tempfile
import shutil

# ============================================================
# Import CrackVault modules (non-GUI)
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CRACKVAULT_PATH = os.path.join(SCRIPT_DIR, 'crackvault_v2.py')

if not os.path.exists(CRACKVAULT_PATH):
    print(f"[ERROR] crackvault_v2.py not found in {SCRIPT_DIR}")
    sys.exit(1)

with open(CRACKVAULT_PATH, 'r') as f:
    source = f.read()

code = source.split("if __name__")[0]
code = code.replace("from tkinter import ttk, filedialog, messagebox, scrolledtext", "pass")
code = code.replace("HAS_TK = True", "HAS_TK = False")
exec(code, globals())


# ============================================================
# Test Framework
# ============================================================

class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []
        self.section = ""

    def section_start(self, name):
        self.section = name
        print(f"\n{'─' * 60}")
        print(f"  {name}")
        print(f"{'─' * 60}")

    def test(self, name, condition, detail=""):
        if condition:
            self.passed += 1
            print(f"  ✓ {name}")
        else:
            self.failed += 1
            msg = f"  ✗ {name}" + (f" — {detail}" if detail else "")
            print(msg)
            self.errors.append(f"[{self.section}] {name}: {detail}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'═' * 60}")
        print(f"  CRACKVAULT v2.0 — UNIT TEST RESULTS")
        print(f"  Netanix lab")
        print(f"{'═' * 60}")
        print(f"  Total:  {total}")
        print(f"  Passed: {self.passed}")
        print(f"  Failed: {self.failed}")
        if self.failed == 0:
            print(f"\n  ★ ALL TESTS PASSED ★")
        else:
            print(f"\n  Failures:")
            for e in self.errors:
                print(f"    • {e}")
        print(f"{'═' * 60}")
        return self.failed == 0


T = TestRunner()

# ============================================================
# Create temp wordlist for testing
# ============================================================

TEMP_DIR = tempfile.mkdtemp()
WL_PATH = os.path.join(TEMP_DIR, 'test_wordlist.txt')
WORDS = ['password', 'admin', 'test123', 'hello', 'world', 'hacker',
         'defensive', 'forensic07', 'root', 'toor', 'monkey', 'dragon',
         'master', 'letmein', 'qwerty', 'abc123', 'shadow', 'princess']
with open(WL_PATH, 'w') as f:
    f.write('\n'.join(WORDS))


# ============================================================
# 1. CUSTOM DATA STRUCTURES
# ============================================================

T.section_start("Custom Data Structures")

# HashMap
hm = HashMap()
hm.put('a', 1)
hm.put('b', 2)
hm.put('c', 3)
T.test("HashMap put/get", hm.get('a') == 1 and hm.get('b') == 2 and hm.get('c') == 3)
T.test("HashMap contains", hm.contains('a') and not hm.contains('z'))
T.test("HashMap size", hm.size() == 3)
hm.put('a', 99)
T.test("HashMap overwrite", hm.get('a') == 99)
hm.remove('b')
T.test("HashMap remove", not hm.contains('b') and hm.size() == 2)
T.test("HashMap keys", set(hm.keys()) == {'a', 'c'})
T.test("HashMap default", hm.get('missing', 'default') == 'default')

# HashMap resize
hm2 = HashMap(capacity=4)
for i in range(20):
    hm2.put(f'key{i}', i)
T.test("HashMap resize", hm2.size() == 20 and hm2.get('key19') == 19)

# Queue
q = Queue()
q.enqueue('a')
q.enqueue('b')
q.enqueue('c')
T.test("Queue size", q.size() == 3)
T.test("Queue peek", q.peek() == 'a')
T.test("Queue dequeue", q.dequeue() == 'a' and q.dequeue() == 'b')
T.test("Queue to_list", q.to_list() == ['c'])
T.test("Queue is_empty", not q.is_empty())
q.dequeue()
T.test("Queue empty after dequeue", q.is_empty())
T.test("Queue dequeue empty", q.dequeue() is None)

# Trie
tr = Trie()
tr.insert("hello")
tr.insert("help")
tr.insert("world")
T.test("Trie search_prefix 'hel'", set(tr.search_prefix('hel')) == {'hello', 'help'})
T.test("Trie search_prefix 'wor'", tr.search_prefix('wor') == ['world'])
T.test("Trie search_prefix empty", len(tr.search_prefix('xyz')) == 0)


# ============================================================
# 2. HASH ENGINE
# ============================================================

T.section_start("Hash Engine")

T.test("MD5 compute", HashEngine.compute('password', 'md5') == '5f4dcc3b5aa765d61d8327deb882cf99')
T.test("SHA1 compute", HashEngine.compute('hello', 'sha1') == 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d')
T.test("SHA256 compute", HashEngine.compute('test', 'sha256') == '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
T.test("SHA512 compute", len(HashEngine.compute('test', 'sha512')) == 128)
T.test("BLAKE2b compute", len(HashEngine.compute('test', 'blake2b')) == 128)
T.test("BLAKE2s compute", len(HashEngine.compute('test', 'blake2s')) == 64)
T.test("Invalid algo returns None", HashEngine.compute('test', 'fake_algo') is None)
T.test("Supported algorithms >= 12", len(HashEngine.supported_algorithms()) >= 12)


# ============================================================
# 3. NTLM ENGINE
# ============================================================

T.section_start("NTLM Engine")

T.test("NTLM empty string", NTLMEngine.compute_ntlm('') == '31d6cfe0d16ae931b73c59d7e0c089c0')
T.test("NTLM 'password'", NTLMEngine.compute_ntlm('password') == '8846f7eaee8fb117ad06bdd830b7586c')
T.test("NTLM 'test'", NTLMEngine.compute_ntlm('test') == '0cb6948805f797bf2a82807973b89537')
T.test("is_ntlm valid", NTLMEngine.is_ntlm('8846f7eaee8fb117ad06bdd830b7586c'))
T.test("is_ntlm invalid", not NTLMEngine.is_ntlm('not-a-hash'))
T.test("is_ntlm wrong length", not NTLMEngine.is_ntlm('abcd1234'))


# ============================================================
# 4. SHADOW PARSER
# ============================================================

T.section_start("Shadow Parser")

# SHA-512-crypt
e = ShadowParser.parse_shadow_line('root:$6$salt$hash:19000:0:99999:7:::')
T.test("SHA512-crypt parse user", e.username == 'root')
T.test("SHA512-crypt parse type", e.hash_type_name == 'SHA-512-crypt')
T.test("SHA512-crypt parse hash_type", e.hash_type == '6')

# yescrypt
e = ShadowParser.parse_shadow_line('user:$y$j9T$salt$hash:19500:::')
T.test("yescrypt parse user", e.username == 'user')
T.test("yescrypt parse type", e.hash_type_name == 'yescrypt')

# bcrypt
e = ShadowParser.parse_shadow_line('admin:$2b$12$abcdefghijklmnopqrstuuhash:19500:::')
T.test("bcrypt parse user", e.username == 'admin')
T.test("bcrypt parse type", e.hash_type_name == 'bcrypt')

# MD5-crypt
e = ShadowParser.parse_shadow_line('$1$salt$hash')
T.test("MD5-crypt no username", e.username == '' and e.hash_type_name == 'MD5-crypt')

# SHA-256-crypt
e = ShadowParser.parse_shadow_line('$5$salt$hash')
T.test("SHA256-crypt parse", e.hash_type_name == 'SHA-256-crypt')

# SHA-512-crypt with rounds
e = ShadowParser.parse_shadow_line('$6$rounds=5000$salt$hash')
T.test("SHA512-crypt with rounds", e.hash_type_name == 'SHA-512-crypt' and 'rounds=5000' in e.salt)

# Empty/invalid lines
T.test("Empty line returns None", ShadowParser.parse_shadow_line('') is None)
T.test("Comment line returns None", ShadowParser.parse_shadow_line('# comment') is None)

# Shadow file parsing
shadow_path = os.path.join(TEMP_DIR, 'test_shadow.txt')
with open(shadow_path, 'w') as f:
    f.write('alice:$6$salt$hash:19000:::\nbob:$6$salt2$hash2:19000:::\n# comment\n')
entries = ShadowParser.parse_shadow_file(shadow_path)
T.test("Shadow file parse count", len(entries) == 2, f"got {len(entries)}")
T.test("Shadow file users", set(e.username for e in entries) == {'alice', 'bob'})

# Hash type identification
T.test("Identify bcrypt", 'bcrypt' in ShadowParser.identify_hash_type('$2b$12$abcdef'))
T.test("Identify yescrypt", 'yescrypt ($y$)' in ShadowParser.identify_hash_type('$y$j9T$salt$hash'))
T.test("Identify SHA512-crypt", 'SHA-512-crypt ($6$)' in ShadowParser.identify_hash_type('$6$salt$hash'))
T.test("Identify non-crypt", ShadowParser.identify_hash_type('abcdef123') == [])


# ============================================================
# 5. HASH IDENTIFIER (integrated)
# ============================================================

T.section_start("Hash Identifier")

T.test("Identify MD5 hash", 'md5' in HashEngine.identify_hash('5f4dcc3b5aa765d61d8327deb882cf99'))
T.test("Identify NTLM in 32-char hex", 'ntlm' in HashEngine.identify_hash('5f4dcc3b5aa765d61d8327deb882cf99'))
T.test("Identify SHA1 hash", 'sha1' in HashEngine.identify_hash('a' * 40))
T.test("Identify SHA256 hash", 'sha256' in HashEngine.identify_hash('a' * 64))
T.test("Identify crypt hash", len(HashEngine.identify_hash('$6$salt$hash')) > 0)


# ============================================================
# 6. KEYWORD FILTER
# ============================================================

T.section_start("Keyword Filter")

kf = KeywordFilter()
kf.set_keywords('admin, root')
T.test("Keywords parsed", kf.keywords == ['admin', 'root'])

# Mutations
pq, rq = kf.filter_wordlist([])
mutations = pq.to_list()
T.test("Mutations generated", len(mutations) > 1000)
T.test("Mutation: admin", 'admin' in mutations)
T.test("Mutation: Admin", 'Admin' in mutations)
T.test("Mutation: ADMIN", 'ADMIN' in mutations)
T.test("Mutation: admin123", 'admin123' in mutations)
T.test("Mutation: admin!", 'admin!' in mutations)
T.test("Mutation: @dm1n (leet)", '@dm1n' in mutations)
T.test("Mutation: admin07", 'admin07' in mutations)
T.test("Mutation: admin (space)", 'admin ' in mutations)
T.test("Mutation: adminroot (combo)", 'adminroot' in mutations)
T.test("Mutation: AdminRoot (combo)", 'AdminRoot' in mutations)

# Priority filtering
words = ['hello', 'admin123', 'rootpass', 'world', 'foobar']
pq2, rq2 = kf.filter_wordlist(words)
pl2 = pq2.to_list()
rl2 = rq2.to_list()
T.test("Priority contains admin123", 'admin123' in pl2)
T.test("Priority contains rootpass", 'rootpass' in pl2)
T.test("Remaining has hello", 'hello' in rl2)
T.test("Remaining has foobar", 'foobar' in rl2)

# Space variants from wordlist grep
kf3 = KeywordFilter()
kf3.set_keywords('defensive')
pq3, rq3 = kf3.filter_wordlist(['defensive', 'hello'])
pl3 = pq3.to_list()
T.test("Wordlist grep adds 'defensive '", 'defensive ' in pl3)
T.test("Wordlist grep adds ' defensive'", ' defensive' in pl3)

# Single keyword
kf4 = KeywordFilter()
kf4.set_keywords('forensic')
pq4, _ = kf4.filter_wordlist([])
pl4 = pq4.to_list()
T.test("forensic07 in mutations", 'forensic07' in pl4)
T.test("Forensic07 in mutations", 'Forensic07' in pl4)
T.test("forensic (space) in mutations", 'forensic ' in pl4)


# ============================================================
# 7. ATTACK MODULES
# ============================================================

T.section_start("Attack Modules — Wordlist")

target_md5 = hashlib.md5(b'test123').hexdigest()
r = WordlistAttack().crack_hash(target_md5, 'md5', WL_PATH)
T.test("Wordlist MD5 crack", r.found and r.password == 'test123')
T.test("Wordlist has attempts", r.attempts > 0)
T.test("Wordlist has speed", r.speed > 0)
T.test("Wordlist method name", r.method == 'Wordlist Attack')

# With keywords
kf5 = KeywordFilter()
kf5.set_keywords('test')
r2 = WordlistAttack().crack_hash(target_md5, 'md5', WL_PATH, kf5)
T.test("Wordlist + keywords crack", r2.found and r2.password == 'test123')

# Not found
target_bad = hashlib.md5(b'nonexistent_pw_xyz').hexdigest()
r3 = WordlistAttack().crack_hash(target_bad, 'md5', WL_PATH)
T.test("Wordlist not found", not r3.found and r3.password is None)

# Stop
wa = WordlistAttack()
wa.stopped = True
r4 = wa.crack_hash(target_md5, 'md5', WL_PATH)
T.test("Wordlist stop works", not r4.found)


T.section_start("Attack Modules — Brute Force")

target_bf = hashlib.md5(b'ab').hexdigest()
r = BruteForceAttack().crack_hash(target_bf, 'md5', 'abcdefghijklmnopqrstuvwxyz', 1, 3)
T.test("BruteForce crack 'ab'", r.found and r.password == 'ab')
T.test("BruteForce attempts", r.attempts == 28)  # 26 + 2 (a*26 + ab is 28th)

target_bf2 = hashlib.md5(b'z').hexdigest()
r2 = BruteForceAttack().crack_hash(target_bf2, 'md5', 'abcdefghijklmnopqrstuvwxyz', 1, 1)
T.test("BruteForce single char", r2.found and r2.password == 'z')


T.section_start("Attack Modules — Rule-Based")

target_rule = hashlib.md5(b'Password123').hexdigest()
r = RuleBasedAttack().crack_hash(target_rule, 'md5', WL_PATH)
T.test("RuleBased crack Password123", r.found and r.password == 'Password123')

target_rule2 = hashlib.md5(b'HELLO').hexdigest()
r2 = RuleBasedAttack().crack_hash(target_rule2, 'md5', WL_PATH)
T.test("RuleBased crack HELLO (uppercase)", r2.found and r2.password == 'HELLO')

target_rule3 = hashlib.md5(b'h3110').hexdigest()
r3 = RuleBasedAttack().crack_hash(target_rule3, 'md5', WL_PATH)
T.test("RuleBased crack h3110 (leet)", r3.found and r3.password == 'h3110')


T.section_start("Attack Modules — NTLM")

target_ntlm = NTLMEngine.compute_ntlm('dragon')
r = NTLMCracker().crack_hash(target_ntlm, WL_PATH)
T.test("NTLM crack 'dragon'", r.found and r.password == 'dragon')
T.test("NTLM method name", r.method == 'NTLM Crack')

target_ntlm2 = NTLMEngine.compute_ntlm('admin')
kf6 = KeywordFilter()
kf6.set_keywords('admin')
r2 = NTLMCracker().crack_hash(target_ntlm2, WL_PATH, kf6)
T.test("NTLM + keywords crack", r2.found and r2.password == 'admin')


# ============================================================
# 8. CRYPT CRACKERS
# ============================================================

T.section_start("Crypt Crackers")

try:
    from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt
    HAS_PASSLIB = True
except ImportError:
    HAS_PASSLIB = False
    print("  [SKIP] passlib not installed")

if HAS_PASSLIB:
    # MD5-crypt
    h = md5_crypt.using(salt='test').hash('test123')
    entry = ShadowParser.parse_shadow_line(h)
    r = CryptCracker(log_callback=lambda m: None).crack(entry, WL_PATH)
    T.test("MD5-crypt crack", r.found and r.password == 'test123')

    # SHA-256-crypt
    h = sha256_crypt.using(salt='test', rounds=5000).hash('hello')
    entry = ShadowParser.parse_shadow_line(h)
    r = CryptCracker(log_callback=lambda m: None).crack(entry, WL_PATH)
    T.test("SHA256-crypt crack", r.found and r.password == 'hello')

    # SHA-512-crypt
    h = sha512_crypt.using(salt='test', rounds=5000).hash('toor')
    entry = ShadowParser.parse_shadow_line(h)
    r = CryptCracker(log_callback=lambda m: None).crack(entry, WL_PATH)
    T.test("SHA512-crypt crack", r.found and r.password == 'toor')

    # SHA-512-crypt with keywords
    h = sha512_crypt.using(salt='ts', rounds=5000).hash('dragon')
    entry = ShadowParser.parse_shadow_line(h)
    kf7 = KeywordFilter()
    kf7.set_keywords('dragon')
    r = CryptCracker(log_callback=lambda m: None).crack(entry, WL_PATH, kf7)
    T.test("SHA512-crypt + keywords", r.found and r.password == 'dragon')

    # Username-based guessing
    h = sha512_crypt.using(salt='ts', rounds=5000).hash('admin123')
    entry = ShadowParser.parse_shadow_line(f'admin:{h}:20000:::')
    r = CryptCracker(log_callback=lambda m: None).crack(entry, WL_PATH)
    T.test("Username guess (admin→admin123)", r.found and r.password == 'admin123')

    # Shadow file cracker
    shadow_test = os.path.join(TEMP_DIR, 'crack_shadow.txt')
    lines = []
    for u, pw in [('alice', 'hello'), ('bob', 'dragon')]:
        h = sha512_crypt.using(salt='ts', rounds=5000).hash(pw)
        lines.append(f'{u}:{h}:20000:::')
    with open(shadow_test, 'w') as f:
        f.write('\n'.join(lines))
    results = ShadowFileCracker(log_callback=lambda m: None).crack_file(shadow_test, WL_PATH)
    fc = sum(1 for r in results if r.found)
    T.test("Shadow file multi-user (2/2)", fc == 2)

try:
    import bcrypt as bc
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

if HAS_BCRYPT:
    h = bc.hashpw(b'monkey', bc.gensalt(rounds=4)).decode()
    entry = ShadowParser.parse_shadow_line(h)
    r = CryptCracker(log_callback=lambda m: None).crack(entry, WL_PATH)
    T.test("bcrypt crack", r.found and r.password == 'monkey')


# ============================================================
# 9. YESCRYPT (if libyescrypt available)
# ============================================================

T.section_start("Yescrypt (bundled library)")

ylib = _load_yescrypt_lib()
if ylib:
    T.test("libyescrypt loaded", True)

    # Generate and verify
    test_h = ylib.yescrypt_check(b'test123', b'$y$j9T$saltsalt$')
    T.test("yescrypt hash generation", test_h is not None and test_h.startswith(b'$y$'))

    v = ylib.yescrypt_verify(b'test123', test_h)
    T.test("yescrypt verify correct", v == 1)

    v2 = ylib.yescrypt_verify(b'wrong', test_h)
    T.test("yescrypt verify wrong", v2 == 0)

    # Crack via CryptCracker
    entry = ShadowParser.parse_shadow_line(f'user:{test_h.decode()}:20000:::')
    r = CryptCracker(log_callback=lambda m: None).crack(entry, WL_PATH)
    T.test("Yescrypt CryptCracker crack", r.found and r.password == 'test123')

    # Crack with space password
    h_space = ylib.yescrypt_check(b'defensive ', b'$y$j9T$saltsalt$')
    entry2 = ShadowParser.parse_shadow_line(f'user:{h_space.decode()}:20000:::')
    kf8 = KeywordFilter()
    kf8.set_keywords('defensive')
    r2 = CryptCracker(log_callback=lambda m: None).crack(entry2, WL_PATH, kf8)
    T.test("Yescrypt crack 'defensive ' (space)", r2.found and r2.password == 'defensive ')

    # Crack with keywords
    h_kw = ylib.yescrypt_check(b'forensic07', b'$y$j9T$saltsalt$')
    entry3 = ShadowParser.parse_shadow_line(f'user:{h_kw.decode()}:20000:::')
    kf9 = KeywordFilter()
    kf9.set_keywords('forensic')
    r3 = CryptCracker(log_callback=lambda m: None).crack(entry3, WL_PATH, kf9)
    T.test("Yescrypt crack forensic07 + keywords", r3.found and r3.password == 'forensic07')
else:
    T.test("libyescrypt loaded", False, "DLL/SO not found — place libyescrypt next to crackvault_v2.py")
    print("  [SKIP] Yescrypt tests skipped — library not found")


# ============================================================
# 10. FILE CRACKERS — ZIP
# ============================================================

T.section_start("File Crackers — ZIP")

# Create a password-protected ZIP for testing
zip_path = os.path.join(TEMP_DIR, 'test.zip')
zip_content = os.path.join(TEMP_DIR, 'secret.txt')
with open(zip_content, 'w') as f:
    f.write('secret data')

# Python can't create password-protected ZIPs natively
# But we can test the cracker initializes and handles errors
zc = ZipCracker(log_callback=lambda m: None)
T.test("ZipCracker init", zc is not None)
T.test("ZipCracker stop", hasattr(zc, 'stop'))

# Test with invalid file
r = zc.crack('/nonexistent/file.zip', WL_PATH)
T.test("ZipCracker invalid file", 'Error' in r.method)

# Test with non-zip file
bad_zip = os.path.join(TEMP_DIR, 'bad.zip')
with open(bad_zip, 'w') as f:
    f.write('not a zip')
r2 = ZipCracker(log_callback=lambda m: None).crack(bad_zip, WL_PATH)
T.test("ZipCracker bad zip", 'Error' in r2.method)

# Test missing wordlist
r3 = ZipCracker(log_callback=lambda m: None).crack(bad_zip, '/nonexistent/wordlist.txt')
T.test("ZipCracker missing wordlist", 'Error' in r3.method)


# ============================================================
# 11. HASH GENERATOR
# ============================================================

T.section_start("Hash Generator")

results = HashGenerator.generate_all('hello')
T.test("Generator produces 13+ types", results.size() >= 13)
T.test("Generator has MD5", results.get('md5') == hashlib.md5(b'hello').hexdigest())
T.test("Generator has SHA256", results.get('sha256') == hashlib.sha256(b'hello').hexdigest())
T.test("Generator has NTLM", results.get('ntlm') == NTLMEngine.compute_ntlm('hello'))
T.test("Generator has BLAKE2b", results.get('blake2b') is not None)

single = HashGenerator.generate('test', 'sha1')
T.test("Generator single algo", single == hashlib.sha1(b'test').hexdigest())


# ============================================================
# 12. SESSION LOG
# ============================================================

T.section_start("Session Log")

log = SessionLog()
T.test("Log starts empty", len(log.get_all()) == 0)

r = AttackResult()
r.found = True
r.password = 'test123'
r.attempts = 42
r.elapsed = 1.5
r.speed = 28.0
r.method = 'Test'
log.add(r)
T.test("Log add entry", len(log.get_all()) == 1)

entry = log.get_all()[0]
T.test("Log entry method", entry['method'] == 'Test')
T.test("Log entry found", entry['found'] == True)
T.test("Log entry password", entry['password'] == 'test123')
T.test("Log entry attempts", entry['attempts'] == 42)

log.add(r)
T.test("Log multiple entries", len(log.get_all()) == 2)

log.clear()
T.test("Log clear", len(log.get_all()) == 0)


# ============================================================
# 13. BRANDING
# ============================================================

T.section_start("Branding")

T.test("Netanix lab in source", 'Netanix lab' in source)
T.test("CrackVault v2.0 in source", 'CrackVault v2.0' in source or 'v2.0' in source)


# ============================================================
# 14. WORDLIST LOADER
# ============================================================

T.section_start("Wordlist Loader")

# Test space preservation
space_wl = os.path.join(TEMP_DIR, 'space_wl.txt')
with open(space_wl, 'w') as f:
    f.write('hello \nworld\ntest \nfoo\n')
words = _load_wordlist(space_wl)
T.test("Preserves trailing space", 'hello ' in words)
T.test("Normal word preserved", 'world' in words)
T.test("Preserves trailing space 2", 'test ' in words)

# Test error handling
try:
    _load_wordlist('/nonexistent/path.txt')
    T.test("Missing wordlist raises error", False)
except FileNotFoundError:
    T.test("Missing wordlist raises error", True)


# ============================================================
# CLEANUP & SUMMARY
# ============================================================

shutil.rmtree(TEMP_DIR, ignore_errors=True)
success = T.summary()
sys.exit(0 if success else 1)
