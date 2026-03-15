import hashlib
import threading
import time
import os
import sys
import itertools
import string
import zipfile
import struct
import re
import base64
import tempfile
import shutil
import io

import ctypes
import ctypes.util

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    HAS_TK = True
except ImportError:
    HAS_TK = False


# =============================================================================
# YESCRYPT LIBRARY LOADER (bundled libyescrypt.so / .dll)
# =============================================================================

_yescrypt_lib_cache = None
_yescrypt_lib_searched = False

def _load_yescrypt_lib():
    """Load bundled libyescrypt shared library. Returns ctypes lib or None."""
    global _yescrypt_lib_cache, _yescrypt_lib_searched
    if _yescrypt_lib_searched:
        return _yescrypt_lib_cache
    _yescrypt_lib_searched = True

    # Build search directories list
    search_dirs = []

    # PyInstaller bundled: files extracted to _MEIPASS temp dir
    if hasattr(sys, '_MEIPASS'):
        search_dirs.append(sys._MEIPASS)

    # Script directory
    try:
        search_dirs.append(os.path.dirname(os.path.abspath(__file__)))
    except Exception:
        pass

    # Current working directory
    search_dirs.append(os.getcwd())

    # EXE directory (for frozen apps)
    if getattr(sys, 'frozen', False):
        search_dirs.append(os.path.dirname(sys.executable))

    # System paths
    if sys.platform != 'win32':
        search_dirs.extend(['/usr/local/lib', '/usr/lib', '/usr/lib64'])

    # Library names per platform
    if sys.platform == 'win32':
        names = ['libyescrypt.dll', 'yescrypt.dll']
    else:
        names = ['libyescrypt.so', 'libyescrypt.so.1']

    for d in search_dirs:
        for name in names:
            path = os.path.join(d, name)
            if os.path.exists(path):
                try:
                    lib = ctypes.CDLL(path)
                    lib.yescrypt_verify.restype = ctypes.c_int
                    lib.yescrypt_verify.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                    lib.yescrypt_check.restype = ctypes.c_char_p
                    lib.yescrypt_check.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                    test = lib.yescrypt_check(b'test', b'$y$j9T$salt$')
                    if test and test.startswith(b'$y$'):
                        _yescrypt_lib_cache = lib
                        return lib
                except Exception:
                    continue

    return None


# =============================================================================
# CUSTOM DATA STRUCTURES
# =============================================================================

class Node:
    __slots__ = ('key', 'value', 'next')
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.next = None


class HashMap:
    def __init__(self, capacity=256):
        self._capacity = capacity
        self._size = 0
        self._buckets = [None] * capacity

    def _hash(self, key):
        h = 5381
        for ch in str(key):
            h = ((h << 5) + h + ord(ch)) & 0xFFFFFFFF
        return h % self._capacity

    def put(self, key, value):
        idx = self._hash(key)
        node = self._buckets[idx]
        while node:
            if node.key == key:
                node.value = value
                return
            node = node.next
        new_node = Node(key, value)
        new_node.next = self._buckets[idx]
        self._buckets[idx] = new_node
        self._size += 1
        if self._size > self._capacity * 0.75:
            self._resize()

    def get(self, key, default=None):
        idx = self._hash(key)
        node = self._buckets[idx]
        while node:
            if node.key == key:
                return node.value
            node = node.next
        return default

    def contains(self, key):
        return self.get(key) is not None

    def remove(self, key):
        idx = self._hash(key)
        node = self._buckets[idx]
        prev = None
        while node:
            if node.key == key:
                if prev:
                    prev.next = node.next
                else:
                    self._buckets[idx] = node.next
                self._size -= 1
                return True
            prev = node
            node = node.next
        return False

    def keys(self):
        result = []
        for bucket in self._buckets:
            node = bucket
            while node:
                result.append(node.key)
                node = node.next
        return result

    def values(self):
        result = []
        for bucket in self._buckets:
            node = bucket
            while node:
                result.append(node.value)
                node = node.next
        return result

    def items(self):
        result = []
        for bucket in self._buckets:
            node = bucket
            while node:
                result.append((node.key, node.value))
                node = node.next
        return result

    def size(self):
        return self._size

    def _resize(self):
        old = self._buckets
        self._capacity *= 2
        self._buckets = [None] * self._capacity
        self._size = 0
        for bucket in old:
            node = bucket
            while node:
                self.put(node.key, node.value)
                node = node.next


class QueueNode:
    __slots__ = ('data', 'next')
    def __init__(self, data):
        self.data = data
        self.next = None


class Queue:
    def __init__(self):
        self._front = None
        self._rear = None
        self._size = 0

    def enqueue(self, data):
        node = QueueNode(data)
        if self._rear:
            self._rear.next = node
        self._rear = node
        if not self._front:
            self._front = node
        self._size += 1

    def dequeue(self):
        if not self._front:
            return None
        data = self._front.data
        self._front = self._front.next
        if not self._front:
            self._rear = None
        self._size -= 1
        return data

    def peek(self):
        return self._front.data if self._front else None

    def is_empty(self):
        return self._size == 0

    def size(self):
        return self._size

    def to_list(self):
        result = []
        node = self._front
        while node:
            result.append(node.data)
            node = node.next
        return result


class TrieNode:
    __slots__ = ('children', 'is_end', 'word')
    def __init__(self):
        self.children = {}
        self.is_end = False
        self.word = None


class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, word):
        node = self.root
        for ch in word:
            if ch not in node.children:
                node.children[ch] = TrieNode()
            node = node.children[ch]
        node.is_end = True
        node.word = word

    def search_prefix(self, prefix):
        node = self.root
        for ch in prefix:
            if ch not in node.children:
                return []
            node = node.children[ch]
        results = []
        self._collect(node, results)
        return results

    def _collect(self, node, results):
        if node.is_end:
            results.append(node.word)
        for child in node.children.values():
            self._collect(child, results)


# =============================================================================
# PURE PYTHON MD4 (fallback for NTLM when hashlib md4 is unavailable)
# =============================================================================

def _md4_hash(data):
    """Pure Python MD4 implementation"""
    def _f(x, y, z):
        return (x & y) | (~x & z)
    def _g(x, y, z):
        return (x & y) | (x & z) | (y & z)
    def _h(x, y, z):
        return x ^ y ^ z
    def _left_rotate(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    msg = bytearray(data)
    orig_len = len(msg)
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len * 8)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        X = list(struct.unpack('<16I', block))
        aa, bb, cc, dd = a, b, c, d

        for k, s in [(0,3),(1,7),(2,11),(3,19),(4,3),(5,7),(6,11),(7,19),
                      (8,3),(9,7),(10,11),(11,19),(12,3),(13,7),(14,11),(15,19)]:
            a = _left_rotate((a + _f(b, c, d) + X[k]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        for k, s in [(0,3),(4,5),(8,9),(12,13),(1,3),(5,5),(9,9),(13,13),
                      (2,3),(6,5),(10,9),(14,13),(3,3),(7,5),(11,9),(15,13)]:
            a = _left_rotate((a + _g(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        for k, s in [(0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),
                      (1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15)]:
            a = _left_rotate((a + _h(b, c, d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    return struct.pack('<4I', a, b, c, d).hex()


# =============================================================================
# HASH ENGINE
# =============================================================================

class HashEngine:
    ALGORITHMS = HashMap()

    @staticmethod
    def _init_algorithms():
        algos = [
            ('md5', 32), ('sha1', 40), ('sha224', 56), ('sha256', 64),
            ('sha384', 96), ('sha512', 128), ('sha3_224', 56), ('sha3_256', 64),
            ('sha3_384', 96), ('sha3_512', 128), ('blake2b', 128), ('blake2s', 64),
        ]
        for name, length in algos:
            HashEngine.ALGORITHMS.put(name, length)

    @staticmethod
    def compute(text, algo='md5'):
        fn = getattr(hashlib, algo, None)
        if fn is None:
            return None
        return fn(text.encode('utf-8')).hexdigest()

    @staticmethod
    def identify_hash(hash_str):
        h = hash_str.strip()
        shadow_matches = ShadowParser.identify_hash_type(h)
        if shadow_matches:
            return shadow_matches
        hash_len = len(h)
        matches = []
        for name, length in HashEngine.ALGORITHMS.items():
            if length == hash_len:
                matches.append(name)
        if hash_len == 32 and all(c in '0123456789abcdef' for c in h.lower()):
            matches.append('ntlm')
        return matches

    @staticmethod
    def supported_algorithms():
        return HashEngine.ALGORITHMS.keys()


HashEngine._init_algorithms()


# =============================================================================
# NTLM HASH SUPPORT
# =============================================================================

class NTLMEngine:
    @staticmethod
    def compute_ntlm(password):
        encoded = password.encode('utf-16-le')
        try:
            return hashlib.new('md4', encoded).hexdigest()
        except (ValueError, TypeError):
            return _md4_hash(encoded)

    @staticmethod
    def is_ntlm(hash_str):
        h = hash_str.strip().lower()
        return len(h) == 32 and all(c in '0123456789abcdef' for c in h)


# =============================================================================
# SHADOW FILE PARSER
# =============================================================================

class ShadowEntry:
    def __init__(self, username='', hash_type='', salt='', hash_value='', full_hash='', raw_line=''):
        self.username = username
        self.hash_type = hash_type
        self.hash_type_name = ''
        self.salt = salt
        self.hash_value = hash_value
        self.full_hash = full_hash
        self.raw_line = raw_line


class ShadowParser:
    HASH_TYPES = {
        '1': 'MD5-crypt', '2a': 'bcrypt', '2b': 'bcrypt', '2y': 'bcrypt',
        '5': 'SHA-256-crypt', '6': 'SHA-512-crypt', '7': 'scrypt',
        'y': 'yescrypt', 'gy': 'gost-yescrypt',
    }

    @staticmethod
    def identify_hash_type(hash_str):
        h = hash_str.strip()
        if not h.startswith('$'):
            return []
        if re.match(r'^\$2[aby]?\$\d{2}\$', h):
            return ['bcrypt']
        match = re.match(r'^\$([a-zA-Z0-9]+)\$', h)
        if match:
            prefix = match.group(1)
            name = ShadowParser.HASH_TYPES.get(prefix)
            if name:
                return [f'{name} (${prefix}$)']
            return [f'Unknown crypt type (${prefix}$)']
        return []

    @staticmethod
    def parse_shadow_line(line):
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        entry = ShadowEntry(raw_line=line)
        parts = line.split(':')
        if len(parts) >= 2 and parts[1].startswith('$'):
            entry.username = parts[0]
            entry.full_hash = parts[1]
        elif line.startswith('$'):
            entry.full_hash = line
        else:
            entry.full_hash = parts[0] if parts else line

        h = entry.full_hash
        if h.startswith('$'):
            crypt_match = re.match(r'^\$([a-zA-Z0-9]+)\$(.+)$', h)
            if crypt_match:
                entry.hash_type = crypt_match.group(1)
                remainder = crypt_match.group(2)
                entry.hash_type_name = ShadowParser.HASH_TYPES.get(
                    entry.hash_type, f'Unknown (${entry.hash_type}$)')

                if entry.hash_type in ('2a', '2b', '2y'):
                    m = re.match(r'^(\d{2})\$(.{22})(.+)$', remainder)
                    if m:
                        entry.salt = f"${entry.hash_type}${m.group(1)}${m.group(2)}"
                        entry.hash_value = m.group(3)
                elif entry.hash_type == 'y':
                    yp = remainder.split('$')
                    if len(yp) >= 3:
                        entry.salt = f"${entry.hash_type}${yp[0]}${yp[1]}"
                        entry.hash_value = yp[2]
                    elif len(yp) == 2:
                        entry.salt = f"${entry.hash_type}${yp[0]}"
                        entry.hash_value = yp[1]
                elif entry.hash_type in ('5', '6'):
                    sp = remainder.split('$')
                    if sp[0].startswith('rounds='):
                        if len(sp) >= 3:
                            entry.salt = f"${entry.hash_type}${sp[0]}${sp[1]}"
                            entry.hash_value = sp[2]
                    else:
                        if len(sp) >= 2:
                            entry.salt = f"${entry.hash_type}${sp[0]}"
                            entry.hash_value = sp[1]
                elif entry.hash_type == '1':
                    mp = remainder.split('$')
                    if len(mp) >= 2:
                        entry.salt = f"$1${mp[0]}"
                        entry.hash_value = mp[1]
                elif entry.hash_type == '7':
                    scp = remainder.split('$')
                    if len(scp) >= 3:
                        entry.salt = f"$7${scp[0]}${scp[1]}"
                        entry.hash_value = scp[2]
                else:
                    ld = remainder.rfind('$')
                    if ld > 0:
                        entry.salt = f"${entry.hash_type}${remainder[:ld]}"
                        entry.hash_value = remainder[ld + 1:]
        return entry

    @staticmethod
    def parse_shadow_file(filepath):
        entries = []
        try:
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    entry = ShadowParser.parse_shadow_line(line)
                    if entry and entry.full_hash and entry.full_hash not in ('*', '!', '!!', 'x', ''):
                        entries.append(entry)
        except FileNotFoundError:
            pass
        return entries


# =============================================================================
# KEYWORD PATTERN FILTER
# =============================================================================

class KeywordFilter:
    def __init__(self):
        self.trie = Trie()
        self.keywords = []

    def set_keywords(self, keyword_string):
        raw = keyword_string.replace(',', ' ')
        self.keywords = [k.strip().lower() for k in raw.split() if k.strip()]
        self.trie = Trie()
        for kw in self.keywords:
            self.trie.insert(kw)

    def _strip_specials(self, word):
        return ''.join(ch for ch in word if ch.isalnum()).lower()

    def _generate_keyword_mutations(self):
        seen = HashMap()
        mutations = Queue()
        specials = ['!', '@', '#', '$', '%', '&', '*', '.', '-', '_', '~', '+', '=']
        suffixes = ['', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                    '10', '11', '12', '13', '14', '15', '16', '17', '18', '19',
                    '20', '21', '22', '23', '24', '25', '26', '27', '28', '29',
                    '30', '31', '32', '33', '34', '44', '55', '66', '77', '88', '99',
                    '01', '02', '03', '04', '05', '06', '07', '08', '09',
                    '00', '69', '42', '50', '64', '86', '96',
                    '12', '123', '1234', '12345', '123456',
                    '100', '101', '111', '007', '666', '777', '786', '420', '911',
                    '2020', '2021', '2022', '2023', '2024', '2025', '2026',
                    '!', '!!', '!!!', '@', '#', '$', '%',
                    '!@', '!@#', '@!', '#1', '$1',
                    '1!', '123!', '1234!', '!1', '!123',
                    '.', '..', '_', '-',
                    ' ', '  ', ' 1', ' 123']  # trailing space variants
        prefixes = ['', '!', '@', '#', '$', '1', '123', '!@', '!@#', ' ']  # includes leading space

        for kw in self.keywords:
            bases = [kw, kw.upper(), kw.capitalize(), kw.swapcase(), kw[::-1], kw + kw]
            leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7', 'l': '1', 'g': '9', 'b': '8'}
            leet = list(kw.lower())
            for idx, ch in enumerate(leet):
                if ch in leet_map:
                    leet[idx] = leet_map[ch]
            bases.append(''.join(leet))
            bases.append(''.join(leet).capitalize())
            bases.extend(['-'.join(kw), '.'.join(kw), '_'.join(kw)])

            for b in bases:
                for s in suffixes:
                    for p in prefixes:
                        candidate = p + b + s
                        if not seen.contains(candidate):
                            seen.put(candidate, True)
                            mutations.enqueue(candidate)
                for sp in specials:
                    for variant in [sp + b, b + sp, sp + b + sp]:
                        if not seen.contains(variant):
                            seen.put(variant, True)
                            mutations.enqueue(variant)

        # Multi-keyword combos (no lambda closure bugs — uses direct string ops)
        multi = []
        if len(self.keywords) >= 2:
            for i in range(len(self.keywords)):
                for j in range(len(self.keywords)):
                    if i != j:
                        a = self.keywords[i]
                        b = self.keywords[j]
                        for sep in ['', ' ', '_', '-', '.', '!', '@', '#', '1', '123']:
                            for c in [a + sep + b, a.capitalize() + sep + b,
                                      a + sep + b.capitalize(),
                                      a.capitalize() + sep + b.capitalize(),
                                      a.upper() + sep + b.upper()]:
                                if not seen.contains(c):
                                    seen.put(c, True)
                                    multi.append(c)
                        for suf in ['', '1', '123', '!', '@', '#', '2025', '2026']:
                            for c in [a + b + suf, a.capitalize() + b.capitalize() + suf]:
                                if not seen.contains(c):
                                    seen.put(c, True)
                                    multi.append(c)

        combo_q = Queue()
        for m in multi:
            combo_q.enqueue(m)
        return combo_q, mutations

    def filter_wordlist(self, words):
        combo_mutations, single_mutations = self._generate_keyword_mutations()
        priority = Queue()
        remaining = Queue()
        seen = HashMap()

        for w in combo_mutations.to_list():
            if not seen.contains(w):
                seen.put(w, True)
                priority.enqueue(w)

        for w in single_mutations.to_list():
            if not seen.contains(w):
                seen.put(w, True)
                priority.enqueue(w)

        for word in words:
            if seen.contains(word):
                continue
            word_lower = word.lower()
            word_stripped = self._strip_specials(word)
            matched = False
            for kw in self.keywords:
                if kw in word_lower or kw in word_stripped:
                    matched = True
                    break
            if matched:
                seen.put(word, True)
                priority.enqueue(word)
                # Also add space variants of matched words
                for space_variant in [word + ' ', ' ' + word, word + '  ']:
                    if not seen.contains(space_variant):
                        seen.put(space_variant, True)
                        priority.enqueue(space_variant)
            else:
                remaining.enqueue(word)
        return priority, remaining


# =============================================================================
# SHARED UTILITIES
# =============================================================================

class AttackResult:
    def __init__(self):
        self.found = False
        self.password = None
        self.attempts = 0
        self.elapsed = 0.0
        self.speed = 0.0
        self.method = ""


def _load_wordlist(path):
    words = []
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            w = line.rstrip('\n').rstrip('\r')  # Preserve trailing spaces
            if w:
                words.append(w)
            else:
                # Also try without trailing spaces (in case file has them)
                w2 = line.strip()
                if w2:
                    words.append(w2)
    return words


def _apply_keyword_priority(words, keyword_filter, log_fn=None):
    if keyword_filter and keyword_filter.keywords:
        pq, rq = keyword_filter.filter_wordlist(words)
        plist = pq.to_list()
        rlist = rq.to_list()
        count = len(plist)
        if log_fn:
            log_fn(f"[KEYWORD PRIORITY] {count:,} words matched keywords, trying those FIRST")
            if count <= 20:
                for pw in plist:
                    log_fn(f"  >> Priority: {pw}")
        return plist + rlist, count
    return words, 0


# =============================================================================
# CRYPT / SHADOW CRACKERS
# =============================================================================

class CryptCracker:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback
        self.stopped = False

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def _verify_password(self, password, shadow_entry):
        full_hash = shadow_entry.full_hash
        hash_type = shadow_entry.hash_type

        try:
            import crypt as crypt_mod
            salt = shadow_entry.salt if shadow_entry.salt else full_hash
            result = crypt_mod.crypt(password, salt)
            return result == full_hash
        except (ImportError, Exception):
            pass

        if hash_type in ('2a', '2b', '2y'):
            try:
                import bcrypt as bcrypt_mod
                return bcrypt_mod.checkpw(password.encode('utf-8'), full_hash.encode('utf-8'))
            except ImportError:
                self._log("[!] bcrypt not installed. Run: pip install bcrypt")
                return None
            except Exception:
                return False

        try:
            from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt
            from passlib.hash import bcrypt as passlib_bcrypt
            verifiers = {'1': md5_crypt, '5': sha256_crypt, '6': sha512_crypt,
                         '2a': passlib_bcrypt, '2b': passlib_bcrypt, '2y': passlib_bcrypt}
            verifier = verifiers.get(hash_type)
            if verifier:
                return verifier.verify(password, full_hash)
        except ImportError:
            pass

        if hash_type == 'y':
            return self._try_yescrypt_ctypes(password, full_hash)

        return None

    def _try_yescrypt_ctypes(self, password, full_hash):
        # === Strategy 1: Bundled libyescrypt (works on Windows + Linux) ===
        try:
            lib = _load_yescrypt_lib()
            if lib is not None:
                result = lib.yescrypt_verify(password.encode('utf-8'), full_hash.encode('utf-8'))
                if result == 1:
                    return True
                elif result == 0:
                    return False
                # result == -1 means error, fall through
        except Exception:
            pass

        # === Strategy 2: System libcrypt (Linux with libxcrypt) ===
        try:
            libcrypt_path = ctypes.util.find_library('crypt')
            if not libcrypt_path:
                for path in ['/lib/x86_64-linux-gnu/libcrypt.so.1', '/lib64/libcrypt.so.1',
                             '/usr/lib/libcrypt.so.1', '/usr/lib/libcrypt.so',
                             '/lib/libcrypt.so.1', '/usr/lib64/libcrypt.so.1']:
                    if os.path.exists(path):
                        libcrypt_path = path
                        break
            if libcrypt_path:
                libcrypt = ctypes.CDLL(libcrypt_path)
                libcrypt.crypt.restype = ctypes.c_char_p
                libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
                result = libcrypt.crypt(password.encode('utf-8'), full_hash.encode('utf-8'))
                if result:
                    return result.decode('utf-8') == full_hash
                return False
        except Exception:
            pass

        self._log("[!] yescrypt: No library found!")
        self._log("[!] Place libyescrypt.so (Linux) or libyescrypt.dll (Windows)")
        self._log("[!]   in the same folder as crackvault_v2.py")
        self._log("[!] Build instructions: https://github.com/openwall/yescrypt")
        return None

    def _generate_username_guesses(self, username):
        guesses = []
        u = username.lower()
        bases = [u, u.capitalize(), u.upper(), u + u, u[::-1]]
        suffixes = ['', '1', '12', '123', '1234', '!', '!!', '@', '#',
                    '01', '99', '2024', '2025', '2026', '007', '69', '666',
                    '123!', '1234!', '!@#', '123456', 'password', 'pass']
        for b in bases:
            for s in suffixes:
                guesses.append(b + s)
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        leet = list(u)
        for idx, ch in enumerate(leet):
            if ch in leet_map:
                leet[idx] = leet_map[ch]
        leet_str = ''.join(leet)
        for s in ['', '1', '123', '!', '!@#']:
            guesses.append(leet_str + s)
        return guesses

    def crack(self, shadow_entry, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = f"Crypt Crack ({shadow_entry.hash_type_name})"
        start = time.time()

        if shadow_entry.username:
            self._log(f"[*] Target user: {shadow_entry.username}")
        self._log(f"[*] Hash type : {shadow_entry.hash_type_name}")
        hd = shadow_entry.full_hash
        self._log(f"[*] Full hash : {hd[:60]}{'...' if len(hd) > 60 else ''}")

        if shadow_entry.hash_type in ('2a', '2b', '2y'):
            self._log("[!] bcrypt is intentionally SLOW (~5-20 pwd/sec). Use keywords!")
        elif shadow_entry.hash_type == 'y':
            self._log("[!] yescrypt is intentionally SLOW (~2-10 pwd/sec). Use keywords!")
        elif shadow_entry.hash_type in ('5', '6'):
            self._log("[*] SHA-crypt: moderate speed (~100-500 pwd/sec)")

        try:
            words = _load_wordlist(wordlist_path)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        ordered, pc = _apply_keyword_priority(words, keyword_filter, self._log)

        if shadow_entry.username:
            uguesses = self._generate_username_guesses(shadow_entry.username)
            self._log(f"[PRIORITY] {len(uguesses)} username-derived guesses added to front")
            seen_set = set(ordered[:pc]) if pc > 0 else set()
            user_new = [g for g in uguesses if g not in seen_set]
            ordered = user_new + ordered

        total = len(ordered)
        self._log(f"[*] Total candidates: {total:,}")
        self._log(f"[*] Starting crack...\n")

        for i, word in enumerate(ordered):
            if self.stopped:
                break
            result.attempts += 1
            verified = self._verify_password(word, shadow_entry)
            if verified is None:
                result.method = f"Error: No library for {shadow_entry.hash_type_name}"
                self._log(f"[!] Cannot verify {shadow_entry.hash_type_name} hashes.")
                self._log(f"[!] Install: pip install bcrypt passlib")
                self._log(f"[!] Or run on Linux (crypt module available)")
                return result
            if verified:
                result.found = True
                result.password = word
                result.elapsed = time.time() - start
                result.speed = result.attempts / max(result.elapsed, 0.001)
                if self.callback:
                    self.callback(result.attempts, total, word, True)
                return result
            if self.callback and result.attempts % 10 == 0:
                self.callback(result.attempts, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


class ShadowFileCracker:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback
        self.stopped = False
        self._current_cracker = None

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def crack_file(self, shadow_path, wordlist_path, keyword_filter=None, target_users=None):
        entries = ShadowParser.parse_shadow_file(shadow_path)
        if not entries:
            r = AttackResult()
            r.method = "Error: No valid hash entries found"
            return [r]

        self._log(f"[*] Parsed {len(entries)} hash entries from shadow file")
        for e in entries:
            ud = e.username if e.username else '(no username)'
            hd = e.full_hash[:40] + '...' if len(e.full_hash) > 40 else e.full_hash
            self._log(f"    {ud:20s}  {e.hash_type_name:20s}  {hd}")

        if target_users:
            tset = set(u.strip().lower() for u in target_users)
            entries = [e for e in entries if e.username.lower() in tset]
            self._log(f"[*] Filtered to {len(entries)} target user(s)")

        self._log(f"\n{'=' * 60}\n")
        results = []

        for idx, entry in enumerate(entries):
            if self.stopped:
                break
            self._log(f"[{idx + 1}/{len(entries)}] Cracking: {entry.username or '(unknown)'} ({entry.hash_type_name})")
            self._log(f"{'-' * 50}")
            cracker = CryptCracker(callback=self.callback, log_callback=self.log_callback)
            self._current_cracker = cracker
            result = cracker.crack(entry, wordlist_path, keyword_filter)
            if entry.username:
                result.method = f"{entry.username}: {result.method}"
            results.append(result)
            if result.found:
                self._log(f"\n[+] CRACKED {entry.username}: {result.password}\n")
            else:
                self._log(f"\n[-] Failed for {entry.username}\n")

        return results

    def stop(self):
        self.stopped = True
        if self._current_cracker:
            self._current_cracker.stop()


# =============================================================================
# HASH ATTACK MODULES
# =============================================================================

class WordlistAttack:
    def __init__(self, callback=None):
        self.callback = callback
        self.stopped = False

    def crack_hash(self, target_hash, algo, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "Wordlist Attack"
        start = time.time()
        try:
            words = _load_wordlist(wordlist_path)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        if keyword_filter and keyword_filter.keywords:
            pq, rq = keyword_filter.filter_wordlist(words)
            ordered_words = pq.to_list() + rq.to_list()
        else:
            ordered_words = words

        total = len(ordered_words)
        for i, word in enumerate(ordered_words):
            if self.stopped:
                break
            computed = HashEngine.compute(word, algo)
            result.attempts += 1
            if computed == target_hash.lower().strip():
                result.found = True
                result.password = word
                result.elapsed = time.time() - start
                result.speed = result.attempts / max(result.elapsed, 0.001)
                if self.callback:
                    self.callback(result.attempts, total, word, True)
                return result
            if self.callback and result.attempts % 500 == 0:
                self.callback(result.attempts, total, word, False)
        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


class BruteForceAttack:
    def __init__(self, callback=None):
        self.callback = callback
        self.stopped = False

    def crack_hash(self, target_hash, algo, charset, min_len, max_len):
        result = AttackResult()
        result.method = "Brute Force Attack"
        start = time.time()
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                if self.stopped:
                    result.elapsed = time.time() - start
                    result.speed = result.attempts / max(result.elapsed, 0.001)
                    return result
                word = ''.join(combo)
                computed = HashEngine.compute(word, algo)
                result.attempts += 1
                if computed == target_hash.lower().strip():
                    result.found = True
                    result.password = word
                    result.elapsed = time.time() - start
                    result.speed = result.attempts / max(result.elapsed, 0.001)
                    if self.callback:
                        self.callback(result.attempts, 0, word, True)
                    return result
                if self.callback and result.attempts % 1000 == 0:
                    self.callback(result.attempts, 0, word, False)
        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


class RuleBasedAttack:
    def __init__(self, callback=None):
        self.callback = callback
        self.stopped = False

    def generate_mutations(self, word):
        mutations = Queue()
        mutations.enqueue(word)
        mutations.enqueue(word.upper())
        mutations.enqueue(word.lower())
        mutations.enqueue(word.capitalize())
        mutations.enqueue(word.swapcase())
        mutations.enqueue(word[::-1])
        mutations.enqueue(word + word)
        leet_map = HashMap()
        leet_map.put('a', '@'); leet_map.put('e', '3'); leet_map.put('i', '1')
        leet_map.put('o', '0'); leet_map.put('s', '$'); leet_map.put('t', '7')
        leet_map.put('l', '1'); leet_map.put('g', '9'); leet_map.put('b', '8')
        leet = list(word.lower())
        for idx, ch in enumerate(leet):
            replacement = leet_map.get(ch)
            if replacement:
                leet[idx] = replacement
        mutations.enqueue(''.join(leet))
        for s in ['1', '12', '123', '1234', '!', '!!', '@', '#',
                  '01', '02', '03', '04', '05', '06', '07', '08', '09',
                  '00', '10', '11', '22', '33', '44', '55', '66', '77', '88', '99',
                  '69', '007', '666', '2024', '2025', '2026', '!@#', '123!']:
            mutations.enqueue(word + s)
            mutations.enqueue(word.capitalize() + s)
        for p in ['!', '@', '#', '1', '123']:
            mutations.enqueue(p + word)
        return mutations

    def crack_hash(self, target_hash, algo, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "Rule-Based Attack"
        start = time.time()
        try:
            words = _load_wordlist(wordlist_path)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        if keyword_filter and keyword_filter.keywords:
            pq, rq = keyword_filter.filter_wordlist(words)
            ordered = pq.to_list() + rq.to_list()
        else:
            ordered = words

        total = len(ordered)
        for i, word in enumerate(ordered):
            if self.stopped:
                break
            mutations = self.generate_mutations(word)
            while not mutations.is_empty():
                if self.stopped:
                    break
                mutant = mutations.dequeue()
                computed = HashEngine.compute(mutant, algo)
                result.attempts += 1
                if computed == target_hash.lower().strip():
                    result.found = True
                    result.password = mutant
                    result.elapsed = time.time() - start
                    result.speed = result.attempts / max(result.elapsed, 0.001)
                    if self.callback:
                        self.callback(i + 1, total, mutant, True)
                    return result
            if self.callback and (i + 1) % 100 == 0:
                self.callback(i + 1, total, word, False)
        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


class NTLMCracker:
    def __init__(self, callback=None):
        self.callback = callback
        self.stopped = False

    def crack_hash(self, target_hash, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "NTLM Crack"
        start = time.time()
        target = target_hash.lower().strip()
        try:
            words = _load_wordlist(wordlist_path)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        if keyword_filter and keyword_filter.keywords:
            pq, rq = keyword_filter.filter_wordlist(words)
            ordered = pq.to_list() + rq.to_list()
        else:
            ordered = words

        total = len(ordered)
        for i, word in enumerate(ordered):
            if self.stopped:
                break
            computed = NTLMEngine.compute_ntlm(word)
            result.attempts += 1
            if computed == target:
                result.found = True
                result.password = word
                result.elapsed = time.time() - start
                result.speed = result.attempts / max(result.elapsed, 0.001)
                if self.callback:
                    self.callback(result.attempts, total, word, True)
                return result
            if self.callback and result.attempts % 500 == 0:
                self.callback(result.attempts, total, word, False)
        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


# =============================================================================
# FILE CRACKERS
# =============================================================================

class ZipCracker:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback
        self.stopped = False

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def crack(self, zip_path, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "ZIP File Crack"
        start = time.time()
        try:
            zf = zipfile.ZipFile(zip_path)
        except Exception as e:
            result.method = f"Error: {e}"
            return result
        try:
            words = _load_wordlist(wordlist_path)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        ordered, _ = _apply_keyword_priority(words, keyword_filter, self._log)
        tmp_dir = tempfile.mkdtemp()
        total = len(ordered)

        for i, word in enumerate(ordered):
            if self.stopped:
                break
            result.attempts += 1
            try:
                zf.extractall(path=tmp_dir, pwd=word.encode('utf-8'))
                result.found = True
                result.password = word
                result.elapsed = time.time() - start
                result.speed = result.attempts / max(result.elapsed, 0.001)
                if self.callback:
                    self.callback(result.attempts, total, word, True)
                zf.close()
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return result
            except (RuntimeError, zipfile.BadZipFile, Exception):
                pass
            if self.callback and result.attempts % 200 == 0:
                self.callback(result.attempts, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        zf.close()
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return result

    def stop(self):
        self.stopped = True


class PDFCracker:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback
        self.stopped = False

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def crack(self, pdf_path, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "PDF File Crack"
        start = time.time()
        try:
            import pikepdf
        except ImportError:
            result.method = "Error: pikepdf not installed (pip install pikepdf)"
            return result
        try:
            words = _load_wordlist(wordlist_path)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        ordered, _ = _apply_keyword_priority(words, keyword_filter, self._log)
        total = len(ordered)

        for i, word in enumerate(ordered):
            if self.stopped:
                break
            result.attempts += 1
            try:
                with pikepdf.open(pdf_path, password=word) as pdf:
                    result.found = True
                    result.password = word
                    result.elapsed = time.time() - start
                    result.speed = result.attempts / max(result.elapsed, 0.001)
                    if self.callback:
                        self.callback(result.attempts, total, word, True)
                    return result
            except Exception:
                pass
            if self.callback and result.attempts % 100 == 0:
                self.callback(result.attempts, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


class RARCracker:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback
        self.stopped = False

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def crack(self, rar_path, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "RAR File Crack"
        start = time.time()
        try:
            import rarfile
            rarfile.UNRAR_TOOL = 'unrar'
        except ImportError:
            result.method = "Error: rarfile not installed (pip install rarfile) + unrar binary needed"
            return result
        try:
            rf = rarfile.RarFile(rar_path)
        except Exception as e:
            result.method = f"Error: {e}"
            return result
        if not rf.needs_password():
            self._log("[*] RAR file is NOT password-protected!")
            result.method = "RAR: No password needed"
            rf.close()
            return result
        try:
            words = _load_wordlist(wordlist_path)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            rf.close()
            return result

        ordered, _ = _apply_keyword_priority(words, keyword_filter, self._log)
        tmp_dir = tempfile.mkdtemp()
        total = len(ordered)

        for i, word in enumerate(ordered):
            if self.stopped:
                break
            result.attempts += 1
            try:
                rf.extractall(path=tmp_dir, pwd=word)
                result.found = True
                result.password = word
                result.elapsed = time.time() - start
                result.speed = result.attempts / max(result.elapsed, 0.001)
                if self.callback:
                    self.callback(result.attempts, total, word, True)
                rf.close()
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return result
            except Exception:
                pass
            if self.callback and result.attempts % 100 == 0:
                self.callback(result.attempts, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        rf.close()
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return result

    def stop(self):
        self.stopped = True


class SevenZipCracker:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback
        self.stopped = False

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def crack(self, archive_path, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "7-Zip File Crack"
        start = time.time()
        try:
            import py7zr
        except ImportError:
            result.method = "Error: py7zr not installed (pip install py7zr)"
            return result
        try:
            words = _load_wordlist(wordlist_path)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        ordered, _ = _apply_keyword_priority(words, keyword_filter, self._log)
        tmp_dir = tempfile.mkdtemp()
        total = len(ordered)

        for i, word in enumerate(ordered):
            if self.stopped:
                break
            result.attempts += 1
            try:
                with py7zr.SevenZipFile(archive_path, mode='r', password=word) as z:
                    z.extractall(path=tmp_dir)
                result.found = True
                result.password = word
                result.elapsed = time.time() - start
                result.speed = result.attempts / max(result.elapsed, 0.001)
                if self.callback:
                    self.callback(result.attempts, total, word, True)
                shutil.rmtree(tmp_dir, ignore_errors=True)
                return result
            except Exception:
                pass
            if self.callback and result.attempts % 50 == 0:
                self.callback(result.attempts, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return result

    def stop(self):
        self.stopped = True


class OfficeCracker:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback
        self.stopped = False

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def crack(self, office_path, wordlist_path, keyword_filter=None):
        result = AttackResult()
        ext = os.path.splitext(office_path)[1].lower()
        result.method = f"Office File Crack ({ext})"
        start = time.time()
        try:
            import msoffcrypto
        except ImportError:
            result.method = "Error: msoffcrypto-tool not installed (pip install msoffcrypto-tool)"
            return result
        try:
            words = _load_wordlist(wordlist_path)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        ordered, _ = _apply_keyword_priority(words, keyword_filter, self._log)
        total = len(ordered)

        for i, word in enumerate(ordered):
            if self.stopped:
                break
            result.attempts += 1
            try:
                with open(office_path, 'rb') as f:
                    of = msoffcrypto.OfficeFile(f)
                    of.load_key(password=word)
                    decrypted = io.BytesIO()
                    of.decrypt(decrypted)
                result.found = True
                result.password = word
                result.elapsed = time.time() - start
                result.speed = result.attempts / max(result.elapsed, 0.001)
                if self.callback:
                    self.callback(result.attempts, total, word, True)
                return result
            except Exception:
                pass
            if self.callback and result.attempts % 50 == 0:
                self.callback(result.attempts, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


class KeePassCracker:
    def __init__(self, callback=None, log_callback=None):
        self.callback = callback
        self.log_callback = log_callback
        self.stopped = False

    def _log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def crack(self, kdbx_path, wordlist_path, keyword_filter=None):
        result = AttackResult()
        result.method = "KeePass (.kdbx) Crack"
        start = time.time()
        try:
            from pykeepass import PyKeePass
        except ImportError:
            result.method = "Error: pykeepass not installed (pip install pykeepass)"
            return result
        try:
            words = _load_wordlist(wordlist_path)
        except FileNotFoundError:
            result.method = "Error: Wordlist not found"
            return result

        self._log("[!] KeePass uses argon2/AES — cracking is SLOW (~1-10 pwd/sec)")
        ordered, _ = _apply_keyword_priority(words, keyword_filter, self._log)
        total = len(ordered)

        for i, word in enumerate(ordered):
            if self.stopped:
                break
            result.attempts += 1
            try:
                PyKeePass(kdbx_path, password=word)
                result.found = True
                result.password = word
                result.elapsed = time.time() - start
                result.speed = result.attempts / max(result.elapsed, 0.001)
                if self.callback:
                    self.callback(result.attempts, total, word, True)
                return result
            except Exception:
                pass
            if self.callback and result.attempts % 5 == 0:
                self.callback(result.attempts, total, word, False)

        result.elapsed = time.time() - start
        result.speed = result.attempts / max(result.elapsed, 0.001)
        return result

    def stop(self):
        self.stopped = True


# =============================================================================
# HASH GENERATOR
# =============================================================================

class HashGenerator:
    @staticmethod
    def generate(text, algo):
        return HashEngine.compute(text, algo)

    @staticmethod
    def generate_all(text):
        results = HashMap()
        for algo in HashEngine.supported_algorithms():
            h = HashEngine.compute(text, algo)
            if h:
                results.put(algo, h)
        results.put('ntlm', NTLMEngine.compute_ntlm(text))
        return results


# =============================================================================
# SESSION LOG
# =============================================================================

class SessionLog:
    def __init__(self):
        self.log = Queue()

    def add(self, result):
        entry = {
            'time': time.strftime('%H:%M:%S'),
            'method': result.method,
            'found': result.found,
            'password': result.password if result.found else 'N/A',
            'attempts': result.attempts,
            'elapsed': f"{result.elapsed:.2f}s",
            'speed': f"{result.speed:.0f} pwd/s"
        }
        self.log.enqueue(entry)

    def get_all(self):
        return self.log.to_list()

    def clear(self):
        self.log = Queue()


# =============================================================================
# GUI APPLICATION
# =============================================================================

if not HAS_TK:
    class CrackVaultApp:
        def __init__(self):
            raise RuntimeError("tkinter is required for GUI.")
        def run(self):
            pass
else:
    class CrackVaultApp:
        BG = '#0a0e14'
        FG = '#d4d4d4'
        ACCENT = '#00bfff'
        GREEN = '#00e676'
        RED = '#ff5252'
        ORANGE = '#ffab40'
        YELLOW = '#ffd740'
        CARD_BG = '#131820'
        ENTRY_BG = '#1a2030'
        BTN_BG = '#00bfff'
        BTN_STOP = '#ff5252'
        BORDER = '#1e2a3a'
        MUTED = '#6b7b8d'

        def __init__(self):
            self.root = tk.Tk()
            self.root.title("CrackVault")
            self.root.geometry("1100x750")
            self.root.configure(bg=self.BG)
            self.root.minsize(950, 680)
            try:
                # Try multiple icon locations (PyInstaller bundle, script dir, assets/)
                base_dirs = []
                if hasattr(sys, '_MEIPASS'):
                    base_dirs.append(sys._MEIPASS)
                if getattr(sys, 'frozen', False):
                    base_dirs.append(os.path.dirname(sys.executable))
                base_dirs.append(os.path.dirname(os.path.abspath(__file__)))
                for bd in base_dirs:
                    for icon_name in ['crackvault.ico', 'icon.ico', os.path.join('assets', 'icon.ico')]:
                        icon_path = os.path.join(bd, icon_name)
                        if os.path.exists(icon_path):
                            self.root.iconbitmap(icon_path)
                            break
            except Exception:
                pass
            self.session_log = SessionLog()
            self.current_attack = None
            self.attack_thread = None
            self.keyword_filter = KeywordFilter()
            self._setup_styles()
            self._build_ui()

        def _setup_styles(self):
            self.style = ttk.Style()
            self.style.theme_use('clam')
            self.style.configure('TNotebook', background=self.BG, borderwidth=0)
            self.style.configure('TNotebook.Tab', background=self.CARD_BG, foreground=self.MUTED,
                                 padding=[20, 10], font=('Segoe UI', 10, 'bold'))
            self.style.map('TNotebook.Tab', background=[('selected', self.BG)],
                           foreground=[('selected', self.ACCENT)])
            self.style.configure('TFrame', background=self.BG)
            self.style.configure('Card.TFrame', background=self.CARD_BG)
            self.style.configure('TLabel', background=self.BG, foreground=self.FG, font=('Segoe UI', 10))
            self.style.configure('Card.TLabel', background=self.CARD_BG, foreground=self.FG, font=('Segoe UI', 10))
            self.style.configure('Muted.TLabel', background=self.CARD_BG, foreground=self.MUTED, font=('Segoe UI', 9))
            self.style.configure('Title.TLabel', background=self.BG, foreground=self.ACCENT,
                                 font=('Segoe UI', 24, 'bold'))
            self.style.configure('Subtitle.TLabel', background=self.BG, foreground=self.MUTED,
                                 font=('Segoe UI', 10))
            self.style.configure('Header.TLabel', background=self.CARD_BG, foreground=self.ACCENT,
                                 font=('Segoe UI', 11, 'bold'))
            self.style.configure('Action.TButton', background=self.BTN_BG, foreground='#000000',
                                 font=('Segoe UI', 10, 'bold'), borderwidth=0, padding=[16, 8])
            self.style.map('Action.TButton', background=[('active', '#33ccff')])
            self.style.configure('Stop.TButton', background=self.BTN_STOP, foreground='#ffffff',
                                 font=('Segoe UI', 10, 'bold'), borderwidth=0, padding=[16, 8])
            self.style.map('Stop.TButton', background=[('active', '#ff7777')])
            self.style.configure('Small.TButton', background=self.ENTRY_BG, foreground=self.ACCENT,
                                 font=('Segoe UI', 9), borderwidth=0, padding=[10, 5])
            self.style.map('Small.TButton', background=[('active', self.BORDER)])
            self.style.configure('TCombobox', fieldbackground=self.ENTRY_BG, background=self.ENTRY_BG,
                                 foreground=self.FG, font=('Consolas', 10))
            self.style.configure('Horizontal.TProgressbar', background=self.ACCENT, troughcolor=self.ENTRY_BG)

        def _build_ui(self):
            header = ttk.Frame(self.root)
            header.pack(fill='x', padx=20, pady=(15, 5))
            ttk.Label(header, text="CrackVault", style='Title.TLabel').pack(side='left')
            ttk.Label(header, text="v2.0  |  Password Cracker for Ethical Hacking  |  Netanix lab",
                      style='Subtitle.TLabel').pack(side='left', padx=(15, 0), pady=(8, 0))

            self.notebook = ttk.Notebook(self.root)
            self.notebook.pack(fill='both', expand=True, padx=20, pady=(5, 0))

            self._build_hash_crack_tab()
            self._build_shadow_crack_tab()
            self._build_file_crack_tab()
            self._build_hash_gen_tab()
            self._build_hash_id_tab()
            self._build_history_tab()
            self._build_status_bar()

        def _card(self, parent):
            return tk.Frame(parent, bg=self.CARD_BG, bd=0, highlightthickness=1,
                            highlightbackground=self.BORDER, highlightcolor=self.BORDER)

        def _entry(self, parent, width=50):
            return tk.Entry(parent, bg=self.ENTRY_BG, fg=self.FG, insertbackground=self.ACCENT,
                            font=('Consolas', 11), relief='flat', bd=8, width=width,
                            selectbackground=self.ACCENT, selectforeground='#000000')

        def _label(self, parent, text, **kw):
            return tk.Label(parent, text=text, bg=self.CARD_BG, fg=self.FG, font=('Segoe UI', 10), **kw)

        def _header_label(self, parent, text):
            return tk.Label(parent, text=text, bg=self.CARD_BG, fg=self.ACCENT, font=('Segoe UI', 11, 'bold'))

        def _muted_label(self, parent, text):
            return tk.Label(parent, text=text, bg=self.CARD_BG, fg=self.MUTED, font=('Segoe UI', 9))

        def _output(self, parent, height=12):
            return scrolledtext.ScrolledText(parent, bg='#0c1018', fg=self.GREEN,
                                              font=('Consolas', 10), relief='flat', bd=8,
                                              insertbackground=self.FG, height=height, wrap='word',
                                              selectbackground=self.ACCENT, selectforeground='#000000')

        def _action_btn(self, parent, text, command):
            return ttk.Button(parent, text=text, style='Action.TButton', command=command)

        def _stop_btn(self, parent, text, command):
            return ttk.Button(parent, text=text, style='Stop.TButton', command=command)

        def _browse(self, entry, ftypes=None):
            if ftypes is None:
                ftypes = [('Text files', '*.txt'), ('All', '*.*')]
            path = filedialog.askopenfilename(filetypes=ftypes)
            if path:
                entry.delete(0, 'end')
                entry.insert(0, path)

        def _log(self, widget, text, clear=False):
            widget.config(state='normal')
            if clear:
                widget.delete('1.0', 'end')
            widget.insert('end', text + '\n')
            widget.see('end')
            widget.config(state='disabled')

        def _status(self, text):
            self.status_label.config(text=text)

        def _get_charset(self):
            cs = self.charset_var.get()
            if cs == 'lowercase': return string.ascii_lowercase
            elif cs == 'uppercase': return string.ascii_uppercase
            elif cs == 'digits': return string.digits
            elif cs == 'lowercase+digits': return string.ascii_lowercase + string.digits
            else: return string.ascii_lowercase + string.ascii_uppercase + string.digits + '!@#$%'

        def _hash_progress_cb(self, current, total, word, found):
            if total > 0:
                self.progress_var.set((current / total) * 100)
            self.root.after(0, lambda: self._status(f"Trying: {word}  |  Attempts: {current:,}"))

        def _shadow_progress_cb(self, current, total, word, found):
            if total > 0:
                self.shadow_progress_var.set((current / total) * 100)
            self.root.after(0, lambda: self._status(f"Trying: {word}  |  Attempts: {current:,}"))

        def _file_progress_cb(self, current, total, word, found):
            if total > 0:
                self.file_progress_var.set((current / total) * 100)
            self.root.after(0, lambda: self._status(f"Trying: {word}  |  Attempts: {current:,}"))

        # === TAB 1: HASH CRACK ===
        def _build_hash_crack_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  Hash Crack  ')
            card = self._card(tab)
            card.pack(fill='x', padx=8, pady=(12, 6))
            inner = tk.Frame(card, bg=self.CARD_BG)
            inner.pack(fill='x', padx=15, pady=12)

            row0 = tk.Frame(inner, bg=self.CARD_BG); row0.pack(fill='x', pady=(0, 8))
            self._header_label(row0, "Target Hash").pack(side='left')
            self.hash_entry = self._entry(row0, width=72)
            self.hash_entry.pack(side='left', padx=(15, 0), fill='x', expand=True)

            row1 = tk.Frame(inner, bg=self.CARD_BG); row1.pack(fill='x', pady=(0, 8))
            self._label(row1, "Algorithm").pack(side='left')
            algo_list = sorted(HashEngine.supported_algorithms()) + ['ntlm']
            self.algo_var = tk.StringVar(value='md5')
            ttk.Combobox(row1, textvariable=self.algo_var, state='readonly', width=14,
                         values=algo_list).pack(side='left', padx=(10, 30))
            self._label(row1, "Attack Mode").pack(side='left')
            self.attack_var = tk.StringVar(value='Wordlist')
            ttk.Combobox(row1, textvariable=self.attack_var, state='readonly', width=14,
                         values=['Wordlist', 'Brute Force', 'Rule-Based']).pack(side='left', padx=(10, 0))

            row2 = tk.Frame(inner, bg=self.CARD_BG); row2.pack(fill='x', pady=(0, 8))
            self._label(row2, "Wordlist").pack(side='left')
            self.wl_entry = self._entry(row2, width=52)
            self.wl_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            ttk.Button(row2, text="Browse", style='Small.TButton',
                       command=lambda: self._browse(self.wl_entry)).pack(side='left')

            row3 = tk.Frame(inner, bg=self.CARD_BG); row3.pack(fill='x', pady=(0, 8))
            self._label(row3, "Keywords").pack(side='left')
            self.kw_entry = self._entry(row3, width=40)
            self.kw_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            self._muted_label(row3, "words to try first (space or comma separated)").pack(side='left')

            row4 = tk.Frame(inner, bg=self.CARD_BG); row4.pack(fill='x')
            self._muted_label(row4, "Brute Force:").pack(side='left')
            self._label(row4, "Min Len").pack(side='left', padx=(10, 0))
            self.bf_min = tk.Spinbox(row4, from_=1, to=8, width=3, bg=self.ENTRY_BG, fg=self.FG,
                                     font=('Consolas', 10), relief='flat', bd=4)
            self.bf_min.pack(side='left', padx=5)
            self._label(row4, "Max Len").pack(side='left', padx=(10, 0))
            self.bf_max = tk.Spinbox(row4, from_=1, to=8, width=3, bg=self.ENTRY_BG, fg=self.FG,
                                     font=('Consolas', 10), relief='flat', bd=4)
            self.bf_max.delete(0, 'end'); self.bf_max.insert(0, '4')
            self.bf_max.pack(side='left', padx=5)
            self._label(row4, "Charset").pack(side='left', padx=(15, 0))
            self.charset_var = tk.StringVar(value='lowercase')
            ttk.Combobox(row4, textvariable=self.charset_var, state='readonly', width=16,
                         values=['lowercase', 'uppercase', 'digits', 'lowercase+digits',
                                 'all printable']).pack(side='left', padx=5)

            btn_row = tk.Frame(tab, bg=self.BG); btn_row.pack(fill='x', padx=8, pady=6)
            self._action_btn(btn_row, "  START CRACK  ", self._start_hash_crack).pack(side='left', padx=(0, 8))
            self._stop_btn(btn_row, "  STOP  ", self._stop_attack).pack(side='left')
            self.hash_speed_lbl = tk.Label(btn_row, text="", bg=self.BG, fg=self.GREEN,
                                            font=('Consolas', 10, 'bold'))
            self.hash_speed_lbl.pack(side='right', padx=10)

            self.progress_var = tk.DoubleVar()
            ttk.Progressbar(tab, variable=self.progress_var, maximum=100,
                            style='Horizontal.TProgressbar').pack(fill='x', padx=8, pady=(0, 6))
            self.hash_output = self._output(tab)
            self.hash_output.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # === TAB 2: SHADOW CRACK ===
        def _build_shadow_crack_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  Shadow Crack  ')
            card = self._card(tab)
            card.pack(fill='x', padx=8, pady=(12, 6))
            inner = tk.Frame(card, bg=self.CARD_BG)
            inner.pack(fill='x', padx=15, pady=12)

            row0 = tk.Frame(inner, bg=self.CARD_BG); row0.pack(fill='x', pady=(0, 8))
            self._header_label(row0, "Shadow / Crypt Hash Cracker").pack(side='left')
            self._muted_label(row0, "  bcrypt  yescrypt  SHA-crypt  MD5-crypt  scrypt").pack(side='left', padx=15)

            row1 = tk.Frame(inner, bg=self.CARD_BG); row1.pack(fill='x', pady=(0, 8))
            self._label(row1, "Mode").pack(side='left')
            self.shadow_mode_var = tk.StringVar(value='Single Hash')
            ttk.Combobox(row1, textvariable=self.shadow_mode_var, state='readonly', width=16,
                         values=['Single Hash', 'Shadow File']).pack(side='left', padx=(10, 20))
            self._label(row1, "Target User(s)").pack(side='left')
            self.shadow_users_entry = self._entry(row1, width=30)
            self.shadow_users_entry.pack(side='left', padx=(10, 10))
            self._muted_label(row1, "optional, comma-separated").pack(side='left')

            row2 = tk.Frame(inner, bg=self.CARD_BG); row2.pack(fill='x', pady=(0, 8))
            self._label(row2, "Hash / File").pack(side='left')
            self.shadow_hash_entry = self._entry(row2, width=60)
            self.shadow_hash_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            ttk.Button(row2, text="Browse", style='Small.TButton',
                       command=lambda: self._browse(self.shadow_hash_entry,
                                                    [('Shadow', '*'), ('Text', '*.txt'), ('All', '*.*')])).pack(side='left')

            row3 = tk.Frame(inner, bg=self.CARD_BG); row3.pack(fill='x', pady=(0, 8))
            self._label(row3, "Wordlist").pack(side='left')
            self.shadow_wl_entry = self._entry(row3, width=55)
            self.shadow_wl_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            ttk.Button(row3, text="Browse", style='Small.TButton',
                       command=lambda: self._browse(self.shadow_wl_entry)).pack(side='left')

            row4 = tk.Frame(inner, bg=self.CARD_BG); row4.pack(fill='x')
            self._label(row4, "Keywords").pack(side='left')
            self.shadow_kw_entry = self._entry(row4, width=40)
            self.shadow_kw_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            self._muted_label(row4, "CRITICAL for slow hashes — target likely passwords").pack(side='left')

            btn_row = tk.Frame(tab, bg=self.BG); btn_row.pack(fill='x', padx=8, pady=6)
            self._action_btn(btn_row, "  CRACK SHADOW  ", self._start_shadow_crack).pack(side='left', padx=(0, 8))
            self._stop_btn(btn_row, "  STOP  ", self._stop_attack).pack(side='left')
            self.shadow_speed_lbl = tk.Label(btn_row, text="", bg=self.BG, fg=self.GREEN,
                                              font=('Consolas', 10, 'bold'))
            self.shadow_speed_lbl.pack(side='right', padx=10)

            self.shadow_progress_var = tk.DoubleVar()
            ttk.Progressbar(tab, variable=self.shadow_progress_var, maximum=100,
                            style='Horizontal.TProgressbar').pack(fill='x', padx=8, pady=(0, 6))
            self.shadow_output = self._output(tab)
            self.shadow_output.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # === TAB 3: FILE CRACK ===
        def _build_file_crack_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  File Crack  ')
            card = self._card(tab)
            card.pack(fill='x', padx=8, pady=(12, 6))
            inner = tk.Frame(card, bg=self.CARD_BG)
            inner.pack(fill='x', padx=15, pady=12)

            row0 = tk.Frame(inner, bg=self.CARD_BG); row0.pack(fill='x', pady=(0, 8))
            self._header_label(row0, "File Type").pack(side='left')
            self.file_type_var = tk.StringVar(value='ZIP')
            ttk.Combobox(row0, textvariable=self.file_type_var, state='readonly', width=12,
                         values=['ZIP', 'RAR', '7-Zip', 'PDF', 'Office', 'KeePass']).pack(side='left', padx=15)
            self._muted_label(row0, "ZIP  RAR  7z  PDF  Office(.docx/.xlsx/.pptx)  KeePass(.kdbx)").pack(side='left')

            row1 = tk.Frame(inner, bg=self.CARD_BG); row1.pack(fill='x', pady=(0, 8))
            self._label(row1, "Target File").pack(side='left')
            self.file_entry = self._entry(row1, width=55)
            self.file_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            ttk.Button(row1, text="Browse", style='Small.TButton',
                       command=lambda: self._browse(self.file_entry,
                                                    [('ZIP', '*.zip'), ('RAR', '*.rar'), ('7z', '*.7z'),
                                                     ('PDF', '*.pdf'), ('Office', '*.docx *.xlsx *.pptx'),
                                                     ('KeePass', '*.kdbx'), ('All', '*.*')])).pack(side='left')

            row2 = tk.Frame(inner, bg=self.CARD_BG); row2.pack(fill='x', pady=(0, 8))
            self._label(row2, "Wordlist").pack(side='left')
            self.file_wl_entry = self._entry(row2, width=55)
            self.file_wl_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            ttk.Button(row2, text="Browse", style='Small.TButton',
                       command=lambda: self._browse(self.file_wl_entry)).pack(side='left')

            row3 = tk.Frame(inner, bg=self.CARD_BG); row3.pack(fill='x')
            self._label(row3, "Keywords").pack(side='left')
            self.file_kw_entry = self._entry(row3, width=40)
            self.file_kw_entry.pack(side='left', padx=(10, 10), fill='x', expand=True)
            self._muted_label(row3, "words to try first (space or comma separated)").pack(side='left')

            btn_row = tk.Frame(tab, bg=self.BG); btn_row.pack(fill='x', padx=8, pady=6)
            self._action_btn(btn_row, "  CRACK FILE  ", self._start_file_crack).pack(side='left', padx=(0, 8))
            self._stop_btn(btn_row, "  STOP  ", self._stop_attack).pack(side='left')
            self.file_speed_lbl = tk.Label(btn_row, text="", bg=self.BG, fg=self.GREEN,
                                            font=('Consolas', 10, 'bold'))
            self.file_speed_lbl.pack(side='right', padx=10)

            self.file_progress_var = tk.DoubleVar()
            ttk.Progressbar(tab, variable=self.file_progress_var, maximum=100,
                            style='Horizontal.TProgressbar').pack(fill='x', padx=8, pady=(0, 6))
            self.file_output = self._output(tab)
            self.file_output.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # === TAB 4: HASH GENERATOR ===
        def _build_hash_gen_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  Hash Generator  ')
            card = self._card(tab)
            card.pack(fill='x', padx=8, pady=(12, 6))
            inner = tk.Frame(card, bg=self.CARD_BG)
            inner.pack(fill='x', padx=15, pady=12)
            self._header_label(inner, "Enter text to generate all hash types (incl. NTLM)").pack(anchor='w')
            row = tk.Frame(inner, bg=self.CARD_BG); row.pack(fill='x', pady=(8, 0))
            self.gen_entry = self._entry(row, width=60)
            self.gen_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
            self._action_btn(row, "  GENERATE  ", self._generate_hashes).pack(side='left')
            self.gen_output = self._output(tab, height=20)
            self.gen_output.pack(fill='both', expand=True, padx=8, pady=(6, 8))

        # === TAB 5: HASH IDENTIFIER ===
        def _build_hash_id_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  Identify Hash  ')
            card = self._card(tab)
            card.pack(fill='x', padx=8, pady=(12, 6))
            inner = tk.Frame(card, bg=self.CARD_BG)
            inner.pack(fill='x', padx=15, pady=12)
            self._header_label(inner, "Paste a hash to identify its algorithm (supports crypt-style)").pack(anchor='w')
            row = tk.Frame(inner, bg=self.CARD_BG); row.pack(fill='x', pady=(8, 0))
            self.id_entry = self._entry(row, width=70)
            self.id_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
            self._action_btn(row, "  IDENTIFY  ", self._identify_hash).pack(side='left')
            self.id_output = self._output(tab, height=18)
            self.id_output.pack(fill='both', expand=True, padx=8, pady=(6, 8))

        # === TAB 6: HISTORY ===
        def _build_history_tab(self):
            tab = tk.Frame(self.notebook, bg=self.BG)
            self.notebook.add(tab, text='  History  ')
            btn_row = tk.Frame(tab, bg=self.BG); btn_row.pack(fill='x', padx=8, pady=(12, 6))
            self._action_btn(btn_row, "  REFRESH  ", self._refresh_history).pack(side='left', padx=(0, 8))
            self._stop_btn(btn_row, "  CLEAR ALL  ", self._clear_history).pack(side='left')
            self.history_count_lbl = tk.Label(btn_row, text="0 entries", bg=self.BG, fg=self.MUTED,
                                              font=('Segoe UI', 10))
            self.history_count_lbl.pack(side='right', padx=10)
            self.history_output = self._output(tab, height=22)
            self.history_output.pack(fill='both', expand=True, padx=8, pady=(0, 8))
            self._refresh_history()

        # === STATUS BAR ===
        def _build_status_bar(self):
            bar = tk.Frame(self.root, bg=self.CARD_BG, height=32)
            bar.pack(fill='x', side='bottom')
            bar.pack_propagate(False)
            self.status_label = tk.Label(bar, text="Ready", bg=self.CARD_BG, fg=self.MUTED, font=('Segoe UI', 9))
            self.status_label.pack(side='left', padx=20, pady=6)
            self.status_right = tk.Label(bar, text="CrackVault v2.0  |  Netanix lab", bg=self.CARD_BG, fg=self.BORDER,
                                          font=('Segoe UI', 9))
            self.status_right.pack(side='right', padx=20, pady=6)

        # === ACTIONS ===
        def _start_hash_crack(self):
            target = self.hash_entry.get().strip()
            if not target:
                messagebox.showwarning("CrackVault", "Enter a target hash."); return
            algo = self.algo_var.get()
            mode = self.attack_var.get()
            kw_text = self.kw_entry.get().strip()
            if kw_text:
                self.keyword_filter.set_keywords(kw_text)
            else:
                self.keyword_filter = KeywordFilter()

            self._log(self.hash_output, "", clear=True)
            self._log(self.hash_output, f"  CrackVault  -  {mode}")
            self._log(self.hash_output, f"  Algorithm    : {algo}")
            self._log(self.hash_output, f"  Target       : {target[:50]}{'...' if len(target) > 50 else ''}")
            if kw_text:
                self._log(self.hash_output, f"  Keywords     : {kw_text}")
            self._log(self.hash_output, f"{'_' * 60}\n")
            self.progress_var.set(0)
            self.hash_speed_lbl.config(text="")

            def run():
                if algo == 'ntlm':
                    wl = self.wl_entry.get().strip()
                    if not wl:
                        self.root.after(0, lambda: messagebox.showwarning("CrackVault", "Select a wordlist.")); return
                    attack = NTLMCracker(callback=self._hash_progress_cb)
                    self.current_attack = attack
                    result = attack.crack_hash(target, wl, self.keyword_filter)
                elif mode == 'Wordlist':
                    wl = self.wl_entry.get().strip()
                    if not wl:
                        self.root.after(0, lambda: messagebox.showwarning("CrackVault", "Select a wordlist.")); return
                    attack = WordlistAttack(callback=self._hash_progress_cb)
                    self.current_attack = attack
                    result = attack.crack_hash(target, algo, wl, self.keyword_filter)
                elif mode == 'Brute Force':
                    charset = self._get_charset()
                    mn, mx = int(self.bf_min.get()), int(self.bf_max.get())
                    attack = BruteForceAttack(callback=self._hash_progress_cb)
                    self.current_attack = attack
                    result = attack.crack_hash(target, algo, charset, mn, mx)
                else:
                    wl = self.wl_entry.get().strip()
                    if not wl:
                        self.root.after(0, lambda: messagebox.showwarning("CrackVault", "Select a wordlist.")); return
                    attack = RuleBasedAttack(callback=self._hash_progress_cb)
                    self.current_attack = attack
                    result = attack.crack_hash(target, algo, wl, self.keyword_filter)
                self.session_log.add(result)
                self.root.after(0, lambda: self._show_result(result, self.hash_output, self.hash_speed_lbl))

            self.attack_thread = threading.Thread(target=run, daemon=True)
            self.attack_thread.start()
            self._status("Cracking...")

        def _start_shadow_crack(self):
            hash_or_file = self.shadow_hash_entry.get().strip()
            wl = self.shadow_wl_entry.get().strip()
            if not hash_or_file or not wl:
                messagebox.showwarning("CrackVault", "Enter a hash/file and wordlist."); return
            mode = self.shadow_mode_var.get()
            kw_text = self.shadow_kw_entry.get().strip()
            users_text = self.shadow_users_entry.get().strip()
            target_users = [u.strip() for u in users_text.split(',') if u.strip()] if users_text else None
            kw_filter = KeywordFilter()
            if kw_text:
                kw_filter.set_keywords(kw_text)

            self._log(self.shadow_output, "", clear=True)
            self._log(self.shadow_output, f"  CrackVault  -  Shadow/Crypt Cracker")
            self._log(self.shadow_output, f"  Mode         : {mode}")
            if kw_text:
                self._log(self.shadow_output, f"  Keywords     : {kw_text}")
            if target_users:
                self._log(self.shadow_output, f"  Target Users : {', '.join(target_users)}")
            self._log(self.shadow_output, f"{'_' * 60}\n")
            self.shadow_progress_var.set(0)
            self.shadow_speed_lbl.config(text="")

            def run():
                def slog(msg):
                    self.root.after(0, lambda m=msg: self._log(self.shadow_output, m))

                if mode == 'Shadow File':
                    cracker = ShadowFileCracker(callback=self._shadow_progress_cb, log_callback=slog)
                    self.current_attack = cracker
                    results = cracker.crack_file(hash_or_file, wl, kw_filter, target_users)
                    for r in results:
                        self.session_log.add(r)
                    fc = sum(1 for r in results if r.found)
                    ta = sum(r.attempts for r in results)
                    self.root.after(0, lambda: self._log(self.shadow_output, f"\n{'=' * 60}"))
                    self.root.after(0, lambda: self._log(self.shadow_output,
                                                          f"  SUMMARY: {fc}/{len(results)} cracked  |  {ta:,} total attempts"))
                    for r in results:
                        if r.found:
                            self.root.after(0, lambda r=r: self._log(self.shadow_output, f"  [+] {r.method}: {r.password}"))
                    self.root.after(0, lambda: self._log(self.shadow_output, f"{'=' * 60}"))
                    self.root.after(0, lambda: self._status(f"Shadow crack done: {fc}/{len(results)} cracked"))
                else:
                    entry = ShadowParser.parse_shadow_line(hash_or_file)
                    if not entry or not entry.full_hash:
                        self.root.after(0, lambda: self._log(self.shadow_output, "[!] Could not parse hash."))
                        self.root.after(0, lambda: self._status("Error: Could not parse hash")); return
                    cracker = CryptCracker(callback=self._shadow_progress_cb, log_callback=slog)
                    self.current_attack = cracker
                    result = cracker.crack(entry, wl, kw_filter)
                    self.session_log.add(result)
                    self.root.after(0, lambda: self._show_result(result, self.shadow_output, self.shadow_speed_lbl))

            self.attack_thread = threading.Thread(target=run, daemon=True)
            self.attack_thread.start()
            self._status("Cracking shadow hashes...")

        def _start_file_crack(self):
            file_path = self.file_entry.get().strip()
            wl = self.file_wl_entry.get().strip()
            if not file_path or not wl:
                messagebox.showwarning("CrackVault", "Select both a target file and wordlist."); return
            ftype = self.file_type_var.get()
            kw_text = self.file_kw_entry.get().strip()
            kw_filter = KeywordFilter()
            if kw_text:
                kw_filter.set_keywords(kw_text)

            self._log(self.file_output, "", clear=True)
            self._log(self.file_output, f"  CrackVault  -  {ftype} File Crack")
            self._log(self.file_output, f"  File         : {os.path.basename(file_path)}")
            self._log(self.file_output, f"  Wordlist     : {os.path.basename(wl)}")
            if kw_text:
                self._log(self.file_output, f"  Keywords     : {kw_text}")
            self._log(self.file_output, f"{'_' * 60}\n")
            self.file_progress_var.set(0)
            self.file_speed_lbl.config(text="")

            def run():
                def flog(msg):
                    self.root.after(0, lambda m=msg: self._log(self.file_output, m))

                crackers = {'ZIP': ZipCracker, 'RAR': RARCracker, '7-Zip': SevenZipCracker,
                            'PDF': PDFCracker, 'Office': OfficeCracker, 'KeePass': KeePassCracker}
                cls = crackers.get(ftype)
                if not cls: return
                attack = cls(callback=self._file_progress_cb, log_callback=flog)
                self.current_attack = attack
                result = attack.crack(file_path, wl, kw_filter)
                self.session_log.add(result)
                self.root.after(0, lambda: self._show_result(result, self.file_output, self.file_speed_lbl))

            self.attack_thread = threading.Thread(target=run, daemon=True)
            self.attack_thread.start()
            self._status(f"Cracking {ftype} file...")

        def _show_result(self, result, output, speed_label):
            self._log(output, f"\n{'=' * 60}")
            if result.found:
                self._log(output, f"  PASSWORD FOUND:  {result.password}")
                self._log(output, f"  {'=' * 56}")
            else:
                self._log(output, f"  PASSWORD NOT FOUND")
            self._log(output, f"  Method   : {result.method}")
            self._log(output, f"  Attempts : {result.attempts:,}")
            self._log(output, f"  Time     : {result.elapsed:.3f} seconds")
            self._log(output, f"  Speed    : {result.speed:,.0f} passwords/sec")
            self._log(output, f"{'=' * 60}")
            if result.found:
                self._status(f"CRACKED: {result.password}")
                speed_label.config(text=f"{result.speed:,.0f} pwd/s  |  {result.attempts:,} attempts")
            else:
                self._status("Not found. Try a larger wordlist or different attack mode.")
                speed_label.config(text="")

        def _stop_attack(self):
            if self.current_attack:
                self.current_attack.stop()
                self._status("Stopped by user.")

        def _generate_hashes(self):
            text = self.gen_entry.get().strip()
            if not text:
                messagebox.showwarning("CrackVault", "Enter text to hash."); return
            results = HashGenerator.generate_all(text)
            self._log(self.gen_output, f"  Hashes for: '{text}'\n{'=' * 60}", clear=True)
            for algo, h in sorted(results.items()):
                self._log(self.gen_output, f"  {algo:12s}  {h}")
            self._log(self.gen_output, f"{'=' * 60}")

        def _identify_hash(self):
            h = self.id_entry.get().strip()
            if not h:
                messagebox.showwarning("CrackVault", "Paste a hash to identify."); return
            matches = HashEngine.identify_hash(h)
            self._log(self.id_output, f"  Hash   : {h}\n  Length : {len(h)} characters\n{'=' * 60}", clear=True)
            if matches:
                self._log(self.id_output, "  Possible algorithms:")
                for m in matches:
                    self._log(self.id_output, f"    ->  {m}")
            else:
                self._log(self.id_output, "  No matching algorithm found for this hash length.")
            self._log(self.id_output, f"{'=' * 60}")

        def _refresh_history(self):
            entries = self.session_log.get_all()
            self.history_count_lbl.config(text=f"{len(entries)} entries")
            self._log(self.history_output, f"  Session History\n{'=' * 60}", clear=True)
            if not entries:
                self._log(self.history_output, "  No history yet. Start cracking!")
            else:
                for e in entries:
                    status = "CRACKED" if e['found'] else "FAILED"
                    self._log(self.history_output,
                              f"  [{e['time']}]  {status:8s}  |  {e['method']:20s}  |  "
                              f"Password: {e['password']:16s}  |  {e['attempts']} attempts  |  "
                              f"{e['elapsed']}  |  {e['speed']}")
            self._log(self.history_output, f"{'=' * 60}")

        def _clear_history(self):
            if messagebox.askyesno("CrackVault", "Clear all session history?"):
                self.session_log.clear()
                self._refresh_history()
                self._status("History cleared.")

        def run(self):
            self.root.mainloop()


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    app = CrackVaultApp()
    app.run()
