# Effuse - AES-256 File Encryption Utility (v1)
# Copyright (C) 2025 Arshit Vora
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
- Per-file random salt stored in header
- PBKDF2 iterations stored in header
- PEM key handling: full PEM payload hashed (SHA-256) to derive AES-256 key
- CLI: encrypt/decrypt/info, key generation, --key to use PEM
"""

import os
import sys
import base64
import getpass
import mimetypes
import argparse
import struct
import time
import random

from rich import print
from rich.prompt import Prompt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2

# --- File header format (binary) ---
# MAGIC (6 bytes)           = b'EFFUSE'
# VERSION (2 bytes)         = b'v1'
# ITER (4 bytes BE)         = PBKDF2 iterations (uint32)
# SALT_LEN (1 byte)         = length of salt (uint8)
# SALT (salt_len bytes)
# IV (16 bytes)
# CIPHERTEXT (rest)

# Encrypted plaintext layout (before padding/encrypt):
# [1 byte ext_len][ext bytes][original file bytes...]

MAGIC = b"EFFUSE"       # 6 bytes
VERSION = "v1"          # 2 bytes
SALT_LEN = 16           # 16 bytes salt (128 bits)

# ---------- file type detection ----------
def detect_file_type(data, fallback_name=""):
    """
    First try magic signatures (content-based).
    Then try mimetypes.guess_type on filename.
    Then fallback to filename extension.
    """
    signatures = [
        (b"%PDF", ".pdf"),
        (b"\x89PNG\r\n\x1a\n", ".png"),
        (b"\xFF\xD8\xFF", ".jpg"),
        (b"PK\x03\x04", ".zip"),
        (b"Rar!\x1A\x07\x00", ".rar"),
        (b"\x1A\x45\xDF\xA3", ".mkv"),
        (b"\x00\x00\x00\x18ftypmp42", ".mp4"),
        (b"\x00\x00\x00\x14ftypisom", ".mp4"),
        (b"OggS", ".ogg"),
        (b"ID3", ".mp3"),
        (b"\xD0\xCF\x11\xE0", ".doc"),
        (b"\x50\x4B\x03\x04", ".docx")
    ]
    for sig, ext in signatures:
        if data.startswith(sig):
            return ext

    mime_type, _ = mimetypes.guess_type(fallback_name)
    if mime_type:
        guessed_ext = mimetypes.guess_extension(mime_type)
        if guessed_ext:
            return guessed_ext

    return os.path.splitext(fallback_name)[1]

# ---------- key derivation ----------
def derive_key_from_password(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """
    Derive a 32-byte AES key from a password and salt using PBKDF2-HMAC-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# ---------- parse PEM key ----------
def get_key_from_pem(pem_file: str) -> bytes:
    """
    Read PEM, remove headers/footers, base64-decode the middle, hash with SHA-256,
    return 32-byte AES key. This uses the entire PEM content as entropy.
    """
    with open(pem_file, 'rb') as f:
        raw = f.read()
    key_data = b"".join(line for line in raw.splitlines() if not line.startswith(b"-----"))
    try:
        decoded = base64.b64decode(key_data, validate=True)
    except Exception:
        decoded = raw
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(decoded)
    return digest.finalize()

# ---------- PEM key generation ----------
def generate_pem_key(file_source):
    """
    Generate an RSA PEM using the file_source as entropy.
    Writes 'key.pem' in current directory.
    """
    try:
        with open(file_source, 'rb') as f:
            f.seek(1024)
            salt = f.read(32)
            if len(salt) < 32:
                print(f"[red][!] Error: Source file '{file_source}' is too small (must be > 1KB).[/red]")
                return
    except FileNotFoundError:
        print(f"[red][!] Error: File not found '{file_source}'.[/red]")
        return
    except Exception as e:
        print(f"[red][!] Error reading file: {e}[/red]")
        return

    password = Prompt.ask("[cyan]Enter password for key generation[/cyan]", password=True)
    master = PBKDF2(password.encode(), salt, count=10000)

# Non-random function for keeping the RSA generation static every time with same input
# If we used os.urandom, the key would differ each time and encryption/decryption would fail
    def notrand(n):
        notrand.i += 1
        return PBKDF2(master, str(notrand.i).encode(), dkLen=n, count=1)

    notrand.i = 0
    print("[yellow]Generating RSA key: In progress...[/yellow]", end="", flush=True)
    RSA_key = None
    while notrand.i < 100:
        RSA_key = RSA.generate(4096, randfunc=notrand)
        time.sleep(0.01)
        print(".", end="", flush=True)
    print("\n[green]Key generation completed.[/green]")
    with open("key.pem", "wb") as key_file:
        key_file.write(RSA_key.export_key("PEM"))
    print("[green]Key exported to key.pem[/green]")

# ---------- Writing Data ----------
def write_encrypted_file(new_filepath: str, iterations: int, salt: bytes, iv: bytes, ciphertext: bytes):
    """
    Write full file with header (MAGIC[8] | VERSION[1] | iterations[4] | salt_len[1] | salt | iv[16] | ciphertext)
    """
    with open(new_filepath, 'wb') as out:
        out.write(MAGIC)                            # 6 bytes MAGIC
        out.write(VERSION.encode())                 # 2 bytes version
        out.write(struct.pack(">I", iterations))    # 4 bytes BE
        out.write(bytes([len(salt)]))               # 1 byte salt len
        out.write(salt)
        out.write(iv)                               # 16 bytes IV
        out.write(ciphertext)

# ---------- Information ----------
def read_header_and_extract(filepath: str):
    """
    Read and require header. If header missing or invalid, raise an error.
    Returns (iterations, salt, iv, ciphertext)
    """
    with open(filepath, 'rb') as f:
        start = f.read(len(MAGIC))
        if start != MAGIC:
            raise ValueError("Missing header — file not recognized")
        version_b = f.read(2)
        version = version_b.decode()
        if version != VERSION:
            raise ValueError("Corrupted file header.")
        iter_bytes = f.read(4)
        iterations = struct.unpack(">I", iter_bytes)[0]
        salt_len_b = f.read(1)
        salt_len = salt_len_b[0]
        salt = f.read(salt_len)
        iv = f.read(16)
        ciphertext = f.read()
        return iterations, salt, iv, ciphertext

# ---------- Encryption ----------
def encrypt_file(filepath: str, password_or_key: bytes, use_pem_key: bool = False):
    """
    If use_pem_key is True, password_or_key is the raw 32-byte AES key (from PEM hashing).
    If False, password_or_key is a string password and will be used with per-file salt.
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    ext = detect_file_type(data, filepath).encode()
    ext_len = struct.pack("B", len(ext))
    plaintext = ext_len + ext + data

    # Generate per-file salt and derive key if password mode
    salt = os.urandom(SALT_LEN)
    iterations = random.randint(100000, 600000)

    if use_pem_key:
        key = password_or_key
    else:
        key = derive_key_from_password(password_or_key, salt, iterations)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    base_name = os.path.splitext(filepath)[0]
    new_filepath = base_name + ".eff"

    write_encrypted_file(new_filepath, iterations, salt, iv, ciphertext)

    print(f"[green][+] Encrypted:[/green] {filepath} -> [yellow]{new_filepath}[/yellow]")
    try:
        os.remove(filepath)
        print(f"[blue][i] Removed original file:[/blue] [red]{filepath}[/red]")
    except Exception as e:
        print(f"[yellow][!] Warning: could not remove original file: {e}[/yellow]")

# ---------- Decryption ----------
def decrypt_file(filepath: str, password_or_key: bytes, use_pem_key: bool = False):
    """
    If use_pem_key is True, password_or_key is the raw 32-byte AES key (from PEM hashing).
    If False, password_or_key is the password string (will derive per-file using header salt).
    """
    try:
        iterations, salt, iv, ciphertext = read_header_and_extract(filepath)
    except Exception as e:
        print(f"[red][!] Error: {e}[/red]")
        return

    if use_pem_key:
        key = password_or_key
    else:
        key = derive_key_from_password(password_or_key, salt, iterations)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
    except Exception:
        print("[red][!] Error: Decryption failed. Wrong password/key or corrupted file.[/red]")
        return

    if len(data) < 1:
        print("[red][!] Error: Decrypted payload too small.[/red]")
        return

    ext_len = data[0]
    ext = data[1:1+ext_len].decode()
    plain_data = data[1+ext_len:]

    base_name = os.path.splitext(filepath)[0]
    new_filepath = base_name + ext

    with open(new_filepath, 'wb') as f:
        f.write(plain_data)
    print(f"[green][+] Decrypted:[/green] {filepath} -> [yellow]{new_filepath}[/yellow]")

    try:
        os.remove(filepath)
        print(f"[blue][i] Removed encrypted file:[/blue] [red]{filepath}[/red]")
    except Exception as e:
        print(f"[yellow][!] Warning: could not remove encrypted file: {e}[/yellow]")

# ---------- Information ----------
def show_info(filepath: str, password_or_key: bytes, use_pem_key: bool = False):
    """
    Show the stored original extension from the encrypted file after deriving key.
    Requires new header format.
    """
    try:
        iterations, salt, iv, ciphertext = read_header_and_extract(filepath)
    except Exception as e:
        print(f"[red][!] Error: {e}[/red]")
        return

    if use_pem_key:
        key = password_or_key
    else:
        key = derive_key_from_password(password_or_key, salt, iterations)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
    except Exception:
        print("[red][!] Error: Could not get info. Wrong password/key or corrupted file.[/red]")
        return

    if len(data) < 1:
        print("[red][!] Error: Decrypted payload too small.[/red]")
        return

    ext_len = data[0]
    ext = data[1:1+ext_len].decode()
    print(f"[blue][i] Original File Type:[/blue] [yellow]{ext}[/yellow]")

# ---------- CLI / argument handling ----------
class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)

        parts = []
        if action.option_strings:
            parts.append(', '.join(action.option_strings))
        if action.metavar:
            parts.append(f' {action.metavar}')
        invocation = ''.join(parts)
        return invocation

    def _get_default_metavar_for_optional(self, action):
        if action.metavar:
            return action.metavar
        return action.dest.upper()

    def _format_args(self, action, default_metavar):
        return ""

def main():
    prog_name = os.path.basename(sys.argv[0])

    parser = argparse.ArgumentParser(
        description='Effuse - AES-256 File Encryption Utility',
        formatter_class=lambda prog: CustomHelpFormatter(prog, max_help_position=80),
        prog=prog_name,
        add_help=False
    )

    arg_defs = [
        (('-h', '--help'),   {'action': 'help', 'help': 'show this help message and exit'}),
        (('-e', '--encrypt'), {'help': 'Encrypt file(s)', 'nargs': '*', 'metavar': '[FILE ...]'}),
        (('-d', '--decrypt'), {'help': 'Decrypt file(s)', 'nargs': '*', 'metavar': '[FILE ...]'}),
        (('-i', '--info'),    {'help': 'Show file type info', 'nargs': '*', 'metavar': '[FILE ...]'}),
        (('--key',),         {'help': 'Use PEM key file', 'metavar': 'KEY_FILE'}),
        (('--genkey',),      {'help': 'Generate a new PEM key from a file', 'metavar': 'SOURCE_FILE'})
    ]

    for names, options in arg_defs:
        parser.add_argument(*names, **options)

    args = parser.parse_args()

    if args.genkey:
        generate_pem_key(args.genkey)
        return

    mode = ""
    files = []
    if args.encrypt:
        mode = "encrypt"
        files = args.encrypt
    elif args.decrypt:
        mode = "decrypt"
        files = args.decrypt
    elif args.info:
        mode = "info"
        files = args.info
    else:
        parser.print_help()
        return

    use_pem_key = False
    password_or_key = None

    try:
        if args.key:
            try:
                key = get_key_from_pem(args.key)
                print("[blue][i] Using key from PEM file.[/blue]")
            except FileNotFoundError:
                print(f"[red][!] Error: Key file not found '{args.key}'.[/red]")
                return
            except Exception as e:
                print(f"[red][!] Error reading key file: {e}[/red]")
                return
            use_pem_key = True
            password_or_key = key
        else:
            password = Prompt.ask("[cyan]Enter password[/cyan]", password=True)
            if not password:
                print("[red][!] Error: Password cannot be empty.[/red]")
                return
            if mode == "encrypt":
                confirm = Prompt.ask("[cyan]Confirm password[/cyan]", password=True)
                if password != confirm:
                    print("[yellow][!] Passwords do not match.[/yellow]")
                    return
            password_or_key = password

        for file in files:
            try:
                if not os.path.exists(file):
                    print(f"[yellow][!] Warning: File not found '{file}'. Skipping.[/yellow]")
                    continue
                if mode == "encrypt":
                    encrypt_file(file, password_or_key, use_pem_key)
                elif mode == "decrypt":
                    decrypt_file(file, password_or_key, use_pem_key)
                elif mode == "info":
                    show_info(file, password_or_key, use_pem_key)

            except Exception as e:
                print(f"[red][!] Failed:[/red] {file} - {e}")

    except Exception as e:
        print(f"[red][-] A fatal error occurred:[/red] {e}")

if __name__ == "__main__":
    main()
