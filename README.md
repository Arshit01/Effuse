# Effuse - AES-256-GCM File Encryption Utility

Effuse is a robust command-line utility for secure file encryption and decryption using **AES-256-GCM**, the gold standard in authenticated encryption. It provides a flexible and highly secure method to protect your sensitive data using either a strong password or a PEM key file.

With features like per-file random salting, PBKDF2 key derivation with randomized iterations, chunked streaming for large files, HMAC-based key verification, SHA-256 header integrity checks, MIME-based file type detection, and secure deletion (shredding) of original files, Effuse ensures your information remains confidential and protected against unauthorized access and tampering.

## ✨ Features

| Feature | Description |
|---|---|
| **AES-256-GCM** | Authenticated encryption with Associated Data (AAD) for confidentiality and integrity. |
| **Chunked Streaming** | Files larger than 256 MB are processed in 128 MB chunks with per-chunk nonce derivation, enabling efficient encryption of arbitrarily large files. |
| **Password or PEM Key** | Choose between a password or a deterministically generated PEM key for encryption/decryption. |
| **PBKDF2-HMAC-SHA256** | Key derivation from password with a random salt and randomized iterations (100k–600k) per file. |
| **Tamper Detection** | Full AEAD authentication, SHA-256 header hash integrity check, and HMAC-based key verification detect any tampering or incorrect credentials. |
| **File Type Detection** | Automatically detects the original file type via MIME sniffing and restores the correct extension upon decryption. |
| **Deterministic Key Generation** | Generate a 4096-bit RSA PEM key deterministically from a source file + password for reproducible, high-entropy keys. |
| **Secure Deletion** | Original plaintext files are securely shredded (overwritten with random data, renamed, then deleted) after encryption. |
| **Custom Output** | Specify a custom output file name (`-o`) and/or destination directory (`-d`). Missing directories are created automatically. |
| **File Info** | Inspect encrypted `.eff` files to view original filename, extension, size, format version, and integrity status in a table. |
| **Multi-File Support** | Encrypt or decrypt multiple files in a single command. |
| **Cross-Platform** | Pre-built binaries for Linux, macOS, and Windows (amd64 & arm64). |

## 📦 Installation

### Download Binary (Recommended)

Download the pre-compiled binaries for your OS and architecture from the [Releases](https://github.com/Arshit01/Effuse/releases/latest) page.

1. Unzip the downloaded file.
2. Move the binary to a directory in your system `PATH`.

### Build from Source

#### Prerequisites

- **Go**: Ensure you have Go installed on your machine. You can download and install it from [go.dev/doc/install](https://go.dev/doc/install).

#### Steps

```bash
git clone https://github.com/Arshit01/Effuse.git
cd Effuse
./build.sh
```

Binaries will be created in the `dist/` directory, organized by OS and architecture:

```
dist/
├── linux/   (amd64, arm64)
├── darwin/  (amd64, arm64)
└── windows/ (amd64, arm64)
```

## 🎯 Usage

```
effuse [command] [flags] [files...]
```

### Commands

| Command | Alias | Description |
|---|---|---|
| `encrypt` | `e` | Encrypt one or more files |
| `decrypt` | `d` | Decrypt one or more `.eff` files |
| `info` | `i` | Inspect encrypted file metadata |
| `genkey` | — | Generate a PEM key from a source file |
| `help` | — | Show help for any command |

### Flags

| Flag | Description |
|---|---|
| `-o <name>` | Custom output file name |
| `-d <path>` | Destination directory (created automatically if it doesn't exist) |
| `--key <file>` | Use a PEM key file instead of a password |
| `--out` | Interactively prompt for output name per file |

---

### 🔒 Encrypt

**With Password:**
```bash
effuse e <file>
```

**With PEM Key:**
```bash
effuse e <file> --key <key.pem>
```

**With Custom Output Name:**
```bash
effuse e <file> -o myfile
# Output: myfile.eff (in the same directory as source)
```

**With Custom Destination Directory:**
```bash
effuse e <file> -d E:\Backups
# Output: E:\Backups\<original-name>.eff
```

**Combining Both:**
```bash
effuse e <file> -o report -d D:\Encrypted
# Output: D:\Encrypted\report.eff
```

**Multiple Files:**
```bash
effuse e file1.pdf file2.docx file3.zip
```

### 🔓 Decrypt

**With Password:**
```bash
effuse d <file.eff>
```

**With PEM Key:**
```bash
effuse d <file.eff> --key <key.pem>
```

**To a Specific Directory:**
```bash
effuse d <file.eff> -d D:\Restored
```

### 🗝️ Generate a PEM Key

```bash
effuse genkey <source-file>
```

The source file provides entropy. You will be prompted for a password which acts as the KDF master seed. The combination of source file + password deterministically generates a 4096-bit RSA key.

**Custom Output Name:**
```bash
effuse genkey <source-file> -o mykey.pem
```

### 📊 Inspect File Info

```bash
effuse i <file.eff>
```

Displays a table with the original filename, detected extension, original file size, format version, and integrity status (`OK`, `CORRUPTED`, or `INCORRECT KEY/PASSWORD`).

**Multiple Files:**
```bash
effuse i file1.eff file2.eff file3.eff
```

## 🏗️ File Format (v2)

The `.eff` file format uses a custom binary header followed by encrypted data.

### Header Layout

```
MAGIC(6) | VERSION(2) | ITER(4) | SALT_LEN(1) | SALT(var) | NONCE(12) | KEY_CHECK(32) | META_LEN(4) | ORIGINAL_SIZE(8) | CHUNK_SIZE(4) | HEADER_HASH(32)
```

| Field | Size | Description |
|---|---|---|
| `MAGIC` | 6 bytes | `EFFUSE` — file signature |
| `VERSION` | 2 bytes | `v2` — format version |
| `ITER` | 4 bytes | PBKDF2 iteration count (uint32, Big Endian) |
| `SALT_LEN` | 1 byte | Length of the salt |
| `SALT` | variable | Random salt for key derivation |
| `NONCE` | 12 bytes | GCM nonce (base nonce for chunked mode) |
| `KEY_CHECK` | 32 bytes | HMAC-SHA256 of the key for verification |
| `META_LEN` | 4 bytes | Length of encrypted metadata |
| `ORIGINAL_SIZE` | 8 bytes | Original plaintext file size (uint64) |
| `CHUNK_SIZE` | 4 bytes | Chunk size (0 = single-shot mode) |
| `HEADER_HASH` | 32 bytes | SHA-256 hash of all preceding header bytes |

### Encrypted Metadata

```
FILENAME_LEN(2) | FILENAME(var) | EXT_LEN(1) | EXTENSION(var)
```

Stores the original filename and MIME-detected extension, encrypted as the first data block.

### Encryption Modes

- **Single-Shot** (≤ 256 MB): The entire file + metadata is encrypted as one AES-256-GCM block with the header as AAD.
- **Chunked** (> 256 MB): The file is split into 128 MB chunks. Each chunk gets a unique nonce (derived by XOR-ing the chunk index into the base nonce) and chunk-specific AAD (header bytes + chunk index). Metadata is encrypted as chunk 0.

## 🔐 Security Details

### Key Derivation
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Salt**: 16 bytes, cryptographically random, unique per file
- **Iterations**: Randomized between 100,000 and 600,000 per encryption
- **Output**: 32-byte (256-bit) AES key

### Key Verification
An HMAC-SHA256 tag of the derived key (using the constant `effuse-key-check`) is stored in the header. This allows distinguishing between an incorrect password and a tampered file during decryption, without leaking any key material.

### Header Integrity
A SHA-256 hash of all header bytes (before the hash field) is appended to the header and verified on read. Any modification to the header is detected before decryption begins.

### Secure Deletion
After encryption, original files are securely shredded:
1. Overwritten with cryptographically random data (128 MB chunks)
2. Flushed to disk via `fsync`
3. Renamed to a random string
4. Deleted

### PEM Key Generation
The `genkey` command generates a deterministic 4096-bit RSA private key:
1. Reads 32 bytes of salt from the source file (at offset 1024)
2. Derives a master seed via PBKDF2 (10,000 iterations)
3. Uses AES-CTR as a deterministic CSPRNG to generate RSA primes
4. Exports the key in PKCS#1 PEM format

The same source file + password always produces the same key.

## 📝 License

This project is licensed under the **AGPL-3.0-only** license.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

See the [LICENSE](LICENSE) file for details.