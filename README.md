# Effuse - AES-256-GCM File Encryption Utility

Effuse is a robust command-line utility designed for secure file encryption and decryption, leveraging the industry-standard AES-256-GCM (Galois/Counter Mode) authenticated encryption algorithm. It offers a flexible and highly secure method to protect your sensitive data, allowing you to choose between a strong password or a PEM key for cryptographic operations. With features like per-file salting, PBKDF2 key derivation, built-in integrity verification, and secure deletion of original files, Effuse ensures that your information remains confidential, tamper-proof, and protected against unauthorized access.

## ✨ Features

- **AES-256-GCM Encryption**: Authenticated encryption providing both confidentiality and integrity.
- **Password or PEM Key**: Choose between a password or a PEM key for encryption.
- **Per-File Salt**: A random salt is generated for each file when using a password, enhancing security.
- **PBKDF2**: Uses PBKDF2 to derive the encryption key from a password.
- **File Type Detection**: Automatically detects the file type and restores it upon decryption.
- **Key Generation**: Generate a PEM key from a source file for added entropy.
- **Secure Deletion**: The original file is securely removed after encryption/decryption.

## 📦 Installation

### Download Binary (Recommended)

You can download the pre-compiled binaries for your OS based on architecture from the [Release](https://github.com/Arshit01/Effuse/releases/latest) page.

- Unzip the downloaded file.
- Move the binary to a directory in your system `PATH`.

### Build from Source

#### Prerequisites

- **Go**: Ensure you have Go installed on your machine. You can download and install it from [go.dev/doc/install](https://go.dev/doc/install).

#### Steps:

1.  Clone the repository:
    ```bash
    git clone https://github.com/Arshit01/Effuse.git
    cd Effuse
    ```
2.  Build the binary using the provided script (handles dependencies automatically):
    ```bash
    ./build.sh
    ```
    This will create binaries in the `dist` directory, organized by architecture and OS (e.g., `dist/amd64/linux/effuse`).

## 🎯 Usage

Effuse uses a subcommand-based approach.

```bash
effuse [command] [flags] [files...]
```

### 🔒 Encrypt a File

- **With Password**
  ```bash
  ./effuse encrypt <file-to-encrypt>
  ```
- **With PEM Key**
  ```bash
  ./effuse encrypt <file-to-encrypt> --key <path-to-pem-key>
  ```

### 🔓 Decrypt a File

- **With Password**
  ```bash
  ./effuse decrypt <file-to-decrypt.eff>
  ```
- **With PEM Key**
  ```bash
  ./effuse decrypt <file-to-decrypt.eff> --key <path-to-pem-key>
  ```

### 🗝️ Generate a PEM Key

- **From Source File**
  ```bash
  ./effuse genkey <source-file>
  ```
  > The source file acts as entropy. This creates `key.pem` in the current directory.

### 📊 Get File Info

- **View Metadata**
  ```bash
  ./effuse info <file.eff>
  ```

## 🏗️ File Header Format

The encrypted file has a custom header to store encryption metadata.

- **MAGIC (6 bytes)**: `EFFUSE`
- **VERSION (2 bytes)**: `v1`
- **ITER (4 bytes BE)**: PBKDF2 iterations (uint32)
- **SALT_LEN (1 byte)**: length of salt (uint8)
- **SALT (salt_len bytes)**
- **IV (16 bytes)**
- **CIPHERTEXT (rest)**

## 🔐 Key Derivation

The encryption key is derived from a password using PBKDF2-HMAC-SHA256. A random salt and a random number of iterations are used for each encryption.

## 🔑 PEM Key Generation

A PEM key can be generated using the `genkey` command. This uses a source file as entropy to generate a 4096-bit RSA key. The key is saved to `key.pem` in the current directory.

## 📝 License

This project is licensed under the **AGPL-3.0-only** license.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

See the [LICENSE](LICENSE) file for details.