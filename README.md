# Effuse - AES-256 File Encryption Utility

Effuse is a robust command-line utility designed for secure file encryption and decryption, leveraging the industry-standard AES-256 algorithm. It offers a flexible and highly secure method to protect your sensitive data, allowing you to choose between a strong password or a PEM key for cryptographic operations. With features like per-file salting, PBKDF2 key derivation, and secure deletion of original files, Effuse ensures that your information remains confidential and protected against unauthorized access.

## Features

- **AES-256 Encryption**: Strong encryption to keep your files secure.
- **Password or PEM Key**: Choose between a password or a PEM key for encryption.
- **Per-File Salt**: A random salt is generated for each file when using a password, enhancing security.
- **PBKDF2**: Uses PBKDF2 to derive the encryption key from a password.
- **File Type Detection**: Automatically detects the file type and restores it upon decryption.
- **Key Generation**: Generate a PEM key from a source file for added entropy.
- **Secure Deletion**: The original file is securely removed after encryption/decryption.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/your-username/effuse.git
    cd effuse
    ```
2.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
    The `requirements.txt` file contains:
    ```
    cryptography
    pycryptodome
    ```

## Usage

### Encrypt a File

To encrypt a file with a password:

```bash
python effuse.py -e <file-to-encrypt>
```

To encrypt a file with a PEM key:

```bash
python effuse.py -e <file-to-encrypt> --key <path-to-pem-key>
```

### Decrypt a File

To decrypt a file with a password:

```bash
python effuse.py -d <file-to-decrypt.eff>
```

To decrypt a file with a PEM key:

```bash
python effuse.py -d <file-to-decrypt.eff> --key <path-to-pem-key>
```

### Generate a PEM Key

To generate a new PEM key from a source file (for entropy):

```bash
python effuse.py --genkey <source-file>
```
> The source file can be any file (e.g., image, video, PDF) and its content is used as entropy for key generation.

This will create a `key.pem` file in the current directory.

### Get File Info

To get information about an encrypted file (original file type):

```bash
python effuse.py -i <file.eff>
```

## File Header Format

The encrypted file has a custom header to store encryption metadata.

- **MAGIC (6 bytes)**: `EFFUSE`
- **VERSION (2 bytes)**: `v1`
- **ITER (4 bytes BE)**: PBKDF2 iterations (uint32)
- **SALT_LEN (1 byte)**: length of salt (uint8)
- **SALT (salt_len bytes)**
- **IV (16 bytes)**
- **CIPHERTEXT (rest)**

## Key Derivation

The encryption key is derived from a password using PBKDF2-HMAC-SHA256. A random salt and a random number of iterations are used for each encryption.

## PEM Key Generation

A PEM key can be generated using the `--genkey` option. This uses a source file as entropy to generate a 4096-bit RSA key. The key is saved to `key.pem` in the current directory.

## License

This project is licensed under the **AGPL-3.0-only** license.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

See the [LICENSE](LICENSE) file for details.