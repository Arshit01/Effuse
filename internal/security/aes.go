// Effuse - AES-256-GCM File Encryption Utility (v2)
// Copyright (C) 2025 Arshit Vora
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

var (
	ErrIncorrectKey = errors.New("incorrect password or key")
	ErrTampered     = errors.New("file has been tampered with")
)

// Perform AES-256-GCM authenticated encryption with AAD.
// The aad (Additional Authenticated Data) is authenticated but not encrypted,
// ensuring the integrity of metadata like the file header.
// Returns ciphertext with the GCM authentication tag appended.
func Encrypt(plaintext, key, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Seal encrypts and authenticates plaintext with the given AAD,
	// appending the 16-byte GCM authentication tag to the ciphertext
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	return ciphertext, nil
}

// Perform AES-256-GCM authenticated decryption with AAD.
// Verifies the GCM authentication tag against both the ciphertext and AAD.
// If the tag does not match, the file has been tampered with.
func Decrypt(ciphertext, key, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Open authenticates and decrypts; returns error if ciphertext or AAD is tampered
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrTampered
	}

	return plaintext, nil
}
