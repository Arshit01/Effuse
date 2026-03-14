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

// AES-256-GCM encryption with AAD (Additional Authenticated Data)
func Encrypt(plaintext, key, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Appending 16-byte GCM authentication tag
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	return ciphertext, nil
}

// AES-256-GCM authenticated decryption with AAD.
func Decrypt(ciphertext, key, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrTampered
	}

	return plaintext, nil
}
