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
	"encoding/binary"
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

// Encrypts plaintext in-place using AES-256-GCM (one shot).
func EncryptInPlace(buf []byte, ptLen int, key, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext := buf[:ptLen]
	ciphertext := gcm.Seal(plaintext[:0], nonce, plaintext, aad)
	return ciphertext, nil
}

// Decrypts ciphertext in-place using AES-256-GCM (one shot).
func DecryptInPlace(ciphertext, key, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(ciphertext[:0], nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrTampered
	}

	return plaintext, nil
}

// Produce a unique nonce per chunk.
func deriveChunkNonce(baseNonce []byte, chunkIdx uint32) []byte {
	nonce := make([]byte, len(baseNonce))
	copy(nonce, baseNonce)
	// XOR chunk index into the last 4 bytes of the nonce
	idxBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idxBytes, chunkIdx)
	for i := 0; i < 4; i++ {
		nonce[len(nonce)-4+i] ^= idxBytes[i]
	}
	return nonce
}

// Create AAD for a chunk
func buildChunkAAD(headerAAD []byte, chunkIdx uint32) []byte {
	aad := make([]byte, len(headerAAD)+4)
	copy(aad, headerAAD)
	binary.BigEndian.PutUint32(aad[len(headerAAD):], chunkIdx)
	return aad
}

// Encrypts a chunk with derived nonce and chunk-specific AAD.
func EncryptChunk(plaintext, key, baseNonce, headerAAD []byte, chunkIdx uint32) ([]byte, error) {
	nonce := deriveChunkNonce(baseNonce, chunkIdx)
	aad := buildChunkAAD(headerAAD, chunkIdx)
	return Encrypt(plaintext, key, nonce, aad)
}

// Decrypts a chunk with derived nonce and chunk-specific AAD.
func DecryptChunk(ciphertext, key, baseNonce, headerAAD []byte, chunkIdx uint32) ([]byte, error) {
	nonce := deriveChunkNonce(baseNonce, chunkIdx)
	aad := buildChunkAAD(headerAAD, chunkIdx)
	return Decrypt(ciphertext, key, nonce, aad)
}
