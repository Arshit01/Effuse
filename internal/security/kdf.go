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
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

// Derives a 32-byte AES key from a password and salt using PBKDF2-HMAC-SHA256.
func DeriveKey(password string, salt []byte, iterations int) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)
}

// GenerateKeyCheck creates an HMAC-SHA256 of the key using a fixed constant.
// This is stored in the file header to verify the key before attempting decryption,
// allowing us to distinguish "wrong password" from "tampered file".
// By using a constant instead of the salt, the key check remains valid even if
// header fields (like the salt) are tampered, enabling correct tamper detection.
func GenerateKeyCheck(key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("effuse-key-check"))
	return mac.Sum(nil)
}

// VerifyKeyCheck compares the stored key check against the expected HMAC.
// Returns true if the key is correct.
func VerifyKeyCheck(key, check []byte) bool {
	expected := GenerateKeyCheck(key)
	return hmac.Equal(expected, check)
}
