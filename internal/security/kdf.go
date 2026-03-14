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

// Create an HMAC-SHA256 of the key with fixed constant.
func GenerateKeyCheck(key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("effuse-key-check"))
	return mac.Sum(nil)
}

// Compare stored key against the expected HMAC.
func VerifyKeyCheck(key, check []byte) bool {
	expected := GenerateKeyCheck(key)
	return hmac.Equal(expected, check)
}
