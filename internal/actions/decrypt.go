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

package actions

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Arshit01/Effuse/internal/magic"
	"github.com/Arshit01/Effuse/internal/security"
	"github.com/pterm/pterm"
)

// Decrypt the .eff files.
func DecryptFile(path string, passwordOrKey []byte, usePEM bool) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Read Header (also returns raw bytes for AAD)
	header, headerBytes, err := magic.ReadHeader(f)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Read remaining ciphertext
	ciphertext, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read ciphertext: %w", err)
	}

	spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Decrypting %s...", filepath.Base(path)))

	// Derive and parse Key/Password
	var key []byte
	if usePEM {
		key = passwordOrKey
	} else {
		key = security.DeriveKey(string(passwordOrKey), header.Salt, int(header.Iterations))
	}

	// Decrypt and verify integrity using GCM with header as AAD.
	// GCM authentication covers both the ciphertext and the entire header (via AAD),
	// so tampering ANY header field (salt, nonce, iterations, etc.) will be caught here.
	plaintext, err := security.Decrypt(ciphertext, key, header.Nonce, headerBytes)
	if err != nil {
		// GCM failed — use HMAC key check to determine cause:
		// If HMAC passes → key is correct, but header or ciphertext was tampered
		// If HMAC fails → key is wrong (wrong password, or salt/iterations were tampered)
		if security.VerifyKeyCheck(key, header.KeyCheck) {
			spinner.Fail("File has been tampered")
			return &DisplayedError{security.ErrTampered}
		}
		spinner.Fail("Incorrect password or key")
		return &DisplayedError{security.ErrIncorrectKey}
	}

	if len(plaintext) < 1 {
		spinner.Fail("Decryption failed")
		return &DisplayedError{fmt.Errorf("Decrypted payload too small")}
	}

	// Parse Extension and Data
	extLen := int(plaintext[0])
	if len(plaintext) < 1+extLen {
		spinner.Fail("Decryption failed")
		return &DisplayedError{fmt.Errorf("Malformed payload")}
	}
	ext := string(plaintext[1 : 1+extLen])
	fileData := plaintext[1+extLen:]

	// Write Output
	baseName := strings.TrimSuffix(path, filepath.Ext(path))
	newPath := baseName + ext

	if err := os.WriteFile(newPath, fileData, 0644); err != nil {
		spinner.Fail("Failed to write decrypted file")
		return &DisplayedError{err}
	}

	spinner.Success("File decrypted successfully")

	pterm.Success.Printf("Decrypted: %s -> %s\n", path, newPath)
	f.Close()
	
	if err := os.Remove(path); err != nil {
		pterm.Warning.Printf("Could not remove encrypted file: %v\n", err)
	} else {
		pterm.Info.Printf("Removed encrypted file: %s\n", path)
	}
	return nil
}
