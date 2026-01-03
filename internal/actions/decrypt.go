// Effuse - AES-256 File Encryption Utility (v1)
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
		return err
	}
	defer f.Close()

	// Read Header
	header, err := magic.ReadHeader(f)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Read remaining ciphertext
	ciphertext, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Decrypting %s...", filepath.Base(path)))

	// Derive and parse Key/Password
	var key []byte
	if usePEM {
		key = passwordOrKey
	} else {
		key = security.DeriveKey(string(passwordOrKey), header.Salt, int(header.Iterations))
	}

	// Decrypt
	plaintext, err := security.Decrypt(ciphertext, key, header.IV)
	if err != nil {
		spinner.Fail("Decryption failed (wrong password?)")
		return fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	if len(plaintext) < 1 {
		return fmt.Errorf("decrypted payload too small")
	}

	// Parse Extension and Data
	extLen := int(plaintext[0])
	if len(plaintext) < 1+extLen {
		return fmt.Errorf("malformed payload")
	}
	ext := string(plaintext[1 : 1+extLen])
	fileData := plaintext[1+extLen:]

	// Write Output
	baseName := strings.TrimSuffix(path, filepath.Ext(path))
	newPath := baseName + ext

	if err := os.WriteFile(newPath, fileData, 0644); err != nil {
		spinner.Fail("Failed to write decrypted file")
		return fmt.Errorf("failed to write decrypted file: %w", err)
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
