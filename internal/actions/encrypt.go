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
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Arshit01/Effuse/internal/magic"
	"github.com/Arshit01/Effuse/internal/security"
	"github.com/pterm/pterm"
)

// Encrypts the file using the given password or key.
func EncryptFile(path string, passwordOrKey []byte, usePEM bool) error {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Detect file type
	ext := magic.DetectFileType(data, path)
	extBytes := []byte(ext)
	if len(extBytes) > 255 {
		extBytes = extBytes[:255]
	}

	// Construct Payload: [ext_len][ext][data]
	payload := make([]byte, 1+len(extBytes)+len(data))
	payload[0] = byte(len(extBytes))
	copy(payload[1:], extBytes)
	copy(payload[1+len(extBytes):], data)

	// Generate salt
	salt := security.GenerateRandomSalt()
	
	// Random iterations between 100k and 600k
	iterByte := make([]byte, 1)
	rand.Read(iterByte)
	iterations := 100000 + int(uint32(iterByte[0])*500000/255)

	spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Encrypting %s...", filepath.Base(path)))

	var key []byte
	if usePEM {
		key = passwordOrKey
	} else {
		key = security.DeriveKey(string(passwordOrKey), salt, iterations)
	}

	// Initialization Vector
	iv := make([]byte, magic.IVLen)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	// Encrypt
	ciphertext, err := security.Encrypt(payload, key, iv)
	if err != nil {
		spinner.Fail("Encryption failed")
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Write Output
	baseName := strings.TrimSuffix(path, filepath.Ext(path))
	newPath := baseName + ".eff"

	outFile, err := os.Create(newPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if err := magic.WriteHeader(outFile, uint32(iterations), salt, iv); err != nil {
		return err
	}
	if _, err := outFile.Write(ciphertext); err != nil {
		spinner.Fail("Failed to write ciphertext")
		return err
	}
	
	spinner.Success("File encrypted successfully")

	pterm.Success.Printf("Encrypted: %s -> %s\n", path, newPath)
	if err := os.Remove(path); err != nil {
		pterm.Warning.Printf("Could not remove original file: %v\n", err)
	} else {
		pterm.Info.Printf("Removed original file: %s\n", path)
	}
	return nil
}
