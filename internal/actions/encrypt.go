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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Arshit01/Effuse/internal/magic"
	"github.com/Arshit01/Effuse/internal/security"
	"github.com/pterm/pterm"
)

// buildMetadata creates the metadata bytes: [filename_len(2)][filename][ext_len(1)][extension]
func buildMetadata(path string, data []byte) []byte {
	// Original filename (basename without path)
	filename := filepath.Base(path)
	filenameBytes := []byte(filename)
	if len(filenameBytes) > 65535 {
		filenameBytes = filenameBytes[:65535]
	}

	// Detect real file type via MIME
	ext := magic.DetectFileType(data, path)
	extBytes := []byte(ext)
	if len(extBytes) > 255 {
		extBytes = extBytes[:255]
	}

	// Build: [filename_len(2)][filename][ext_len(1)][extension]
	meta := make([]byte, 2+len(filenameBytes)+1+len(extBytes))
	binary.BigEndian.PutUint16(meta[0:2], uint16(len(filenameBytes)))
	copy(meta[2:], filenameBytes)
	meta[2+len(filenameBytes)] = byte(len(extBytes))
	copy(meta[2+len(filenameBytes)+1:], extBytes)

	return meta
}

// Encrypts the file using the given password or key.
func EncryptFile(path string, passwordOrKey []byte, usePEM bool) error {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		pterm.Error.Printf("Failed to read file %s: %v\n", filepath.Base(path), err)
		return &DisplayedError{err}
	}

	// Build metadata
	meta := buildMetadata(path, data)

	// Construct Payload: [metadata][filedata]
	payload := make([]byte, len(meta)+len(data))
	copy(payload, meta)
	copy(payload[len(meta):], data)

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

	// Nonce (12 bytes for GCM)
	nonce := make([]byte, magic.NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		spinner.Fail("Failed to generate nonce")
		return &DisplayedError{err}
	}

	// Generate key check (HMAC-SHA256) for key verification during decryption
	keyCheck := security.GenerateKeyCheck(key)

	// Write header and capture raw bytes for AAD
	baseName := strings.TrimSuffix(path, filepath.Ext(path))
	newPath := baseName + ".eff"

	outFile, err := os.Create(newPath)
	if err != nil {
		pterm.Error.Printf("Failed to create output file %s: %v\n", newPath, err)
		return &DisplayedError{err}
	}
	defer outFile.Close()

	headerBytes, err := magic.WriteHeader(outFile, uint32(iterations), salt, nonce, keyCheck, uint32(len(meta)))
	if err != nil {
		spinner.Fail("Failed to write file header")
		return &DisplayedError{err}
	}

	// Encrypt with header bytes as AAD
	ciphertext, err := security.Encrypt(payload, key, nonce, headerBytes)
	if err != nil {
		spinner.Fail("Encryption failed")
		return &DisplayedError{err}
	}

	if _, err := outFile.Write(ciphertext); err != nil {
		spinner.Fail("Failed to write ciphertext")
		return &DisplayedError{err}
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
