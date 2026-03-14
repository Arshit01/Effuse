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
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Arshit01/Effuse/internal/magic"
	"github.com/Arshit01/Effuse/internal/security"
	"github.com/pterm/pterm"
)

// Extracts filename and extension from metadata bytes.
func parseMetadata(meta []byte) (filename, ext string, err error) {
	if len(meta) < 3 {
		return "", "", fmt.Errorf("metadata too short")
	}

	filenameLen := int(binary.BigEndian.Uint16(meta[0:2]))
	if len(meta) < 2+filenameLen+1 {
		return "", "", fmt.Errorf("malformed metadata: filename truncated")
	}
	filename = string(meta[2 : 2+filenameLen])

	extLen := int(meta[2+filenameLen])
	if len(meta) < 2+filenameLen+1+extLen {
		return "", "", fmt.Errorf("malformed metadata: extension truncated")
	}
	ext = string(meta[2+filenameLen+1 : 2+filenameLen+1+extLen])

	return filename, ext, nil
}

// Decrypt the .eff files.
func DecryptFile(path string, passwordOrKey []byte, usePEM bool, customOutPath string) error {
	f, err := os.Open(path)
	if err != nil {
		pterm.Error.Printf("Failed to open file %s: %v\n", filepath.Base(path), err)
		return &DisplayedError{err}
	}
	defer f.Close()

	// Read Header (also returns raw bytes for AAD)
	// ReadHeader verifies magic, version, and header hash.
	header, headerBytes, err := magic.ReadHeader(f)
	if err != nil {
		pterm.Error.Println(err.Error())
		return &DisplayedError{err}
	}

	// Read remaining ciphertext
	ciphertext, err := io.ReadAll(f)
	if err != nil {
		pterm.Error.Println("File has been tampered")
		return &DisplayedError{err}
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
	plaintext, err := security.Decrypt(ciphertext, key, header.Nonce, headerBytes)
	if err != nil {
		// GCM failed — use HMAC key check to determine cause:
		if security.VerifyKeyCheck(key, header.KeyCheck) {
			spinner.Fail("File has been tampered") // If HMAC passes → key is correct, but ciphertext was tampered
			return &DisplayedError{security.ErrTampered}
		}
		spinner.Fail("Incorrect password or key") // If HMAC fails → key is wrong
		return &DisplayedError{security.ErrIncorrectKey}
	}

	// Split plaintext into metadata and file data using MetaLen from header
	metaLen := int(header.MetaLen)
	if len(plaintext) < metaLen {
		spinner.Fail("Decryption failed")
		return &DisplayedError{fmt.Errorf("decrypted payload too small for metadata")}
	}

	metaBytes := plaintext[:metaLen]
	fileData := plaintext[metaLen:]

	// Parse metadata to get original filename and extension
	originalName, ext, err := parseMetadata(metaBytes)
	if err != nil {
		spinner.Fail("Decryption failed")
		return &DisplayedError{fmt.Errorf("malformed metadata: %w", err)}
	}

	// Write Output
	var desiredPath string
	if customOutPath != "" {
		desiredPath = customOutPath
		if filepath.Ext(desiredPath) == "" {
			desiredPath += ext
		}
	} else {
		desiredPath = filepath.Join(filepath.Dir(path), originalName)
	}

	newPath := generateSafePath(desiredPath)

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
