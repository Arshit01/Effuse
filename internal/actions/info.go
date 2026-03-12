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
	"io"
	"os"
	"path/filepath"

	"github.com/Arshit01/Effuse/internal/magic"
	"github.com/Arshit01/Effuse/internal/security"
)

// FileInfo holds the result of inspecting an .eff file.
type FileInfo struct {
	File      string // .eff filename
	FileName  string // original filename from metadata
	Extension string // MIME-detected extension
	Version   string // file format version
	Status    string // "OK" or "CORRUPTED"
}

// GetFileInfo inspects an .eff file and returns its info.
// Performs a full status check: magic → version → header hash → key → GCM → metadata.
func GetFileInfo(path string, passwordOrKey []byte, usePEM bool) FileInfo {
	info := FileInfo{
		File:      filepath.Base(path),
		FileName:  "NA",
		Extension: "NA",
		Version:   "NA",
		Status:    "CORRUPTED",
	}

	f, err := os.Open(path)
	if err != nil {
		return info
	}
	defer f.Close()

	// Read and verify header (magic, version, header hash)
	header, headerBytes, err := magic.ReadHeader(f)
	if err != nil {
		return info
	}

	// If we got here, magic, version, and header hash are all valid
	info.Version = magic.VersionString

	// Read ciphertext
	ciphertext, err := io.ReadAll(f)
	if err != nil {
		return info
	}

	// Derive key
	var key []byte
	if usePEM {
		key = passwordOrKey
	} else {
		key = security.DeriveKey(string(passwordOrKey), header.Salt, int(header.Iterations))
	}

	// GCM decrypt
	plaintext, err := security.Decrypt(ciphertext, key, header.Nonce, headerBytes)
	if err != nil {
		if !security.VerifyKeyCheck(key, header.KeyCheck) {
			info.Status = "INCORRECT KEY/PASSWORD"
		}
		return info
	}

	// Parse metadata
	metaLen := int(header.MetaLen)
	if len(plaintext) < metaLen {
		return info
	}

	originalName, ext, err := parseMetadata(plaintext[:metaLen])
	if err != nil {
		return info
	}

	info.FileName = originalName
	info.Extension = ext
	info.Status = "OK"
	return info
}
