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

	"github.com/Arshit01/Effuse/internal/magic"
	"github.com/Arshit01/Effuse/internal/security"
)

// Inspecting an .eff file.
type FileInfo struct {
	File         string // .eff filename
	FileName     string // original filename from metadata
	Extension    string // MIME-detected extension
	OriginalSize string // human-readable original file size
	Version      string // file format version
	Status       string // "OK" or "CORRUPTED" or "INCORRECT KEY/PASSWORD"
}

// Convert bytes to human-readable string.
func formatSize(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// Full status check
func GetFileInfo(path string, passwordOrKey []byte, usePEM bool) FileInfo {
	info := FileInfo{
		File:         filepath.Base(path),
		FileName:     "NA",
		Extension:    "NA",
		OriginalSize: "NA",
		Version:      "NA",
		Status:       "CORRUPTED",
	}

	f, err := os.Open(path)
	if err != nil {
		return info
	}
	defer f.Close()

	// Verify header
	header, headerBytes, err := magic.ReadHeader(f)
	if err != nil {
		return info
	}
	info.Version = magic.VersionString
	info.OriginalSize = formatSize(header.OriginalSize)

	// Derive key
	var key []byte
	if usePEM {
		key = passwordOrKey
	} else {
		key = security.DeriveKey(string(passwordOrKey), header.Salt, int(header.Iterations))
	}

	if header.ChunkSize == 0 {
		// Read all ciphertext and decrypt
		ciphertext, err := io.ReadAll(f)
		if err != nil {
			return info
		}

		plaintext, err := security.Decrypt(ciphertext, key, header.Nonce, headerBytes)
		if err != nil {
			if !security.VerifyKeyCheck(key, header.KeyCheck) {
				info.Status = "INCORRECT KEY/PASSWORD"
			}
			return info
		}

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
	} else {
		// Chunked: only need to decrypt metadata
		metaChunkSize := int(header.MetaLen) + magic.GCMTagSize
		metaChunkBuf := make([]byte, metaChunkSize)
		if _, err := io.ReadFull(f, metaChunkBuf); err != nil {
			return info
		}

		metaPlain, err := security.DecryptChunk(metaChunkBuf, key, header.Nonce, headerBytes, 0)
		if err != nil {
			if !security.VerifyKeyCheck(key, header.KeyCheck) {
				info.Status = "INCORRECT KEY/PASSWORD"
			}
			return info
		}

		originalName, ext, err := parseMetadata(metaPlain)
		if err != nil {
			return info
		}

		info.FileName = originalName
		info.Extension = ext
		info.Status = "OK"
	}

	return info
}
