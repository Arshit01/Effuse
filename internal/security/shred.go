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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// Wipes the file content with random data, renames it to a random string,
// and then deletes it to prevent data recovery.
func SecureRemove(path string) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	size := fileInfo.Size()

	// Overwrite with random data
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open for shredding: %w", err)
	}

	chunkSize := 128 * 1024 * 1024
	buf := make([]byte, chunkSize)

	for written := int64(0); written < size; {
		remaining := size - written
		currentChunk := int(remaining)
		if currentChunk > chunkSize {
			currentChunk = chunkSize
		}

		if _, err := rand.Read(buf[:currentChunk]); err != nil {
			f.Close()
			return fmt.Errorf("failed to generate random shred data: %w", err)
		}

		if _, err := f.Write(buf[:currentChunk]); err != nil {
			f.Close()
			return fmt.Errorf("failed to write shred data: %w", err)
		}
		written += int64(currentChunk)
	}

	// Sync to ensure data is written to physical disk
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("failed to sync shred data: %w", err)
	}
	f.Close()

	// Rename to random string to hide original filename
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	tempPath := filepath.Join(filepath.Dir(path), hex.EncodeToString(randomBytes))

	if err := os.Rename(path, tempPath); err != nil {
		os.Remove(path)
		return fmt.Errorf("failed to rename for secure deletion: %w", err)
	}

	return os.Remove(tempPath)
}
