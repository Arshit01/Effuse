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
	"io"
	"os"
	"path/filepath"

	"github.com/Arshit01/Effuse/internal/magic"
	"github.com/Arshit01/Effuse/internal/security"
	"github.com/pterm/pterm"
)

// Creates the metadata bytes
func buildMetadata(path string, headerData []byte) []byte {
	// Original filename
	filename := filepath.Base(path)
	filenameBytes := []byte(filename)
	if len(filenameBytes) > 65535 {
		filenameBytes = filenameBytes[:65535]
	}

	// Detect real file type via MIME
	ext := magic.DetectFileType(headerData, path)
	extBytes := []byte(ext)
	if len(extBytes) > 255 {
		extBytes = extBytes[:255]
	}

	meta := make([]byte, 2+len(filenameBytes)+1+len(extBytes))
	binary.BigEndian.PutUint16(meta[0:2], uint16(len(filenameBytes)))
	copy(meta[2:], filenameBytes)
	meta[2+len(filenameBytes)] = byte(len(extBytes))
	copy(meta[2+len(filenameBytes)+1:], extBytes)

	return meta
}

// Encrypts the file using the given password or key.
func EncryptFile(path string, passwordOrKey []byte, usePEM bool, destDir, customOutPath string) error {
	// Stat file to get size
	fileInfo, err := os.Stat(path)
	if err != nil {
		pterm.Error.Printf("Failed to stat file %s: %v\n", filepath.Base(path), err)
		return &DisplayedError{err}
	}
	fileSize := fileInfo.Size()

	// Open file for reading
	srcFile, err := os.Open(path)
	if err != nil {
		pterm.Error.Printf("Failed to open file %s: %v\n", filepath.Base(path), err)
		return &DisplayedError{err}
	}
	defer srcFile.Close()

	// Read first 3072 bytes for MIME detection
	mimeSniff := make([]byte, 3072)
	n, _ := srcFile.Read(mimeSniff)
	mimeSniff = mimeSniff[:n]
	srcFile.Seek(0, io.SeekStart)

	// Build metadata
	meta := buildMetadata(path, mimeSniff)

	// Generate salt
	salt := security.GenerateRandomSalt()

	// Random iterations between 100k and 600k
	iterByte := make([]byte, 1)
	rand.Read(iterByte)
	iterations := 100000 + int(uint32(iterByte[0])*500000/255)

	// Derive key
	var key []byte
	if usePEM {
		key = passwordOrKey
	} else {
		key = security.DeriveKey(string(passwordOrKey), salt, iterations)
	}

	// Nonce (12 bytes for GCM)
	nonce := make([]byte, magic.NonceLen)
	if _, err := rand.Read(nonce); err != nil {
		pterm.Error.Println("Failed to generate nonce")
		return &DisplayedError{err}
	}

	// Generates (HMAC-SHA256) for key verification
	keyCheck := security.GenerateKeyCheck(key)

	// Determine chunk size
	var chunkSize uint32
	if fileSize > magic.SingleShotLimit {
		chunkSize = uint32(magic.DefaultChunkSize)
	}

	// Resolve output path
	newPath := ResolveOutputPath(path, destDir, customOutPath, "", ".eff")

	// Create output file
	outFile, err := os.Create(newPath)
	if err != nil {
		pterm.Error.Printf("Failed to create output file %s: %v\n", newPath, err)
		return &DisplayedError{err}
	}
	defer outFile.Close()

	// Write header
	headerBytes, err := magic.WriteHeader(outFile, uint32(iterations), salt, nonce, keyCheck, uint32(len(meta)), uint64(fileSize), chunkSize)
	if err != nil {
		pterm.Error.Println("Failed to write file header")
		return &DisplayedError{err}
	}

	if chunkSize == 0 {
		spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Encrypting %s...", filepath.Base(path)))

		// Allocate one buffer: meta + file data + GCM tag
		bufSize := len(meta) + int(fileSize) + magic.GCMTagSize
		buf := make([]byte, bufSize)
		copy(buf, meta)

		// Read file directly into buffer
		if _, err := io.ReadFull(srcFile, buf[len(meta):len(meta)+int(fileSize)]); err != nil {
			spinner.Fail("Failed to read file")
			return &DisplayedError{err}
		}

		// Encrypt in-place
		ptLen := len(meta) + int(fileSize)
		ciphertext, err := security.EncryptInPlace(buf, ptLen, key, nonce, headerBytes)
		if err != nil {
			spinner.Fail("Encryption failed")
			return &DisplayedError{err}
		}

		// Write ciphertext
		if _, err := outFile.Write(ciphertext); err != nil {
			spinner.Fail("Failed to write ciphertext")
			return &DisplayedError{err}
		}

		spinner.Success("File encrypted successfully")
	} else {
		// Encrypt metadata
		metaCiphertext, err := security.EncryptChunk(meta, key, nonce, headerBytes, 0)
		if err != nil {
			pterm.Error.Println("Failed to encrypt metadata")
			return &DisplayedError{err}
		}
		if _, err := outFile.Write(metaCiphertext); err != nil {
			pterm.Error.Println("Failed to write metadata chunk")
			return &DisplayedError{err}
		}

		// Calculate total data chunks
		cs := int64(chunkSize)
		totalChunks := int((fileSize + cs - 1) / cs)

		// Progress bar
		pb, _ := pterm.DefaultProgressbar.WithTotal(totalChunks).WithTitle(fmt.Sprintf("Encrypting %s", filepath.Base(path))).Start()

		readBuf := make([]byte, cs)
		var chunkIdx uint32 = 1

		for {
			n, readErr := io.ReadFull(srcFile, readBuf)
			if n > 0 {
				chunk := readBuf[:n]
				encChunk, err := security.EncryptChunk(chunk, key, nonce, headerBytes, chunkIdx)
				if err != nil {
					pb.Stop()
					pterm.Error.Println("Encryption failed")
					return &DisplayedError{err}
				}

				if _, err := outFile.Write(encChunk); err != nil {
					pb.Stop()
					pterm.Error.Println("Failed to write chunk")
					return &DisplayedError{err}
				}
				chunkIdx++
				pb.Increment()
			}

			if readErr != nil {
				if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
					break
				}
				pb.Stop()
				pterm.Error.Println("Failed to read file")
				return &DisplayedError{readErr}
			}
		}

		pb.Stop()
		pterm.Success.Println("File encrypted successfully")
	}

	pterm.Success.Printf("Encrypted: %s -> %s\n", path, newPath)

	// Close source before shredding
	srcFile.Close()

	// Securely shred the original plaintext file
	shredSpinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Securely removing original file: %s...", filepath.Base(path)))
	if err := security.SecureRemove(path); err != nil {
		shredSpinner.Fail(fmt.Sprintf("Could not securely remove original file: %v", err))
	} else {
		shredSpinner.Success(fmt.Sprintf("Securely removed original file: %s", path))
	}
	return nil
}
