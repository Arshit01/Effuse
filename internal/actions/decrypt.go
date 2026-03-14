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
func DecryptFile(path string, passwordOrKey []byte, usePEM bool, destDir, customOutPath string) error {
	f, err := os.Open(path)
	if err != nil {
		pterm.Error.Printf("Failed to open file %s: %v\n", filepath.Base(path), err)
		return &DisplayedError{err}
	}
	defer f.Close()

	// Read Header
	header, headerBytes, err := magic.ReadHeader(f)
	if err != nil {
		pterm.Error.Println(err.Error())
		return &DisplayedError{err}
	}

	// Derive key
	var key []byte
	if usePEM {
		key = passwordOrKey
	} else {
		key = security.DeriveKey(string(passwordOrKey), header.Salt, int(header.Iterations))
	}

	// Resolve output path
	var originalName, ext string
	var outFile *os.File

	if header.ChunkSize == 0 {
		spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Decrypting %s...", filepath.Base(path)))

		// Read remaining ciphertext
		ciphertext, err := io.ReadAll(f)
		if err != nil {
			spinner.Fail("File has been tampered")
			return &DisplayedError{err}
		}

		// Decrypt
		plaintext, err := security.DecryptInPlace(ciphertext, key, header.Nonce, headerBytes)
		if err != nil {
			if security.VerifyKeyCheck(key, header.KeyCheck) {
				spinner.Fail("File has been tampered")
				return &DisplayedError{security.ErrTampered}
			}
			spinner.Fail("Incorrect password or key")
			return &DisplayedError{security.ErrIncorrectKey}
		}

		// Extract metadata
		metaLen := int(header.MetaLen)
		if len(plaintext) < metaLen {
			spinner.Fail("Decryption failed")
			return &DisplayedError{fmt.Errorf("decrypted payload too small for metadata")}
		}

		originalName, ext, err = parseMetadata(plaintext[:metaLen])
		if err != nil {
			spinner.Fail("Decryption failed")
			return &DisplayedError{fmt.Errorf("malformed metadata: %w", err)}
		}
		fileData := plaintext[metaLen:]

		// Resolve and write output
		newPath := ResolveOutputPath(path, destDir, customOutPath, originalName, ext)

		if err := os.WriteFile(newPath, fileData, 0644); err != nil {
			spinner.Fail("Failed to write decrypted file")
			return &DisplayedError{err}
		}

		spinner.Success("File decrypted successfully")
		pterm.Success.Printf("Decrypted: %s -> %s\n", path, newPath)
	} else {
		// Decrypt metadata chunk
		metaChunkSize := int(header.MetaLen) + magic.GCMTagSize
		metaChunkBuf := make([]byte, metaChunkSize)
		if _, err := io.ReadFull(f, metaChunkBuf); err != nil {
			pterm.Error.Println("File has been tampered")
			return &DisplayedError{err}
		}

		metaPlain, err := security.DecryptChunk(metaChunkBuf, key, header.Nonce, headerBytes, 0)
		if err != nil {
			if security.VerifyKeyCheck(key, header.KeyCheck) {
				pterm.Error.Println("File has been tampered")
				return &DisplayedError{security.ErrTampered}
			}
			pterm.Error.Println("Incorrect password or key")
			return &DisplayedError{security.ErrIncorrectKey}
		}

		originalName, ext, err = parseMetadata(metaPlain)
		if err != nil {
			pterm.Error.Println("Decryption failed")
			return &DisplayedError{fmt.Errorf("malformed metadata: %w", err)}
		}

		// Resolve and create output file
		newPath := ResolveOutputPath(path, destDir, customOutPath, originalName, ext)
		outFile, err = os.Create(newPath)
		if err != nil {
			pterm.Error.Printf("Failed to create output file: %v\n", err)
			return &DisplayedError{err}
		}
		defer outFile.Close()

		// Calculate total data chunks
		cs := int64(header.ChunkSize)
		totalDataChunks := int((int64(header.OriginalSize) + cs - 1) / cs)

		// Progress bar
		pb, _ := pterm.DefaultProgressbar.WithTotal(totalDataChunks).WithTitle(fmt.Sprintf("Decrypting %s", filepath.Base(path))).Start()

		encChunkSize := int(header.ChunkSize) + magic.GCMTagSize
		readBuf := make([]byte, encChunkSize)
		var chunkIdx uint32 = 1

		for {
			n, readErr := io.ReadFull(f, readBuf)
			if n > 0 {
				decrypted, err := security.DecryptChunk(readBuf[:n], key, header.Nonce, headerBytes, chunkIdx)
				if err != nil {
					pb.Stop()
					if security.VerifyKeyCheck(key, header.KeyCheck) {
						pterm.Error.Println("File has been tampered")
						return &DisplayedError{security.ErrTampered}
					}
					pterm.Error.Println("Incorrect password or key")
					return &DisplayedError{security.ErrIncorrectKey}
				}

				if _, err := outFile.Write(decrypted); err != nil {
					pb.Stop()
					pterm.Error.Println("Failed to write decrypted data")
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
		pterm.Success.Println("File decrypted successfully")
		pterm.Success.Printf("Decrypted: %s -> %s\n", path, newPath)
	}

	f.Close()
	if err := os.Remove(path); err != nil {
		pterm.Warning.Printf("Could not remove encrypted file: %v\n", err)
	} else {
		pterm.Info.Printf("Removed encrypted file: %s\n", path)
	}
	return nil
}

