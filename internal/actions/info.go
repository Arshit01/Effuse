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

	"github.com/Arshit01/Effuse/internal/magic"
	"github.com/Arshit01/Effuse/internal/security"
	"github.com/pterm/pterm"
)

// Decrypts the file just enough (or fully) to reveal the original file type.
func ShowInfo(path string, passwordOrKey []byte, usePEM bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	header, err := magic.ReadHeader(f)
	if err != nil {
		return err
	}

	ciphertext, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Reading info for %s...", filepath.Base(path)))

	var key []byte
	if usePEM {
		key = passwordOrKey
	} else {
		key = security.DeriveKey(string(passwordOrKey), header.Salt, int(header.Iterations))
	}

	plaintext, err := security.Decrypt(ciphertext, key, header.IV)
	if err != nil {
		spinner.Fail("Decryption failed")
		return fmt.Errorf("decryption failed: %w", err)
	}
	
	spinner.Success("Info retrieved")

	if len(plaintext) < 1 {
		return fmt.Errorf("payload too small")
	}

	extLen := int(plaintext[0])
	if len(plaintext) < 1+extLen {
		return fmt.Errorf("malformed payload")
	}
	ext := string(plaintext[1 : 1+extLen])

	pterm.Info.Printf("Original File Type: %s\n", pterm.Yellow(ext))
	return nil
}
