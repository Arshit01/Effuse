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

package magic

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	MagicString    = "EFFUSE"
	VersionString  = "v2"
	DefaultSaltLen = 16
	NonceLen       = 12
	KeyCheckLen    = 32
	HeaderHashLen  = 32
)

var (
	ErrInvalidMagic   = errors.New("File not recognized")
	ErrInvalidVersion = errors.New("Unsupported version")
	ErrShortRead      = errors.New("File has been tampered")
	ErrTamperedHeader = errors.New("File has been tampered")
)

type Header struct {
	Iterations uint32
	Salt       []byte
	Nonce      []byte
	KeyCheck   []byte
	MetaLen    uint32
}

// Format: MAGIC(6) | VERSION(2) | ITER(4) | SALT_LEN(1) | SALT(var) | NONCE(12) | KEY_CHECK(32) | META_LEN(4) | HEADER_HASH(32)
func WriteHeader(w io.Writer, iterations uint32, salt, nonce, keyCheck []byte, metaLen uint32) ([]byte, error) {
	var buf bytes.Buffer

	// Magic and Version
	buf.Write([]byte(MagicString))
	buf.Write([]byte(VersionString))

	// KDF Iterations
	binary.Write(&buf, binary.BigEndian, iterations)

	// Salt
	saltLen := len(salt)
	if saltLen > 255 {
		return nil, errors.New("salt too long")
	}
	buf.Write([]byte{uint8(saltLen)})
	buf.Write(salt)

	// GCM Nonce
	if len(nonce) != NonceLen {
		return nil, errors.New("invalid nonce length")
	}
	buf.Write(nonce)

	// Key Check (HMAC)
	if len(keyCheck) != KeyCheckLen {
		return nil, errors.New("invalid key check length")
	}
	buf.Write(keyCheck)

	// Metadata Length
	binary.Write(&buf, binary.BigEndian, metaLen)

	// Compute SHA256 hash of all preceding header bytes
	hash := sha256.Sum256(buf.Bytes())
	buf.Write(hash[:])

	// Writes header
	headerBytes := buf.Bytes()
	if _, err := w.Write(headerBytes); err != nil {
		return nil, err
	}

	return headerBytes, nil
}

// Verifies magic, version, and header hash.
func ReadHeader(r io.Reader) (*Header, []byte, error) {
	var raw bytes.Buffer
	tee := io.TeeReader(r, &raw)

	// Magic
	magicBuf := make([]byte, len(MagicString))
	if _, err := io.ReadFull(tee, magicBuf); err != nil {
		return nil, nil, ErrShortRead
	}
	if string(magicBuf) != MagicString {
		return nil, nil, ErrInvalidMagic
	}

	// Version
	verBuf := make([]byte, len(VersionString))
	if _, err := io.ReadFull(tee, verBuf); err != nil {
		return nil, nil, ErrShortRead
	}
	if string(verBuf) != VersionString {
		return nil, nil, ErrInvalidVersion
	}

	// Iterations
	var iterations uint32
	if err := binary.Read(tee, binary.BigEndian, &iterations); err != nil {
		return nil, nil, ErrShortRead
	}

	// Salt
	saltLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(tee, saltLenBuf); err != nil {
		return nil, nil, ErrShortRead
	}
	saltLen := int(saltLenBuf[0])
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(tee, salt); err != nil {
		return nil, nil, ErrShortRead
	}

	// Nonce
	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(tee, nonce); err != nil {
		return nil, nil, ErrShortRead
	}

	// Key Check
	keyCheck := make([]byte, KeyCheckLen)
	if _, err := io.ReadFull(tee, keyCheck); err != nil {
		return nil, nil, ErrShortRead
	}

	// Meta Length
	var metaLen uint32
	if err := binary.Read(tee, binary.BigEndian, &metaLen); err != nil {
		return nil, nil, ErrShortRead
	}

	// Bytes before the hash
	preHashBytes := make([]byte, raw.Len())
	copy(preHashBytes, raw.Bytes())

	// Header Hash
	storedHash := make([]byte, HeaderHashLen)
	if _, err := io.ReadFull(tee, storedHash); err != nil {
		return nil, nil, ErrShortRead
	}

	// Verify header hash
	expectedHash := sha256.Sum256(preHashBytes)
	if !bytes.Equal(expectedHash[:], storedHash) {
		return nil, nil, ErrTamperedHeader
	}

	return &Header{
		Iterations: iterations,
		Salt:       salt,
		Nonce:      nonce,
		KeyCheck:   keyCheck,
		MetaLen:    metaLen,
	}, raw.Bytes(), nil
}
