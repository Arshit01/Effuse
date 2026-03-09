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
	"encoding/binary"
	"errors"
	"io"
)

const (
	MagicString = "EFFUSE"
	VersionString = "v2"
	DefaultSaltLen = 16
	NonceLen = 12
	KeyCheckLen = 32
)

var (
	ErrInvalidMagic   = errors.New("missing header — file not recognized")
	ErrInvalidVersion = errors.New("corrupted file header or unsupported version")
	ErrShortRead      = errors.New("unexpected EOF while reading header")
)

type Header struct {
	Iterations uint32
	Salt       []byte
	Nonce      []byte
	KeyCheck   []byte
}

// Format: MAGIC(6 Byte) | VERSION(2 Byte) | ITER(4 Byte) | SALT_LEN(1 Byte) | SALT | NONCE(12 Byte) | KEY_CHECK(32 Byte)
// Returns the raw header bytes (used as AAD for GCM).
func WriteHeader(w io.Writer, iterations uint32, salt, nonce, keyCheck []byte) ([]byte, error) {
	var buf bytes.Buffer

	buf.Write([]byte(MagicString))
	buf.Write([]byte(VersionString))
	binary.Write(&buf, binary.BigEndian, iterations)

	saltLen := len(salt)
	if saltLen > 255 {
		return nil, errors.New("salt too long")
	}
	buf.Write([]byte{uint8(saltLen)})
	buf.Write(salt)

	if len(nonce) != NonceLen {
		return nil, errors.New("invalid nonce length")
	}
	buf.Write(nonce)

	if len(keyCheck) != KeyCheckLen {
		return nil, errors.New("invalid key check length")
	}
	buf.Write(keyCheck)

	headerBytes := buf.Bytes()
	if _, err := w.Write(headerBytes); err != nil {
		return nil, err
	}

	return headerBytes, nil
}

// ReadHeader parses the file header and returns both the parsed struct
// and the raw header bytes (used as AAD for GCM verification).
func ReadHeader(r io.Reader) (*Header, []byte, error) {
	var raw bytes.Buffer
	tee := io.TeeReader(r, &raw)

	magicBuf := make([]byte, len(MagicString))
	if _, err := io.ReadFull(tee, magicBuf); err != nil {
		return nil, nil, ErrShortRead
	}
	if string(magicBuf) != MagicString {
		return nil, nil, ErrInvalidMagic
	}

	verBuf := make([]byte, len(VersionString))
	if _, err := io.ReadFull(tee, verBuf); err != nil {
		return nil, nil, ErrShortRead
	}
	if string(verBuf) != VersionString {
		return nil, nil, ErrInvalidVersion
	}

	var iterations uint32
	if err := binary.Read(tee, binary.BigEndian, &iterations); err != nil {
		return nil, nil, ErrShortRead
	}
	saltLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(tee, saltLenBuf); err != nil {
		return nil, nil, ErrShortRead
	}
	saltLen := int(saltLenBuf[0])
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(tee, salt); err != nil {
		return nil, nil, ErrShortRead
	}

	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(tee, nonce); err != nil {
		return nil, nil, ErrShortRead
	}

	keyCheck := make([]byte, KeyCheckLen)
	if _, err := io.ReadFull(tee, keyCheck); err != nil {
		return nil, nil, ErrShortRead
	}

	return &Header{
		Iterations: iterations,
		Salt:       salt,
		Nonce:      nonce,
		KeyCheck:   keyCheck,
	}, raw.Bytes(), nil
}
