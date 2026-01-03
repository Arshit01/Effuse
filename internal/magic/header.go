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

package magic

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	MagicString = "EFFUSE"
	VersionString = "v1"
	DefaultSaltLen = 16
	IVLen = 16
)

var (
	ErrInvalidMagic   = errors.New("missing header — file not recognized")
	ErrInvalidVersion = errors.New("corrupted file header or unsupported version")
	ErrShortRead      = errors.New("unexpected EOF while reading header")
)

type Header struct {
	Iterations uint32
	Salt       []byte
	IV         []byte
}

// Format: MAGIC(6 Byte) | VERSION(2 Byte) | ITER(4 Byte) | SALT_LEN(1 Byte) | SALT | IV(16 Byte)
func WriteHeader(w io.Writer, iterations uint32, salt, iv []byte) error {
	if _, err := w.Write([]byte(MagicString)); err != nil {
		return err
	}

	if _, err := w.Write([]byte(VersionString)); err != nil {
		return err
	}

	if err := binary.Write(w, binary.BigEndian, iterations); err != nil {
		return err
	}

	saltLen := len(salt)
	if saltLen > 255 {
		return errors.New("salt too long")
	}
	if _, err := w.Write([]byte{uint8(saltLen)}); err != nil {
		return err
	}

	if _, err := w.Write(salt); err != nil {
		return err
	}

	if len(iv) != IVLen {
		return errors.New("invalid IV length")
	}
	if _, err := w.Write(iv); err != nil {
		return err
	}

	return nil
}

func ReadHeader(r io.Reader) (*Header, error) {
	magicBuf := make([]byte, len(MagicString))
	if _, err := io.ReadFull(r, magicBuf); err != nil {
		return nil, ErrShortRead
	}
	if string(magicBuf) != MagicString {
		return nil, ErrInvalidMagic
	}

	verBuf := make([]byte, len(VersionString))
	if _, err := io.ReadFull(r, verBuf); err != nil {
		return nil, ErrShortRead
	}
	if string(verBuf) != VersionString {
		return nil, ErrInvalidVersion
	}

	var iterations uint32
	if err := binary.Read(r, binary.BigEndian, &iterations); err != nil {
		return nil, ErrShortRead
	}
	saltLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, saltLenBuf); err != nil {
		return nil, ErrShortRead
	}
	saltLen := int(saltLenBuf[0])
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, ErrShortRead
	}

	iv := make([]byte, IVLen)
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, ErrShortRead
	}

	return &Header{
		Iterations: iterations,
		Salt:       salt,
		IV:         iv,
	}, nil
}
