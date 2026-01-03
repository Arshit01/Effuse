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

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/pterm/pterm"
)

// Reads a PEM file, strips headers, and hashes the content to derive a 32-byte key.
func GetKeyFromPEM(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var keyBuilder strings.Builder
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----") {
			continue
		}
		keyBuilder.WriteString(line)
	}
	
	keyData := keyBuilder.String()
	var decoded []byte

	// Try strict base64 decoding
	d, err := base64.StdEncoding.DecodeString(keyData)
	if err == nil {
		decoded = d
	} else {
		// Fallback to raw bytes
		decoded = data
	}

	hash := sha256.Sum256(decoded)
	return hash[:], nil
}

type DeterministicReader struct {
	cipher cipher.Stream
}

func NewDeterministicReader(seed []byte) (*DeterministicReader, error) {
	// Use SHA256 to hash seed to 32 bytes
	key := sha256.Sum256(seed)
	
	// Create AES cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	
	// Use CTR mode with a zero IV for determinism
	iv := make([]byte, aes.BlockSize)
	ctr := cipher.NewCTR(block, iv)
	
	return &DeterministicReader{cipher: ctr}, nil
}

func (r *DeterministicReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	r.cipher.XORKeyStream(p, p)
	return len(p), nil
}

// Writes "key.pem" using the sourceFile and password for entropy.
func GenerateDeterministicRSAKeys(sourceFile, password string) error {
	f, err := os.Open(sourceFile)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(1024, 0); err != nil {
		return err
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(f, salt); err != nil {
		return errors.New("source file too small")
	}

	// Derive strong Master seed
	master := DeriveKey(password, salt, 10000)

	// Create Deterministic Reader
	randReader, err := NewDeterministicReader(master)
	if err != nil {
		return err
	}

	// Generate Key
	spinner, _ := pterm.DefaultSpinner.Start("Generating RSA key (deterministically)...")

	// Generate two large primes sequentially
	p, err := generatePrime(randReader, 4096/2)
	if err != nil {
		return err
	}
	q, err := generatePrime(randReader, 4096/2)
	if err != nil {
		return err
	}

	// Calculate N = p * q
	n := new(big.Int).Mul(p, q)
	
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(p, one)
	qMinus1 := new(big.Int).Sub(q, one)
	totient := new(big.Int).Mul(pMinus1, qMinus1)
	
	e := 65537
	bigE := big.NewInt(int64(e))
	
	d := new(big.Int).ModInverse(bigE, totient)
	if d == nil {
		return errors.New("failed to generate private key (inverse not found)")
	}

	dP := new(big.Int).Mod(d, pMinus1)
	dQ := new(big.Int).Mod(d, qMinus1)
	qInv := new(big.Int).ModInverse(q, p)

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: e,
		},
		D:      d,
		Primes: []*big.Int{p, q},
		Precomputed: rsa.PrecomputedValues{
			Dp:   dP,
			Dq:   dQ,
			Qinv: qInv,
		},
	}
	
	spinner.Success("Key generation completed")

	// Export to PEM
	outFile, err := os.Create("key.pem")
	if err != nil {
		return err
	}
	defer outFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}

	if err := pem.Encode(outFile, pemBlock); err != nil {
		return err
	}
	
	pterm.Success.Println("Key exported to key.pem")
	return nil
}

// Finds a prime of byte length bits/8 using the reader
func generatePrime(r io.Reader, bits int) (*big.Int, error) {
	bytes := bits / 8
	buf := make([]byte, bytes)
	
	// Maximum attempts to find a prime
	for i := 0; i < 10000; i++ {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		
		// high and low bits to ensure it is a large odd number
		buf[0] |= 0x80
		buf[bytes-1] |= 0x1
		
		p := new(big.Int).SetBytes(buf)
		
		if p.ProbablyPrime(20) {
			return p, nil
		}
	}
	return nil, errors.New("failed to generate prime: too many iterations")
}

func GenerateRandomSalt() []byte {
	b := make([]byte, 16)
	rand.Read(b)
	return b
}
