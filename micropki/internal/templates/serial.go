package templates

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// SerialNumber wraps big.Int for serial number operations
type SerialNumber struct {
	int *big.Int
}

// NewSerialNumber generates a new cryptographically secure serial number
// Implements PKI-2: minimum 20 bits of entropy (we use 160 bits)
func NewSerialNumber() (*SerialNumber, error) {
	// Generate 20 bytes (160 bits) of random data
	bytes := make([]byte, 20)
	if _, err := rand.Read(bytes); err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Ensure positive number by clearing the most significant bit
	bytes[0] &= 0x7F

	return &SerialNumber{
		int: new(big.Int).SetBytes(bytes),
	}, nil
}

// BigInt returns the underlying big.Int
func (s *SerialNumber) BigInt() *big.Int {
	return s.int
}

// Hex returns hexadecimal representation
func (s *SerialNumber) Hex() string {
	return fmt.Sprintf("%X", s.int)
}

// String returns decimal representation
func (s *SerialNumber) String() string {
	return s.int.String()
}
