package util

import (
	"crypto/rand"
	"fmt"
)

func GenerateRandomBytes(n int) ([]byte, error) {
	buffer := make([]byte, n)
	_, err := rand.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %v random bytes: %v", n, err)
	}
	return buffer, nil
}