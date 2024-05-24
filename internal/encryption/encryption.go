package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	mathRand "math/rand"
)

const (
	letterBytes  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	specialBytes = "!@#$%^&*()_+-=[]{}\\|;':\",.<>/?`~"
	numBytes     = "0123456789"
)

type AesEncryptor struct {
	Key []byte
}

func NewAesEncryptor() *AesEncryptor {
	return &AesEncryptor{
		Key: []byte(generateKey(256, true, true, true)),
	}
}

func (a *AesEncryptor) Encrypt(in io.Reader, out io.Writer) error {
	// Create a new AES cipher block
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}

	// GCM mode is used here
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create a nonce. GCM standard requires a unique nonce for each encryption.
	nonce := make([]byte, aesGCM.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Write the nonce to the output writer
	_, err = out.Write(nonce)
	if err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}

	// Encrypt the data in chunks
	buffer := make([]byte, 4096)

	for {
		n, err := in.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read input: %w", err)
		}

		if n == 0 {
			break
		}

		ciphertext := aesGCM.Seal(nil, nonce, buffer[:n], nil)

		_, err = out.Write(ciphertext)
		if err != nil {
			return fmt.Errorf("failed to write encrypted data: %w", err)
		}
	}

	return nil
}

func (a *AesEncryptor) Decrypt(in io.Reader, out io.Writer) error {
	// Creating block of algorithm
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Creating GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Read the nonce from the input reader
	nonce := make([]byte, aesGCM.NonceSize())

	_, err = io.ReadFull(in, nonce)
	if err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	// Decrypt the data in chunks
	buffer := make([]byte, 4096+aesGCM.Overhead())
	for {
		n, err := in.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read input: %w", err)
		}

		if n == 0 {
			break
		}

		plaintext, err := aesGCM.Open(nil, nonce, buffer[:n], nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %w", err)
		}

		_, err = out.Write(plaintext)
		if err != nil {
			return fmt.Errorf("failed to write decrypted data: %w", err)
		}
	}

	return nil
}

func generateKey(length int, useLetters bool, useSpecial bool, useNum bool) string {
	b := make([]byte, length)
	for i := range b {
		if useLetters {
			b[i] = letterBytes[mathRand.Intn(len(letterBytes))]
		} else if useSpecial {
			b[i] = specialBytes[mathRand.Intn(len(specialBytes))]
		} else if useNum {
			b[i] = numBytes[mathRand.Intn(len(numBytes))]
		}
	}
	return string(b)
}
