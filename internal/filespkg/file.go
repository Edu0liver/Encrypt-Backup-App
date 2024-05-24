package filespkg

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Edu0liver/Encrypt-Backup-App/internal/encryption"
)

var FileDB []File

type File struct {
	Filename          *string
	EncryptedFilename string
	DecryptedFilename string
	Encrypted         bool
	aesEncryptor      *encryption.AesEncryptor
}

func NewFile(filename *string) *File {
	return &File{
		Filename:          filename,
		EncryptedFilename: *filename + ".enc",
		DecryptedFilename: *filename + ".decr",
		Encrypted:         false,
		aesEncryptor:      encryption.NewAesEncryptor(),
	}
}

func (f *File) Encrypt(file io.Reader) error {
	if f.Encrypted {
		return fmt.Errorf("already encrypted")
	}

	filePath := filepath.Join("../../tmp", f.EncryptedFilename)

	newEncryptedFile, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %v", err)
	}
	defer newEncryptedFile.Close()

	err = f.aesEncryptor.Encrypt(file, newEncryptedFile)
	if err != nil {
		return err
	}

	f.Encrypted = true

	return nil
}

func (f *File) Decrypt() error {
	if !f.Encrypted {
		return fmt.Errorf("not encrypted")
	}

	encryptedFile, err := os.Open(fmt.Sprintf("../../tmp/%s", f.EncryptedFilename))
	if err != nil {
		return fmt.Errorf("failed to open encrypted file: %v", err)
	}
	defer encryptedFile.Close()

	newDecryptedFile, err := os.Create(fmt.Sprintf("../../tmp/%s", f.DecryptedFilename))
	if err != nil {
		return fmt.Errorf("failed to create decrypted file: %v", err)
	}

	defer newDecryptedFile.Close()

	err = f.aesEncryptor.Decrypt(encryptedFile, newDecryptedFile)
	if err != nil {
		return err
	}
	f.Encrypted = false

	return nil
}
