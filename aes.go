package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// CryptoJS-compatible AES-256-CBC encryption/decryption.
// Uses MD5-based key derivation (OpenSSL EVP_BytesToKey) for compatibility
// with existing encrypted PHP/CryptoJS logs.

func aesEncrypt(value interface{}, passphrase string) (string, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key, iv := evpBytesToKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// PKCS7 padding
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	result := map[string]string{
		"ct": base64.StdEncoding.EncodeToString(ciphertext),
		"iv": hex.EncodeToString(iv),
		"s":  hex.EncodeToString(salt),
	}

	out, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func aesDecrypt(jsonStr string, passphrase string) (json.RawMessage, error) {
	var data struct {
		CT string `json:"ct"`
		IV string `json:"iv"`
		S  string `json:"s"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil, err
	}

	salt, err := hex.DecodeString(data.S)
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(data.CT)
	if err != nil {
		return nil, err
	}

	key, iv := evpBytesToKey(passphrase, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove PKCS7 padding
	padLen := int(ciphertext[len(ciphertext)-1])
	if padLen > aes.BlockSize || padLen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	plaintext := ciphertext[:len(ciphertext)-padLen]

	return json.RawMessage(plaintext), nil
}

// evpBytesToKey derives a 32-byte key and 16-byte IV from passphrase+salt
// using the same MD5-based algorithm as OpenSSL/CryptoJS.
func evpBytesToKey(passphrase string, salt []byte) ([]byte, []byte) {
	var derived []byte
	var block []byte

	for len(derived) < 48 {
		h := md5.New()
		h.Write(block)
		h.Write([]byte(passphrase))
		h.Write(salt)
		block = h.Sum(nil)
		derived = append(derived, block...)
	}

	return derived[:32], derived[32:48]
}
