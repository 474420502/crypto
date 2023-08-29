package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"sync"
)

func init() {
	gob.Register(map[string]any{})
	gob.Register([]any{})
	gob.Register([]map[string]any{})
	gob.Register([]string{})
}

func DerivationKeyV1(keysting string) []byte {
	key := []byte(keysting)

	var result [16]byte

	// If key length is more than 32, truncate it
	if len(key) > 16 {
		key = key[:16]
	}

	// If key length is less than 32, replicate it until it reaches 32
	for len(key) < 16 {
		key = append(key, key...)
	}

	// Only take the first 32 bytes
	key = key[:16]

	// Swap the first 16 bytes with the last 16 bytes
	copy(result[:], key[8:])
	copy(result[8:], key[:8])

	return result[:]
}

type SecretGCM[T any] struct {
	srcKey        string
	secretKey     []byte
	derivationKey func(keysting string) []byte
	mu            sync.Mutex
	EncDec        ISecretEncDec
}

func NewSecretGCM[T any](key string) *SecretGCM[T] {
	s := &SecretGCM[T]{
		srcKey:        key,
		derivationKey: DerivationKeyV1,
		EncDec:        base64.RawURLEncoding,
	}
	s.secretKey = s.derivationKey(s.srcKey)
	return s
}

func (s *SecretGCM[T]) UpdateDerivationKeyFunc(kfunc func(keysting string) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.derivationKey = kfunc
	s.secretKey = s.derivationKey(s.srcKey)
}

func (s *SecretGCM[T]) Encrypt(gobj *T) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var buf = bytes.NewBuffer(nil)
	err := gob.NewEncoder(buf).Encode(gobj)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.secretKey)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, buf.Bytes(), nil)

	return s.EncDec.EncodeToString(ciphertext), nil
}

func (s *SecretGCM[T]) Decrypt(ciphertext string) (*T, error) {
	block, err := aes.NewCipher(s.secretKey)
	if err != nil {
		return nil, err
	}

	ct, err := s.EncDec.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	if len(ct) < 12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, ct[:12], ct[12:], nil)
	if err != nil {
		return nil, err
	}

	// 解出golang的结构体
	var protected T
	var buf = bytes.NewBuffer(plaintext)
	err = gob.NewDecoder(buf).Decode(&protected)
	if err != nil {
		return nil, err
	}
	return &protected, nil
}
