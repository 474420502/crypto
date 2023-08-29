package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/gob"
	"sync"
)

type SecretCRT[T any] struct {
	srcKey        string
	secretKey     []byte
	iv            []byte
	derivationKey func(keysting string) []byte
	mu            sync.Mutex
	EncDec        ISecretEncDec
}

func NewSecretCRT[T any](key string, iv string) *SecretCRT[T] {
	s := &SecretCRT[T]{
		derivationKey: DerivationKeyV1,
		iv:            []byte(iv),
		EncDec:        base64.RawURLEncoding,
	}
	s.secretKey = s.derivationKey(key)
	return s
}

func (s *SecretCRT[T]) UpdateDerivationKeyFunc(kfunc func(keysting string) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.derivationKey = kfunc
	s.secretKey = s.derivationKey(s.srcKey)
}

func (s *SecretCRT[T]) Encrypt(gobj *T) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var buf = bytes.NewBuffer(nil)
	err := gob.NewEncoder(buf).Encode(gobj)
	if err != nil {
		return "", err
	}

	// 使用AES加密,返回一个Block接口
	block, err := aes.NewCipher(s.secretKey)
	if err != nil {
		panic(err)
	}

	// 使用CTR模式
	stream := cipher.NewCTR(block, s.iv)

	// 加密明文
	plaintext := buf.Bytes()
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	// 转为hex编码打印出来

	return s.EncDec.EncodeToString(ciphertext), nil
}

func (s *SecretCRT[T]) Decrypt(ciphertext string) (*T, error) {
	// 将hex解码成[]byte

	ciphertextbytes, err := s.EncDec.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	// 生成Block接口
	block, err := aes.NewCipher(s.secretKey)
	if err != nil {
		panic(err)
	}

	// 生成CTR模式
	stream := cipher.NewCTR(block, s.iv)

	// 解密密文
	plaintext := make([]byte, len(ciphertextbytes))
	stream.XORKeyStream(plaintext, ciphertextbytes)

	// 解出golang的结构体
	var protected T
	var buf = bytes.NewBuffer(plaintext)
	err = gob.NewDecoder(buf).Decode(&protected)
	if err != nil {
		return nil, err
	}
	return &protected, nil
}
