package crypto

import "net/url"

type ConfirmationLink[T any] struct {
	// Secret    []byte
	SecretGCM *SecretGCM[T]

	DefaultQueryKey string // 默认key 是 token
	link            *url.URL
}

func NewConfirmationLink[T any](key string, UrlStr string) *ConfirmationLink[T] {
	u, err := url.Parse(UrlStr)
	if err != nil {
		panic(err)
	}

	return &ConfirmationLink[T]{
		SecretGCM:       NewSecretGCM[T](key),
		DefaultQueryKey: "token",
		link:            u,
	}
}

// Generate 序列化链接传入需求的obj
func (cl *ConfirmationLink[T]) Generate(obj *T) (string, error) {

	token, err := cl.Encrypt(obj)
	if err != nil {
		return "", err
	}

	return cl.GenerateWithToken(token)
}

// GenerateWithToken 序列化url带token
func (cl *ConfirmationLink[T]) GenerateWithToken(token string) (string, error) {

	q := cl.link.Query()
	if q.Has(cl.DefaultQueryKey) {
		q.Set(cl.DefaultQueryKey, token)
	} else {
		q.Add(cl.DefaultQueryKey, token)
	}

	// 生成确认链接
	cl.link.RawQuery = q.Encode()

	return cl.link.String(), nil
}

// Encrypt golang加密后的数据
func (cl *ConfirmationLink[T]) Encrypt(obj *T) (string, error) {
	return cl.SecretGCM.Encrypt(obj)
}

// Decrypt Encrypt加密后的数据解密 obj
func (cl *ConfirmationLink[T]) Decrypt(ciphertext string) (*T, error) {
	return cl.SecretGCM.Decrypt(ciphertext)
}
