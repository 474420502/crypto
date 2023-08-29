package crypto

type ISecretEncDec interface {
	EncodeToString([]byte) string
	DecodeString(string) ([]byte, error)
}
