package secrets

type SecretLoader interface {
	GetSecret(string) (*map[string][]byte, error)
}
