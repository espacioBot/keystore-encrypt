package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// Ed25519Key holds the result of Ed25519 key generation.
type Ed25519Key struct {
	PublicKey    ed25519.PublicKey // 32 bytes
	KeystoreJSON []byte
}

// GenerateEd25519Key generates a new Ed25519 key pair, encrypts the seed
// into a Keystore V3 blob, and returns the public key.
func GenerateEd25519Key(password string, params ScryptParams) (*Ed25519Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ed25519 key: %w", err)
	}

	seed := priv.Seed()
	defer zeroBytes(seed)
	defer zeroBytes(priv)

	ksJSON, err := Encrypt(seed, password, params)
	if err != nil {
		return nil, fmt.Errorf("encrypting ed25519 seed: %w", err)
	}

	return &Ed25519Key{
		PublicKey:    pub,
		KeystoreJSON: ksJSON,
	}, nil
}
