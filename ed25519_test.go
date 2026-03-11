package keystore

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestGenerateEd25519KeyRoundTrip(t *testing.T) {
	result, err := GenerateEd25519Key("mypassword", LightScryptParams())
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}

	if len(result.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(result.PublicKey), ed25519.PublicKeySize)
	}

	// Decrypt seed and reconstruct key pair
	seed, err := Decrypt(result.KeystoreJSON, "mypassword")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed size = %d, want %d", len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	if !bytes.Equal(pub, result.PublicKey) {
		t.Error("reconstructed public key does not match original")
	}
}

func TestEd25519SignVerify(t *testing.T) {
	result, err := GenerateEd25519Key("password", LightScryptParams())
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}

	seed, err := Decrypt(result.KeystoreJSON, "password")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	message := []byte("hello world")
	sig := ed25519.Sign(priv, message)

	if !ed25519.Verify(result.PublicKey, message, sig) {
		t.Error("signature verification failed")
	}
}

func TestEd25519WrongPassword(t *testing.T) {
	result, err := GenerateEd25519Key("correct", LightScryptParams())
	if err != nil {
		t.Fatalf("GenerateEd25519Key: %v", err)
	}

	_, err = Decrypt(result.KeystoreJSON, "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}
