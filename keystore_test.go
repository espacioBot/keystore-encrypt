package keystore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	secret := []byte("this is a 32-byte secret key!!")
	password := "testpassword"

	ksJSON, err := Encrypt(secret, password, LightScryptParams())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var ks KeystoreV3
	if err := json.Unmarshal(ksJSON, &ks); err != nil {
		t.Fatalf("unmarshal keystore: %v", err)
	}
	if ks.Version != 3 {
		t.Errorf("version = %d, want 3", ks.Version)
	}
	if ks.Crypto.Cipher != "aes-128-ctr" {
		t.Errorf("cipher = %s, want aes-128-ctr", ks.Crypto.Cipher)
	}

	decrypted, err := Decrypt(ksJSON, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, secret) {
		t.Errorf("decrypted = %x, want %x", decrypted, secret)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	secret := []byte("secret-key-bytes")
	ksJSON, err := Encrypt(secret, "correct", LightScryptParams())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(ksJSON, "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password, got nil")
	}
}

func TestEncryptDecryptKnownKey(t *testing.T) {
	// Use a known 32-byte private key and verify round-trip preserves exact bytes
	knownKey, _ := hex.DecodeString("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
	password := "testpassword"

	ksJSON, err := Encrypt(knownKey, password, LightScryptParams())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Verify JSON structure
	var ks KeystoreV3
	if err := json.Unmarshal(ksJSON, &ks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ks.Crypto.KDF != "scrypt" {
		t.Errorf("kdf = %s, want scrypt", ks.Crypto.KDF)
	}
	if ks.Crypto.KDFParams.N != 4096 {
		t.Errorf("N = %d, want 4096", ks.Crypto.KDFParams.N)
	}

	decrypted, err := Decrypt(ksJSON, password)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, knownKey) {
		t.Errorf("decrypted = %x, want %x", decrypted, knownKey)
	}
}

func TestEncryptOmitsAddress(t *testing.T) {
	secret := []byte("this is a 32-byte secret key!!")
	ksJSON, err := Encrypt(secret, "pass", LightScryptParams())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(ksJSON, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["address"]; ok {
		t.Error("Encrypt() output should not contain address field")
	}
}

func TestEncryptWithAddressIncludesAddress(t *testing.T) {
	secret := []byte("this is a 32-byte secret key!!")
	addr := "7ef5a6135f1fd6a02593eedc869c6d41d934aef8"

	ksJSON, err := EncryptWithAddress(secret, "pass", LightScryptParams(), addr)
	if err != nil {
		t.Fatalf("EncryptWithAddress: %v", err)
	}

	var ks KeystoreV3
	if err := json.Unmarshal(ksJSON, &ks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ks.Address != addr {
		t.Errorf("address = %q, want %q", ks.Address, addr)
	}

	// Verify round-trip decryption still works
	decrypted, err := Decrypt(ksJSON, "pass")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, secret) {
		t.Errorf("decrypted = %x, want %x", decrypted, secret)
	}
}

func TestDecryptInvalidJSON(t *testing.T) {
	_, err := Decrypt([]byte("not json"), "password")
	if err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestDecryptUnsupportedVersion(t *testing.T) {
	ks := `{"version": 2, "crypto": {"cipher": "aes-128-ctr", "kdf": "scrypt", "ciphertext": "aa", "cipherparams": {"iv": "aa"}, "kdfparams": {"n": 4096, "r": 8, "p": 1, "dklen": 32, "salt": "aa"}, "mac": "aa"}}`
	_, err := Decrypt([]byte(ks), "password")
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}
