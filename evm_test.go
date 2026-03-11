package keystore

import (
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestGenerateEVMKeyRoundTrip(t *testing.T) {
	result, err := GenerateEVMKey("password123", LightScryptParams())
	if err != nil {
		t.Fatalf("GenerateEVMKey: %v", err)
	}

	if !strings.HasPrefix(result.Address, "0x") {
		t.Errorf("address should start with 0x, got %s", result.Address)
	}
	if len(result.Address) != 42 {
		t.Errorf("address length = %d, want 42", len(result.Address))
	}

	// Decrypt and verify the key can derive the same address
	privBytes, err := Decrypt(result.KeystoreJSON, "password123")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	key, err := crypto.ToECDSA(privBytes)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}

	addr := crypto.PubkeyToAddress(key.PublicKey)
	if addr.Hex() != result.Address {
		t.Errorf("address mismatch: decrypted=%s, original=%s", addr.Hex(), result.Address)
	}
}

func TestEIP55Checksum(t *testing.T) {
	// Known private key → known EIP-55 address
	privHex := "4c0883a69102937d6231471b5dbb6204fe512961708279f51bd1e0f8c1397e02"
	privBytes, _ := hex.DecodeString(privHex)

	key, err := crypto.ToECDSA(privBytes)
	if err != nil {
		t.Fatalf("ToECDSA: %v", err)
	}

	addr := crypto.PubkeyToAddress(key.PublicKey)
	expected := "0x488406940362BcdC2c7969E8d45c462567b33d4E"
	if addr.Hex() != expected {
		t.Errorf("EIP-55 address = %s, want %s", addr.Hex(), expected)
	}
}

func TestEVMKeystoreContainsAddress(t *testing.T) {
	result, err := GenerateEVMKey("password123", LightScryptParams())
	if err != nil {
		t.Fatalf("GenerateEVMKey: %v", err)
	}

	var ks KeystoreV3
	if err := json.Unmarshal(result.KeystoreJSON, &ks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// address must be 40-char lowercase hex, no 0x prefix
	if len(ks.Address) != 40 {
		t.Errorf("address length = %d, want 40", len(ks.Address))
	}
	if matched, _ := regexp.MatchString("^[0-9a-f]{40}$", ks.Address); !matched {
		t.Errorf("address %q is not lowercase hex without 0x prefix", ks.Address)
	}

	// address must match the EIP-55 address (case-insensitive)
	expectedAddr := strings.ToLower(result.Address[2:]) // strip 0x, lowercase
	if ks.Address != expectedAddr {
		t.Errorf("address = %q, want %q", ks.Address, expectedAddr)
	}
}

func TestGenerateEVMKeyWrongPassword(t *testing.T) {
	result, err := GenerateEVMKey("correct", LightScryptParams())
	if err != nil {
		t.Fatalf("GenerateEVMKey: %v", err)
	}

	_, err = Decrypt(result.KeystoreJSON, "wrong")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}
