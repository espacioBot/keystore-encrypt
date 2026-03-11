package keystore

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// EVMKey holds the result of EVM key generation.
type EVMKey struct {
	Address      string // EIP-55 checksum address
	KeystoreJSON []byte
}

// GenerateEVMKey generates a new secp256k1 key pair, encrypts the private key
// into a Keystore V3 blob, and returns the EIP-55 checksummed address.
func GenerateEVMKey(password string, params ScryptParams) (*EVMKey, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating secp256k1 key: %w", err)
	}

	privBytes := crypto.FromECDSA(key)
	defer zeroBytes(privBytes)

	addr := crypto.PubkeyToAddress(key.PublicKey)

	addrHex := strings.ToLower(addr.Hex()[2:]) // 40-char lowercase hex, no 0x prefix

	ksJSON, err := EncryptWithAddress(privBytes, password, params, addrHex)
	if err != nil {
		return nil, fmt.Errorf("encrypting private key: %w", err)
	}

	return &EVMKey{
		Address:      addr.Hex(), // go-ethereum returns EIP-55 checksum
		KeystoreJSON: ksJSON,
	}, nil
}
