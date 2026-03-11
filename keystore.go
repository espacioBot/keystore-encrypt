package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

// KeystoreV3 represents an Ethereum-style V3 keystore.
type KeystoreV3 struct {
	Address string     `json:"address,omitempty"`
	Version int        `json:"version"`
	ID      string     `json:"id"`
	Crypto  CryptoJSON `json:"crypto"`
}

// CryptoJSON contains the crypto section of the keystore.
type CryptoJSON struct {
	Cipher       string       `json:"cipher"`
	CipherText   string       `json:"ciphertext"`
	CipherParams CipherParams `json:"cipherparams"`
	KDF          string       `json:"kdf"`
	KDFParams    KDFParams    `json:"kdfparams"`
	MAC          string       `json:"mac"`
}

// CipherParams holds the IV for AES-128-CTR.
type CipherParams struct {
	IV string `json:"iv"`
}

// KDFParams holds scrypt parameters.
type KDFParams struct {
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DKLen int    `json:"dklen"`
	Salt  string `json:"salt"`
}

// ScryptParams configures the scrypt key derivation function.
type ScryptParams struct {
	N, R, P, DKLen int
}

// DefaultScryptParams returns standard scrypt parameters (N=262144).
func DefaultScryptParams() ScryptParams {
	return ScryptParams{N: 262144, R: 8, P: 1, DKLen: 32}
}

// LightScryptParams returns fast scrypt parameters for testing (N=4096).
func LightScryptParams() ScryptParams {
	return ScryptParams{N: 4096, R: 8, P: 1, DKLen: 32}
}

// Encrypt encrypts privateKey into a Keystore V3 JSON blob.
func Encrypt(privateKey []byte, password string, params ScryptParams) ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	dk, err := scrypt.Key([]byte(password), salt, params.N, params.R, params.P, params.DKLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation: %w", err)
	}
	defer zeroBytes(dk)

	encKey := dk[:16]
	macKey := dk[16:32]

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("generating iv: %w", err)
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("creating aes cipher: %w", err)
	}

	ciphertext := make([]byte, len(privateKey))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, privateKey)

	mac := keccak256(append(macKey, ciphertext...))

	id, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("generating uuid: %w", err)
	}

	ks := KeystoreV3{
		Version: 3,
		ID:      id,
		Crypto: CryptoJSON{
			Cipher:     "aes-128-ctr",
			CipherText: hex.EncodeToString(ciphertext),
			CipherParams: CipherParams{
				IV: hex.EncodeToString(iv),
			},
			KDF: "scrypt",
			KDFParams: KDFParams{
				N:     params.N,
				R:     params.R,
				P:     params.P,
				DKLen: params.DKLen,
				Salt:  hex.EncodeToString(salt),
			},
			MAC: hex.EncodeToString(mac),
		},
	}

	return json.Marshal(ks)
}

// EncryptWithAddress encrypts privateKey into a Keystore V3 JSON blob with
// the given address embedded. The address should be a 40-character lowercase
// hex string without the "0x" prefix (matching geth's V3 format).
func EncryptWithAddress(privateKey []byte, password string, params ScryptParams, address string) ([]byte, error) {
	raw, err := Encrypt(privateKey, password, params)
	if err != nil {
		return nil, err
	}

	var ks KeystoreV3
	if err := json.Unmarshal(raw, &ks); err != nil {
		return nil, err
	}
	ks.Address = address
	return json.Marshal(ks)
}

// Decrypt decrypts a Keystore V3 JSON blob and returns the private key bytes.
func Decrypt(keystoreJSON []byte, password string) ([]byte, error) {
	var ks KeystoreV3
	if err := json.Unmarshal(keystoreJSON, &ks); err != nil {
		return nil, fmt.Errorf("parsing keystore json: %w", err)
	}

	if ks.Version != 3 {
		return nil, fmt.Errorf("unsupported keystore version: %d", ks.Version)
	}
	if ks.Crypto.Cipher != "aes-128-ctr" {
		return nil, fmt.Errorf("unsupported cipher: %s", ks.Crypto.Cipher)
	}
	if ks.Crypto.KDF != "scrypt" {
		return nil, fmt.Errorf("unsupported kdf: %s", ks.Crypto.KDF)
	}

	salt, err := hex.DecodeString(ks.Crypto.KDFParams.Salt)
	if err != nil {
		return nil, fmt.Errorf("decoding salt: %w", err)
	}

	p := ks.Crypto.KDFParams
	dk, err := scrypt.Key([]byte(password), salt, p.N, p.R, p.P, p.DKLen)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation: %w", err)
	}
	defer zeroBytes(dk)

	macKey := dk[16:32]

	ciphertext, err := hex.DecodeString(ks.Crypto.CipherText)
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}

	expectedMAC := keccak256(append(macKey, ciphertext...))
	storedMAC, err := hex.DecodeString(ks.Crypto.MAC)
	if err != nil {
		return nil, fmt.Errorf("decoding mac: %w", err)
	}

	if subtle.ConstantTimeCompare(expectedMAC, storedMAC) != 1 {
		return nil, errors.New("mac mismatch: wrong password or corrupted keystore")
	}

	iv, err := hex.DecodeString(ks.Crypto.CipherParams.IV)
	if err != nil {
		return nil, fmt.Errorf("decoding iv: %w", err)
	}

	encKey := dk[:16]
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("creating aes cipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

func newUUID() (string, error) {
	var uuid [16]byte
	if _, err := io.ReadFull(rand.Reader, uuid[:]); err != nil {
		return "", err
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
