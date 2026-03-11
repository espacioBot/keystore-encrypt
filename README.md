# keystore-encrypt

Go package for encrypting/decrypting private keys using the Ethereum Keystore V3 format (scrypt + AES-128-CTR). Supports EVM (secp256k1) and Ed25519 key generation.

```
go get github.com/espacioBot/keystore-encrypt
```

Import as:
```go
import keystore "github.com/espacioBot/keystore-encrypt"
```

## API Reference

### Core: Encrypt / Decrypt

```go
// Encrypt any private key bytes into a Keystore V3 JSON blob.
func Encrypt(privateKey []byte, password string, params ScryptParams) ([]byte, error)

// EncryptWithAddress encrypts and embeds an address field (for EVM keystores).
func EncryptWithAddress(privateKey []byte, password string, params ScryptParams, address string) ([]byte, error)

// Decrypt a Keystore V3 JSON blob back to private key bytes.
func Decrypt(keystoreJSON []byte, password string) ([]byte, error)
```

**Example:**
```go
secret := []byte("my-32-byte-private-key-material!")

// Encrypt
ksJSON, err := keystore.Encrypt(secret, "mypassword", keystore.DefaultScryptParams())

// Decrypt
decrypted, err := keystore.Decrypt(ksJSON, "mypassword")
// decrypted == secret
```

### EVM Key Generation

```go
type EVMKey struct {
    Address      string // EIP-55 checksummed, e.g. "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    KeystoreJSON []byte // Keystore V3 JSON containing the encrypted secp256k1 private key
}

func GenerateEVMKey(password string, params ScryptParams) (*EVMKey, error)
```

**Example:**
```go
result, err := keystore.GenerateEVMKey("mypassword", keystore.DefaultScryptParams())
fmt.Println(result.Address)       // "0x..."
os.WriteFile("keystore.json", result.KeystoreJSON, 0600)

// Later: recover private key
privBytes, err := keystore.Decrypt(result.KeystoreJSON, "mypassword")
// privBytes is the raw 32-byte secp256k1 private key
```

### Ed25519 Key Generation

```go
type Ed25519Key struct {
    PublicKey    ed25519.PublicKey // 32 bytes
    KeystoreJSON []byte           // Keystore V3 JSON containing the encrypted 32-byte seed
}

func GenerateEd25519Key(password string, params ScryptParams) (*Ed25519Key, error)
```

**Example:**
```go
result, err := keystore.GenerateEd25519Key("mypassword", keystore.DefaultScryptParams())
fmt.Printf("pubkey: %x\n", result.PublicKey)

// Later: recover key pair from keystore
seed, err := keystore.Decrypt(result.KeystoreJSON, "mypassword")
priv := ed25519.NewKeyFromSeed(seed)
sig := ed25519.Sign(priv, []byte("hello"))
```

### Scrypt Parameters

```go
// Production (N=262144, ~1s on modern hardware)
keystore.DefaultScryptParams()

// Testing (N=4096, fast)
keystore.LightScryptParams()

// Custom
keystore.ScryptParams{N: 131072, R: 8, P: 1, DKLen: 32}
```

Use `LightScryptParams()` in tests to avoid slow key derivation.

## Keystore V3 JSON Format

Output follows the [Web3 Secret Storage Definition](https://ethereum.org/en/developers/docs/data-structures-and-encoding/web3-secret-storage/):

```json
{
  "address": "7ef5a6135f1fd6a02593eedc869c6d41d934aef8",
  "version": 3,
  "id": "uuid-v4",
  "crypto": {
    "cipher": "aes-128-ctr",
    "ciphertext": "hex-encoded",
    "cipherparams": { "iv": "hex-encoded-16-bytes" },
    "kdf": "scrypt",
    "kdfparams": { "n": 262144, "r": 8, "p": 1, "dklen": 32, "salt": "hex-encoded-32-bytes" },
    "mac": "keccak256(dk[16:32] + ciphertext)"
  }
}
```

The `address` field is present for EVM keystores (40-character lowercase hex, no `0x` prefix, matching geth V3 format). For non-EVM keys (e.g., Ed25519), the field is omitted.

## File Structure

| File | Contents |
|---|---|
| `keystore.go` | Types (`KeystoreV3`, `CryptoJSON`, `ScryptParams`), `Encrypt()`, `Decrypt()`, internal helpers |
| `evm.go` | `EVMKey`, `GenerateEVMKey()` — secp256k1 key gen + EIP-55 address |
| `ed25519.go` | `Ed25519Key`, `GenerateEd25519Key()` — Ed25519 key gen |

## Security Notes

- Private keys and derived keys are zeroed after use via `zeroBytes()`
- MAC verification uses `crypto/subtle.ConstantTimeCompare`
- All randomness sourced from `crypto/rand`
- The private key never appears in the returned structs — only the encrypted keystore JSON

## Dependencies

- `golang.org/x/crypto` — scrypt KDF, Keccak-256 (Go official)
- `github.com/ethereum/go-ethereum/crypto` — secp256k1 key generation and address derivation
- Go standard library — `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/ed25519`
