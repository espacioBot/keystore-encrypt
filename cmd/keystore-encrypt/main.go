package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	keystore "github.com/espacioBot/keystore-encrypt"
)

const usage = `Usage: keystore-encrypt <command> [options]

Commands:
  generate-evm       Generate a new EVM (secp256k1) keystore
  generate-ed25519   Generate a new Ed25519 keystore
  encrypt            Encrypt a hex-encoded private key into a keystore
  decrypt            Decrypt a keystore JSON file

Options:
  -password string   Password for encryption/decryption (required)
  -key string        Hex-encoded private key (required for encrypt)
  -raw string        Raw string to encrypt (alternative to -key)
  -address string    Address to embed in keystore (optional, for encrypt)
  -output string     Output file path (default: stdout)
  -file string       Keystore JSON file to decrypt (required for decrypt)
  -raw-output        Decrypt output as raw string instead of hex (for decrypt)
  -light             Use light scrypt params (fast, for testing only)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	password := fs.String("password", "", "password for encryption/decryption")
	key := fs.String("key", "", "hex-encoded private key (for encrypt)")
	raw := fs.String("raw", "", "raw string to encrypt (alternative to -key)")
	address := fs.String("address", "", "address to embed in keystore (for encrypt)")
	output := fs.String("output", "", "output file path (default: stdout)")
	file := fs.String("file", "", "keystore JSON file to decrypt")
	rawOutput := fs.Bool("raw-output", false, "decrypt output as raw string instead of hex")
	light := fs.Bool("light", false, "use light scrypt params (testing only)")
	fs.Parse(os.Args[2:])

	if *password == "" {
		fatal("error: -password is required")
	}

	switch cmd {
	case "generate-evm":
		generateEVM(*password, *output, *light)
	case "generate-ed25519":
		generateEd25519(*password, *output, *light)
	case "encrypt":
		encrypt(*key, *raw, *password, *address, *output, *light)
	case "decrypt":
		decrypt(*file, *password, *rawOutput)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}

func generateEVM(password, output string, light bool) {
	params := keystore.DefaultScryptParams()
	if light {
		params = keystore.LightScryptParams()
	}

	result, err := keystore.GenerateEVMKey(password, params)
	if err != nil {
		fatal("error: %v", err)
	}

	pretty, _ := json.MarshalIndent(json.RawMessage(result.KeystoreJSON), "", "  ")

	if output != "" {
		if err := os.WriteFile(output, pretty, 0600); err != nil {
			fatal("error writing file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Address:  %s\n", result.Address)
		fmt.Fprintf(os.Stderr, "Keystore: %s\n", output)
	} else {
		fmt.Fprintf(os.Stderr, "Address: %s\n", result.Address)
		fmt.Println(string(pretty))
	}
}

func generateEd25519(password, output string, light bool) {
	params := keystore.DefaultScryptParams()
	if light {
		params = keystore.LightScryptParams()
	}

	result, err := keystore.GenerateEd25519Key(password, params)
	if err != nil {
		fatal("error: %v", err)
	}

	pretty, _ := json.MarshalIndent(json.RawMessage(result.KeystoreJSON), "", "  ")

	if output != "" {
		if err := os.WriteFile(output, pretty, 0600); err != nil {
			fatal("error writing file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Public Key: %s\n", hex.EncodeToString(result.PublicKey))
		fmt.Fprintf(os.Stderr, "Keystore:   %s\n", output)
	} else {
		fmt.Fprintf(os.Stderr, "Public Key: %s\n", hex.EncodeToString(result.PublicKey))
		fmt.Println(string(pretty))
	}
}

func encrypt(keyHex, rawStr, password, address, output string, light bool) {
	if keyHex == "" && rawStr == "" {
		fatal("error: -key or -raw is required for encrypt")
	}
	if keyHex != "" && rawStr != "" {
		fatal("error: -key and -raw are mutually exclusive")
	}

	var privBytes []byte
	if rawStr != "" {
		privBytes = []byte(rawStr)
	} else {
		var err error
		privBytes, err = hex.DecodeString(keyHex)
		if err != nil {
			fatal("error: invalid hex key: %v", err)
		}
	}
	defer func() {
		for i := range privBytes {
			privBytes[i] = 0
		}
	}()

	params := keystore.DefaultScryptParams()
	if light {
		params = keystore.LightScryptParams()
	}

	var (
		ksJSON []byte
		err    error
	)
	if address != "" {
		ksJSON, err = keystore.EncryptWithAddress(privBytes, password, params, address)
	} else {
		ksJSON, err = keystore.Encrypt(privBytes, password, params)
	}
	if err != nil {
		fatal("error: %v", err)
	}

	pretty, _ := json.MarshalIndent(json.RawMessage(ksJSON), "", "  ")

	if output != "" {
		if err := os.WriteFile(output, pretty, 0600); err != nil {
			fatal("error writing file: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Keystore: %s\n", output)
	} else {
		fmt.Println(string(pretty))
	}
}

func decrypt(file, password string, rawOutput bool) {
	if file == "" {
		fatal("error: -file is required for decrypt")
	}

	data, err := os.ReadFile(file)
	if err != nil {
		fatal("error reading file: %v", err)
	}

	privBytes, err := keystore.Decrypt(data, password)
	if err != nil {
		fatal("error: %v", err)
	}

	if rawOutput {
		fmt.Print(string(privBytes))
	} else {
		fmt.Println(hex.EncodeToString(privBytes))
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
