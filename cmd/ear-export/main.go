// ear-export converts a silicon-cert JSON document into a COSE_Sign1_Tagged
// binary (EAR — External Attestation Record per BSL ADR-023).
//
// Typical flow:
//
//	go run ./cmd/ear-export sign -in cert.json -key export.key -out record.cbor
//	go run ./cmd/ear-export verify -in record.cbor -pub <hex64>
//
// Export key is Ed25519: raw 32-byte seed file OR 64-byte expanded private key.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/963causal/agent/internal/earpack"
	"github.com/963causal/agent/internal/siliconcert"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "sign":
		fs := flag.NewFlagSet("sign", flag.ExitOnError)
		inPath := fs.String("in", "", "path to silicon-cert JSON (siliconcert v1)")
		keyPath := fs.String("key", "", "path to Ed25519 export private key file (raw bytes)")
		outPath := fs.String("out", "", "output path for COSE CBOR (.cbor)")
		scope := fs.String("scope", "", "optional scope string (default: ADR-023 line)")
		_ = fs.Parse(os.Args[2:])
		if *inPath == "" || *keyPath == "" || *outPath == "" {
			fs.Usage()
			os.Exit(2)
		}
		certRaw, err := os.ReadFile(*inPath)
		if err != nil {
			die(err)
		}
		cert, err := siliconcert.ParseV1(certRaw)
		if err != nil {
			die(err)
		}
		keyFile, err := os.Open(*keyPath)
		if err != nil {
			die(err)
		}
		defer keyFile.Close()
		priv, err := earpack.ReadEd25519PrivateFile(keyFile)
		if err != nil {
			die(err)
		}
		out, err := earpack.SignDocument(cert, priv, *scope)
		if err != nil {
			die(err)
		}
		if err := os.WriteFile(*outPath, out, 0o644); err != nil {
			die(err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d bytes COSE Sign1)\n", *outPath, len(out))

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		inPath := fs.String("in", "", "path to COSE .cbor file")
		pubHex := fs.String("pub", "", "Ed25519 public key (64 hex chars)")
		_ = fs.Parse(os.Args[2:])
		if *inPath == "" || *pubHex == "" {
			fs.Usage()
			os.Exit(2)
		}
		pub, err := hex.DecodeString(*pubHex)
		if err != nil || len(pub) != 32 {
			die(fmt.Errorf("pub must be 64 hex chars (32 bytes Ed25519 public key)"))
		}
		raw, err := os.ReadFile(*inPath)
		if err != nil {
			die(err)
		}
		pl, cert, err := earpack.VerifyDocument(raw, pub)
		if err != nil {
			die(err)
		}
		fmt.Printf("EAR ok version=%s scope=%q sc_ver=%s inner_op=%s\n",
			pl.V, pl.Scope, pl.ScVer, cert.Workload.OpID)

	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  ear-export sign  -in <silicon-cert.json> -key <export.key> -out <record.cbor> [-scope text]
  ear-export verify -in <record.cbor> -pub <64-hex-ed25519-pubkey>

Export key file: raw 32-byte seed OR 64-byte expanded Ed25519 private key.

`)
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "ear-export: %v\n", err)
	os.Exit(1)
}
