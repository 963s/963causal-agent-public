// daq-seed mints BDN keys for N witnesses, persists each one to a
// file inside --dir, and prints the resulting roster as JSON so an
// operator can paste it into the control-plane DB (or feed it to
// `psql < roster.json`).
//
// This tool is the control plane's side of the "generate once, keep
// private keys local to each witness" pattern: the private halves
// live in files on the agent host, the roster (public halves + URLs
// + labels) is the only thing the server ever sees.
//
// Typical local-dev flow:
//
//   mkdir -p /var/lib/963causal/daq/witnesses
//   bin/daq-seed --dir /var/lib/963causal/daq/witnesses --base-port 17001 > /tmp/roster.json
//   # then start PM2 / systemd for the 5 witnesses, pointing them at
//   # the same key files
//
// The printed JSON is the exact body the seed-roster SQL script
// passes into Prisma on first launch.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/963causal/agent/internal/daq"
)

type rosterEntry struct {
	Index     int    `json:"index"`
	Label     string `json:"label"`
	URL       string `json:"url"`
	Pubkey    string `json:"pubkey"`
	KeyFile   string `json:"key_file"`
	// AuthToken is the plaintext 32-byte bearer token the witness
	// is configured to require. The seed tool also drops a
	// parallel "<keyfile>.token" file with the token so the
	// operator can feed the witness via --auth-token-file.
	AuthToken string `json:"auth_token"`
}

type rosterEnvelope struct {
	Threshold int           `json:"threshold"`
	Witnesses []rosterEntry `json:"witnesses"`
}

func main() {
	dir := flag.String("dir", "/var/lib/963causal/daq", "directory for per-witness private-key files")
	n := flag.Int("n", 5, "number of witnesses to mint")
	threshold := flag.Int("threshold", 3, "k in the k-of-n threshold")
	basePort := flag.Int("base-port", 17001, "first port; witness i listens on base_port+i")
	host := flag.String("host", "127.0.0.1", "host to publish in the roster URL")
	overwrite := flag.Bool("overwrite", false, "if set, re-mint keys even if the file already exists")
	flag.Parse()

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatalf("mkdir %s: %v", *dir, err)
	}
	if *n < 1 || *n > 32 {
		log.Fatalf("n must be 1..32, got %d", *n)
	}
	if *threshold < 1 || *threshold > *n {
		log.Fatalf("threshold must be 1..%d, got %d", *n, *threshold)
	}

	envelope := rosterEnvelope{Threshold: *threshold}
	for i := 0; i < *n; i++ {
		keyPath := filepath.Join(*dir, fmt.Sprintf("witness-%02d.key", i))
		tokenPath := keyPath + ".token"
		var (
			priv   *daq.PrivateKey
			pub    *daq.PublicKey
			err    error
			minted bool
		)
		if _, statErr := os.Stat(keyPath); statErr == nil && !*overwrite {
			priv, pub, _, err = daq.LoadOrCreateWitnessKey(keyPath)
		} else {
			priv, pub, err = daq.GenerateKeyPair()
			if err == nil {
				err = daq.SaveWitnessKey(keyPath, priv)
				minted = true
			}
		}
		if err != nil {
			log.Fatalf("witness %d: %v", i, err)
		}
		pubBytes, _ := pub.MarshalBinary()
		url := fmt.Sprintf("http://%s:%d", *host, *basePort+i)

		// Provision an auth token. Reuse the one already on disk if
		// the key file was reused (so restarting this tool does not
		// silently rotate tokens on existing witnesses); mint a
		// fresh 32-byte random token otherwise.
		var token string
		if !minted && !*overwrite {
			if existing, readErr := os.ReadFile(tokenPath); readErr == nil {
				token = trimSpace(string(existing))
			}
		}
		if token == "" {
			var tb [32]byte
			if _, err := rand.Read(tb[:]); err != nil {
				log.Fatalf("witness %d: token entropy: %v", i, err)
			}
			token = hex.EncodeToString(tb[:])
			if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
				log.Fatalf("witness %d: write token: %v", i, err)
			}
		}

		envelope.Witnesses = append(envelope.Witnesses, rosterEntry{
			Index:     i,
			Label:     fmt.Sprintf("witness-%02d", i),
			URL:       url,
			Pubkey:    hex.EncodeToString(pubBytes),
			KeyFile:   keyPath,
			AuthToken: token,
		})
		fmt.Fprintf(os.Stderr, "  w=%d key=%s pub=%s… token=%s %s\n",
			i, keyPath, hex.EncodeToString(pubBytes)[:16], token[:12]+"…",
			map[bool]string{true: "[minted]", false: "[existing]"}[minted])
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envelope); err != nil {
		log.Fatalf("emit roster: %v", err)
	}
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\n' || s[j-1] == '\r' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}
