// silicon-cert converts a verified DAQ ticket into a portable Silicon
// Certificate JSON (schema 963causal.silicon-cert/v1) or verifies such a file
// offline given a witness roster (same hex pubkey format as daq-seed).
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/963causal/agent/internal/daq"
	"github.com/963causal/agent/internal/siliconcert"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "wrap":
		fs := flag.NewFlagSet("wrap", flag.ExitOnError)
		ticketPath := fs.String("ticket", "", "path to JSON daq.Ticket (from quorum client)")
		label := fs.String("label", "", "human workload label stored in cert")
		_ = fs.Parse(os.Args[2:])
		if *ticketPath == "" {
			fs.Usage()
			os.Exit(2)
		}
		raw, err := os.ReadFile(*ticketPath)
		if err != nil {
			die(err)
		}
		var tk daq.Ticket
		if err := json.Unmarshal(raw, &tk); err != nil {
			die(fmt.Errorf("parse ticket: %w", err))
		}
		cert, err := siliconcert.FromTicket(&tk, *label)
		if err != nil {
			die(err)
		}
		out, err := cert.MarshalJSONBytes()
		if err != nil {
			die(err)
		}
		os.Stdout.Write(out)
		os.Stdout.Write([]byte("\n"))

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		certPath := fs.String("cert", "", "path to silicon-cert JSON")
		rosterPath := fs.String("roster", "", "path to roster JSON (daq-seed format)")
		_ = fs.Parse(os.Args[2:])
		if *certPath == "" || *rosterPath == "" {
			fs.Usage()
			os.Exit(2)
		}
		certRaw, err := os.ReadFile(*certPath)
		if err != nil {
			die(err)
		}
		v, err := siliconcert.ParseV1(certRaw)
		if err != nil {
			die(err)
		}
		pubs, err := loadRosterPubkeys(*rosterPath)
		if err != nil {
			die(err)
		}
		if err := siliconcert.Verify(v, pubs); err != nil {
			fmt.Fprintf(os.Stderr, "VERIFY FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("VERIFY OK")

	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  silicon-cert wrap  -ticket <daq-ticket.json> [-label text] > cert.json
  silicon-cert verify -cert <cert.json> -roster <roster.json>

Roster JSON is the envelope printed by daq-seed (witnesses[].pubkey hex).

`)
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "silicon-cert: %v\n", err)
	os.Exit(1)
}

type rosterWitness struct {
	Index  int    `json:"index"`
	Pubkey string `json:"pubkey"`
}

type rosterFile struct {
	Threshold int             `json:"threshold"`
	Witnesses []rosterWitness `json:"witnesses"`
}

func loadRosterPubkeys(path string) ([]*daq.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf rosterFile
	if err := json.Unmarshal(raw, &rf); err != nil {
		return nil, err
	}
	if len(rf.Witnesses) == 0 {
		return nil, errors.New("empty witnesses")
	}
	sort.Slice(rf.Witnesses, func(i, j int) bool {
		return rf.Witnesses[i].Index < rf.Witnesses[j].Index
	})
	maxIdx := rf.Witnesses[len(rf.Witnesses)-1].Index
	if maxIdx >= 256 {
		return nil, errors.New("witness index too large")
	}
	out := make([]*daq.PublicKey, maxIdx+1)
	for _, w := range rf.Witnesses {
		h, err := hex.DecodeString(w.Pubkey)
		if err != nil {
			return nil, fmt.Errorf("witness %d pubkey hex: %w", w.Index, err)
		}
		pk, err := daq.UnmarshalPublicKey(h)
		if err != nil {
			return nil, fmt.Errorf("witness %d: %w", w.Index, err)
		}
		if w.Index < 0 || w.Index >= len(out) {
			return nil, fmt.Errorf("witness index %d out of range", w.Index)
		}
		if out[w.Index] != nil {
			return nil, fmt.Errorf("duplicate witness index %d", w.Index)
		}
		out[w.Index] = pk
	}
	for i := range out {
		if out[i] == nil {
			return nil, fmt.Errorf("missing roster pubkey at index %d", i)
		}
	}
	return out, nil
}
