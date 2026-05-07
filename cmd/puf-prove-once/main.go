// puf-prove-once drives exactly one W5b proof-of-possession cycle
// against the already-enrolled local agent: it loads the on-disk
// KeyState, takes a fresh measurement, runs Reproduce, signs a
// self-chosen nonce, and POSTs the proof to /api/agent/puf/key/proof.
// This is the integration-test flavour of `ProveKey`; the real agent
// runs exactly this flow on every ProofInterval tick.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/963causal/agent/internal/config"
	"github.com/963causal/agent/internal/identity"
	"github.com/963causal/agent/internal/license"
	"github.com/963causal/agent/internal/puf"
	agentpb "github.com/963causal/agent/proto"
)

const AgentVersion = "0.6.0-w5b-puf-prove-once"

func main() {
	cfgPath := flag.String("config", config.DefaultPath, "path to agent.yaml")
	tamper := flag.Bool("tamper", false, "flip one byte of the signature before POST (expect reject)")
	replay := flag.Bool("replay", false, "send the same proof twice; second send must be rejected")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	hk, err := identity.LoadOrCreate(cfg.KeystorePath)
	if err != nil {
		log.Fatalf("keystore: %v", err)
	}

	state, err := puf.LoadKeyState(puf.KeyStorePath(cfg.KeystorePath))
	if err != nil {
		log.Fatalf("load key state: %v", err)
	}
	if state == nil {
		log.Fatalf("no puf.keystore.json on this host; run 963causal-agent once to enrol first")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	lc := license.NewClient(cfg.ControlPlaneURL, cfg.InsecureSkipTLSVerify)

	// Run Enroll against the control plane so we get a fresh token,
	// then POST the proof. In production the agent re-uses the token
	// it got at boot; here we keep the tool self-contained.
	ecdh, err := identity.NewECDH()
	if err != nil {
		log.Fatalf("ecdh: %v", err)
	}
	defer ecdh.Zero()
	enrolReq := &agentpb.EnrollRequest{
		LicenseKey:    cfg.LicenseKey,
		PublicKey:     hk.EdPublic,
		X25519Public:  ecdh.Public[:],
		HwFingerprint: identity.HardwareFingerprint(),
		AgentVersion:  AgentVersion,
		TimestampUnix: time.Now().Unix(),
	}
	hostname, _ := os.Hostname()
	enrolReq.Hostname = hostname
	enrolResp, err := lc.Enroll(ctx, enrolReq)
	if err != nil {
		log.Fatalf("enroll: %v", err)
	}
	fmt.Printf("enrolled host_id=%s\n", enrolResp.HostId)

	proof, err := puf.ProveKey(ctx, enrolResp.HostId, AgentVersion, state)
	if err != nil {
		log.Fatalf("prove: %v", err)
	}
	fmt.Printf("proof built: nonce=%x generatedAtMs=%d sig_len=%d\n",
		proof.Nonce, proof.GeneratedAtMs, len(proof.Signature))

	if *tamper {
		proof.Signature[0] ^= 0x01
		fmt.Println("⚠ tampered: flipped signature[0] bit")
	}

	err = lc.PostPufKeyProof(ctx, enrolResp.AgentToken, proof)
	if *tamper || *replay && false {
		// first send in replay mode should succeed; tamper must fail.
	}
	switch {
	case *tamper && err != nil:
		fmt.Printf("expected reject (tamper): %v\n", err)
		return
	case *tamper && err == nil:
		log.Fatalf("tamper: server accepted a bad signature")
	case err != nil:
		log.Fatalf("post proof: %v", err)
	}
	fmt.Println("proof accepted by server")

	if *replay {
		err = lc.PostPufKeyProof(ctx, enrolResp.AgentToken, proof)
		if err == nil {
			log.Fatalf("replay: server accepted a duplicate nonce")
		}
		fmt.Printf("expected reject (replay): %v\n", err)
	}
}
