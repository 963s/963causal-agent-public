// puf-attest-once is a debug utility that takes a fresh PUF measurement
// and ships it to the control plane as an attestation, reusing the
// production enrollment flow. It exists so operators can exercise the
// server pipeline without waiting for the 6h attestation ticker.
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"log"
	"os"
	"time"

	"github.com/963causal/agent/internal/config"
	"github.com/963causal/agent/internal/identity"
	"github.com/963causal/agent/internal/license"
	"github.com/963causal/agent/internal/puf"
	agentpb "github.com/963causal/agent/proto"
)

func main() {
	configPath := flag.String("config", "/etc/963causal/agent.yaml", "path to agent.yaml")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	hk, err := identity.LoadOrCreate(cfg.KeystorePath)
	if err != nil {
		log.Fatalf("load identity: %v", err)
	}
	ecdh, err := identity.NewECDH()
	if err != nil {
		log.Fatalf("ecdh: %v", err)
	}
	defer ecdh.Zero()

	lc := license.NewClient(cfg.ControlPlaneURL, cfg.InsecureSkipTLSVerify)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	hostname, _ := os.Hostname()
	nonceBytes := make([]byte, 8)
	_, _ = rand.Read(nonceBytes)
	req := &agentpb.EnrollRequest{
		LicenseKey:    cfg.LicenseKey,
		PublicKey:     hk.EdPublic,
		X25519Public:  ecdh.Public[:],
		HwFingerprint: identity.HardwareFingerprint(),
		Hostname:      hostname,
		AgentVersion:  "0.5.0-w5a-puf-attestation",
		Nonce:         int64(binary.BigEndian.Uint64(nonceBytes) & 0x7fffffffffffffff),
	}
	enr, err := lc.Enroll(ctx, req)
	if err != nil {
		log.Fatalf("enroll: %v", err)
	}
	log.Printf("host_id=%s; measuring attestation...", enr.HostId)
	att, err := puf.MeasureAttestation(ctx, enr.HostId, "0.5.0-w5a-puf-attestation")
	if err != nil {
		log.Fatalf("measure: %v", err)
	}
	if err := lc.PostPufAttestation(ctx, enr.AgentToken, att); err != nil {
		log.Fatalf("post: %v", err)
	}
	log.Printf("attestation shipped (%dc × %dl × %dt, %.0fms)",
		att.NumCores, att.NumLoops, att.NumTrials, att.DurationMs)
}
