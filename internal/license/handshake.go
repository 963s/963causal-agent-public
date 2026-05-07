// Package license performs the enroll + heartbeat protocol with the Sentinel
// control plane.
package license

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	agentpb "github.com/963causal/agent/proto"
)

type Client struct {
	baseURL string
	http    *http.Client
}

func NewClient(baseURL string, insecure bool) *Client {
	tlsCfg := &tls.Config{InsecureSkipVerify: insecure}
	return &Client{
		baseURL: baseURL,
		http: &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				IdleConnTimeout:     60 * time.Second,
				MaxIdleConnsPerHost: 4,
			},
		},
	}
}

func (c *Client) Enroll(ctx context.Context, req *agentpb.EnrollRequest) (*agentpb.EnrollResponse, error) {
	body, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal enroll: %w", err)
	}
	r, err := c.post(ctx, "/api/agent/enroll", body, "")
	if err != nil {
		return nil, err
	}
	resp := &agentpb.EnrollResponse{}
	if err := proto.Unmarshal(r, resp); err != nil {
		return nil, fmt.Errorf("unmarshal enroll response: %w", err)
	}
	if resp.HostId == "" {
		return nil, fmt.Errorf("server refused enrollment (empty host_id)")
	}
	return resp, nil
}

func (c *Client) PostFrame(ctx context.Context, token string, signed *agentpb.SignedFrame) error {
	body, err := proto.Marshal(signed)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	_, err = c.post(ctx, "/api/agent/frame", body, token)
	return err
}

// PostAbsenceReport ships Kernel Sentinel absence events to the
// server. Safe to call with an empty events slice (the server ignores
// it); the agent typically only posts once, right after restart.
func (c *Client) PostAbsenceReport(ctx context.Context, token string, rep *agentpb.AbsenceReport) error {
	body, err := proto.Marshal(rep)
	if err != nil {
		return fmt.Errorf("marshal absence report: %w", err)
	}
	_, err = c.post(ctx, "/api/agent/absence", body, token)
	return err
}

// PostPufEnrollment ships the PUF baseline measurement the agent takes on
// its first run on a given host (and again after an operator-triggered
// re-enrollment). Server-side this upserts the enrollment row and flips
// host.pufEnrolled; the agent discards the handle on success.
func (c *Client) PostPufEnrollment(ctx context.Context, token string, rep *agentpb.PufEnrollment) error {
	body, err := proto.Marshal(rep)
	if err != nil {
		return fmt.Errorf("marshal puf enrollment: %w", err)
	}
	_, err = c.post(ctx, "/api/agent/puf/enroll", body, token)
	return err
}

// PostPufAttestation ships a periodic PUF attestation — the agent's
// fresh measurement, to be compared on the server against the enrolled
// baseline. The server computes the verdict; the agent does not need it
// and we therefore drop the response body.
func (c *Client) PostPufAttestation(ctx context.Context, token string, rep *agentpb.PufAttestation) error {
	body, err := proto.Marshal(rep)
	if err != nil {
		return fmt.Errorf("marshal puf attestation: %w", err)
	}
	_, err = c.post(ctx, "/api/agent/puf/attest", body, token)
	return err
}

// PostPufKeyEnrollment ships W5b fuzzy-extractor helper data plus the
// derived Ed25519 public key. The agent keeps the helper on local disk
// too so it can reproduce K deterministically without a server round
// trip; the server copy is what the /api/agent/puf/key/proof endpoint
// later verifies signatures against.
func (c *Client) PostPufKeyEnrollment(ctx context.Context, token string, rep *agentpb.PufKeyEnrollment) error {
	body, err := proto.Marshal(rep)
	if err != nil {
		return fmt.Errorf("marshal puf key enrollment: %w", err)
	}
	_, err = c.post(ctx, "/api/agent/puf/key/enroll", body, token)
	return err
}

// PostPufKeyProof ships a fresh proof-of-possession signature. The
// agent has just run Reproduce against fresh silicon, recovered K,
// derived the Ed25519 private key, and signed a self-chosen nonce.
func (c *Client) PostPufKeyProof(ctx context.Context, token string, rep *agentpb.PufKeyProof) error {
	body, err := proto.Marshal(rep)
	if err != nil {
		return fmt.Errorf("marshal puf key proof: %w", err)
	}
	_, err = c.post(ctx, "/api/agent/puf/key/proof", body, token)
	return err
}

func (c *Client) Heartbeat(ctx context.Context, token string, req *agentpb.HeartbeatRequest) (*agentpb.HeartbeatResponse, error) {
	body, err := proto.Marshal(req)
	if err != nil {
		return nil, err
	}
	r, err := c.post(ctx, "/api/agent/heartbeat", body, token)
	if err != nil {
		return nil, err
	}
	resp := &agentpb.HeartbeatResponse{}
	if err := proto.Unmarshal(r, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) post(ctx context.Context, path string, body []byte, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("User-Agent", "963causal-agent/0.1 go")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", path, err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s: HTTP %d: %s", path, res.StatusCode, truncate(b, 512))
	}
	return b, nil
}

func truncate(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}

// SignFrame signs a Frame blob with the host Ed25519 private key.
func SignFrame(priv ed25519.PrivateKey, frame *agentpb.Frame) (*agentpb.SignedFrame, error) {
	blob, err := proto.Marshal(frame)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, blob)
	return &agentpb.SignedFrame{FrameBlob: blob, Signature: sig}, nil
}

// SignHeartbeat signs a host_id || sequence || timestamp envelope.
func SignHeartbeat(priv ed25519.PrivateKey, hostID string, sequence uint64, tsUnix int64) []byte {
	buf := new(bytes.Buffer)
	buf.WriteString(hostID)
	_ = binary.Write(buf, binary.BigEndian, sequence)
	_ = binary.Write(buf, binary.BigEndian, tsUnix)
	return ed25519.Sign(priv, buf.Bytes())
}
