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
	"log"
	"math/rand"
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

// retryPost wraps post() with exponential backoff + jitter.
// It retries up to maxAttempts times on transient failures (network
// errors, 5xx responses). Context cancellation aborts immediately.
//
// Backoff schedule: base 2s, multiplied by 2^attempt, capped at 60s,
// plus uniform jitter in [-500ms, +500ms].
func (c *Client) retryPost(ctx context.Context, path string, body []byte, token string, maxAttempts int) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := c.post(ctx, path, body, token)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if attempt+1 >= maxAttempts {
			break
		}
		backoff := backoffDuration(attempt)
		log.Printf("retry: POST %s attempt %d/%d failed: %v (backoff %s)",
			path, attempt+1, maxAttempts, err, backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("all %d attempts failed for POST %s: %w", maxAttempts, path, lastErr)
}

// backoffDuration returns the backoff sleep for a given attempt index.
// Base 2s × 2^attempt, capped at 60s, plus ±500ms uniform jitter.
func backoffDuration(attempt int) time.Duration {
	base := 2 * time.Second
	shift := uint(attempt)
	if shift > 5 {
		shift = 5 // cap multiplier at 2^5 = 32 → 64s before jitter
	}
	d := base << shift
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	// Uniform jitter ±500ms.
	jitter := time.Duration(rand.Int63n(int64(time.Second))) - 500*time.Millisecond
	d += jitter
	if d < 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	return d
}

// PostFrameRetry is PostFrame with exponential backoff. The agent
// main loop should prefer this over PostFrame to survive transient
// network outages without silently dropping telemetry.
func (c *Client) PostFrameRetry(ctx context.Context, token string, signed *agentpb.SignedFrame, maxAttempts int) error {
	body, err := proto.Marshal(signed)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	_, err = c.retryPost(ctx, "/api/agent/frame", body, token, maxAttempts)
	return err
}

// PostPufAttestationRetry is PostPufAttestation with exponential backoff.
func (c *Client) PostPufAttestationRetry(ctx context.Context, token string, rep *agentpb.PufAttestation, maxAttempts int) error {
	body, err := proto.Marshal(rep)
	if err != nil {
		return fmt.Errorf("marshal puf attestation: %w", err)
	}
	_, err = c.retryPost(ctx, "/api/agent/puf/attest", body, token, maxAttempts)
	return err
}

// PostPufKeyProofRetry is PostPufKeyProof with exponential backoff.
func (c *Client) PostPufKeyProofRetry(ctx context.Context, token string, rep *agentpb.PufKeyProof, maxAttempts int) error {
	body, err := proto.Marshal(rep)
	if err != nil {
		return fmt.Errorf("marshal puf key proof: %w", err)
	}
	_, err = c.retryPost(ctx, "/api/agent/puf/key/proof", body, token, maxAttempts)
	return err
}

// RetryEnroll wraps Enroll with exponential backoff so the agent
// survives a temporarily-down control plane at boot time instead
// of crash-looping via Fatalf.
func (c *Client) RetryEnroll(ctx context.Context, req *agentpb.EnrollRequest, maxAttempts int) (*agentpb.EnrollResponse, error) {
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := c.Enroll(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if attempt+1 >= maxAttempts {
			break
		}
		backoff := backoffDuration(attempt)
		log.Printf("retry: enroll attempt %d/%d failed: %v (backoff %s)",
			attempt+1, maxAttempts, err, backoff)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("enroll failed after %d attempts: %w", maxAttempts, lastErr)
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
