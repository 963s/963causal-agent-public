// Package sculpture converts per-epoch histograms into a Sobolev sculpture
// vertex vector + 2-character genotype.
package sculpture

import (
	"math"

	agentpb "github.com/963causal/agent/proto"
)

// BuildVertices maps per-syscall histograms to a stable 24-dim vector:
// for up to 8 syscalls, (log1p(p50), log1p(p90), log1p(p99)).
// Missing syscalls contribute zeros.
func BuildVertices(hists []*agentpb.HdrHistogram) []float64 {
	const perSyscall = 3
	const maxSyscalls = 8
	out := make([]float64, maxSyscalls*perSyscall)
	for i, h := range hists {
		if i >= maxSyscalls {
			break
		}
		base := i * perSyscall
		out[base+0] = math.Log1p(h.P50Ns)
		out[base+1] = math.Log1p(h.P90Ns)
		out[base+2] = math.Log1p(h.P99Ns)
	}
	return out
}

// Genotype renders the vector into a two-character topological genotype.
// First character: A..Z indexed by the log-sum (total timing mass).
// Second character: 0..9 indexed by the p99 variance across syscalls.
func Genotype(v []float64) string {
	if len(v) == 0 {
		return "A0"
	}
	var sum float64
	for _, x := range v {
		sum += x
	}
	avg := sum / float64(len(v))
	// scale avg into [0, 26). Empirical range: log1p(1e3)=6.9, log1p(1e7)=16.1
	letterIdx := int(clamp01((avg-6.0)/10.0) * 26)
	if letterIdx >= 26 {
		letterIdx = 25
	}

	// p99 variance proxy
	var vars float64
	for i := 2; i < len(v); i += 3 {
		d := v[i] - avg
		vars += d * d
	}
	vars /= float64(len(v) / 3)
	digit := int(clamp01(vars/30.0) * 10)
	if digit >= 10 {
		digit = 9
	}
	return string(rune('A'+letterIdx)) + string(rune('0'+digit))
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}
