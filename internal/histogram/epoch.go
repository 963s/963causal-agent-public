// Package histogram wraps HDR histogram rotation per epoch.
package histogram

import (
	"sort"

	agentpb "github.com/963causal/agent/proto"
)

// Epoch collects samples for a single syscall and emits percentiles for one
// measurement epoch.
type Epoch struct {
	Syscall string
	samples []int64
}

func NewEpoch(name string) *Epoch {
	return &Epoch{Syscall: name, samples: make([]int64, 0, 1024)}
}

func (e *Epoch) Add(ns int64) {
	if ns <= 0 {
		return
	}
	e.samples = append(e.samples, ns)
}

func (e *Epoch) AddAll(ns []int64) {
	e.samples = append(e.samples, ns...)
}

// Digest computes the HDR quantile summary for this epoch. We compute manually
// on the sorted sample set; for W1 this is simpler than a full HDR backing
// store and the sample counts are bounded.
func (e *Epoch) Digest() *agentpb.HdrHistogram {
	h := &agentpb.HdrHistogram{Syscall: e.Syscall, TotalCount: uint64(len(e.samples))}
	if len(e.samples) == 0 {
		return h
	}
	sort.Slice(e.samples, func(i, j int) bool { return e.samples[i] < e.samples[j] })
	h.P50Ns = quantile(e.samples, 0.50)
	h.P90Ns = quantile(e.samples, 0.90)
	h.P99Ns = quantile(e.samples, 0.99)
	h.P999Ns = quantile(e.samples, 0.999)
	h.MeanNs = mean(e.samples)
	h.StddevNs = stddev(e.samples, h.MeanNs)
	return h
}

func quantile(sorted []int64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(q * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return float64(sorted[idx])
}

func mean(v []int64) float64 {
	var s float64
	for _, x := range v {
		s += float64(x)
	}
	return s / float64(len(v))
}

func stddev(v []int64, m float64) float64 {
	var s float64
	for _, x := range v {
		d := float64(x) - m
		s += d * d
	}
	return sqrt(s / float64(len(v)))
}

// Newton-Raphson sqrt to avoid importing math just for this.
func sqrt(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 16; i++ {
		z = z - (z*z-x)/(2*z)
	}
	return z
}
