package puf

import (
	"encoding/hex"
	"sort"
	"time"

	"golang.org/x/crypto/sha3"
)

// Quantize reduces a Matrix to a Fingerprint by extracting rank-order bits
// across cores, loops and trials. The goal is to produce a vector whose
// bits are stable across short-term noise (thermal drift, scheduler jitter,
// warm cache state) but flip deterministically when the underlying silicon
// changes (VM migration, disk image on new host, CPU replacement).
//
// Quantisation strategy (W5a MVP):
//
//	1. Pair-sign bits:
//	     for each loop L and each unordered core pair (a, b):
//	         bit = 1 if median(f[a,L]) > median(f[b,L]) else 0
//	     Count: C(numCores, 2) * numLoops
//
//	2. Per-core-vs-loop-median bits:
//	     for each (core, loop):
//	         bit = 1 if median(f[core,loop]) > grand_median(f[*,loop]) else 0
//	     Count: numCores * numLoops
//
//	3. CV quartile bits (2 bits per cell):
//	     for each (core, loop):
//	         CV is the coefficient of variation across trials.
//	         bit0 = 1 if CV > grand_median(CV[*,loop])
//	         bit1 = 1 if CV > grand_p75(CV[*,loop])
//	     Count: numCores * numLoops * 2
//
//	4. Pair-magnitude bits:
//	     for each loop L and each unordered core pair (a, b):
//	         bit = 1 if |median(f[a,L]) - median(f[b,L])| > median_pair_gap(L)
//	     Count: C(numCores, 2) * numLoops
//
// For a 4-core, 3-loop cycle this yields 18 + 12 + 24 + 18 = 72 bits. Enough
// for distance-based attestation (per ADR-002, MVP is attestation-only); not
// enough for direct cryptographic key extraction, which is deferred to W5b
// pending real BER data.
func Quantize(m Matrix) Fingerprint {
	// For each (core, loop) compute the median iters-per-second and the CV
	// across trials. We keep them in linearised slices because the later
	// ranking passes operate per-loop across all cores.
	medians := make([][]float64, m.NumCores) // [core][loop]
	cvs := make([][]float64, m.NumCores)
	for c := 0; c < m.NumCores; c++ {
		medians[c] = make([]float64, m.NumLoops)
		cvs[c] = make([]float64, m.NumLoops)
		for l := 0; l < m.NumLoops; l++ {
			rates := make([]float64, m.NumTrials)
			for t := 0; t < m.NumTrials; t++ {
				rates[t] = m.Samples[c][l][t].ItersPerSec()
			}
			med, _ := medianMAD(rates)
			medians[c][l] = med
			cvs[c][l] = cvOf(rates)
		}
	}

	var bits bitBuilder

	// (1) Pair-sign bits: C(n,2) per loop.
	for l := 0; l < m.NumLoops; l++ {
		for a := 0; a < m.NumCores; a++ {
			for b := a + 1; b < m.NumCores; b++ {
				bits.appendBit(medians[a][l] > medians[b][l])
			}
		}
	}

	// (2) Per-core-vs-loop-median bits.
	for l := 0; l < m.NumLoops; l++ {
		col := make([]float64, m.NumCores)
		for c := 0; c < m.NumCores; c++ {
			col[c] = medians[c][l]
		}
		gm := grandMedian(col)
		for c := 0; c < m.NumCores; c++ {
			bits.appendBit(medians[c][l] > gm)
		}
	}

	// (3) CV quartile bits (two bits per cell): > median, > p75.
	for l := 0; l < m.NumLoops; l++ {
		col := make([]float64, m.NumCores)
		for c := 0; c < m.NumCores; c++ {
			col[c] = cvs[c][l]
		}
		gm := grandMedian(col)
		p75 := percentile(col, 0.75)
		for c := 0; c < m.NumCores; c++ {
			bits.appendBit(cvs[c][l] > gm)
			bits.appendBit(cvs[c][l] > p75)
		}
	}

	// (4) Pair-magnitude bits.
	for l := 0; l < m.NumLoops; l++ {
		// Collect all pair gaps for this loop, compute their median.
		gaps := make([]float64, 0, m.NumCores*(m.NumCores-1)/2)
		for a := 0; a < m.NumCores; a++ {
			for b := a + 1; b < m.NumCores; b++ {
				g := medians[a][l] - medians[b][l]
				if g < 0 {
					g = -g
				}
				gaps = append(gaps, g)
			}
		}
		medGap := grandMedian(gaps)
		// Re-iterate pairs in the same order as step (1) for deterministic
		// bit positions.
		for a := 0; a < m.NumCores; a++ {
			for b := a + 1; b < m.NumCores; b++ {
				g := medians[a][l] - medians[b][l]
				if g < 0 {
					g = -g
				}
				bits.appendBit(g > medGap)
			}
		}
	}

	packed := bits.bytes()
	h := sha3.New256()
	h.Write(packed)
	// Length-pad with a one-byte tag so two fingerprints of different bit
	// lengths can never collide, even if their packed bytes are identical.
	h.Write([]byte{byte(bits.length)})
	digest := hex.EncodeToString(h.Sum(nil))

	return Fingerprint{
		Bits:       packed,
		Length:     bits.length,
		Cores:      m.NumCores,
		Loops:      m.NumLoops,
		Trials:     m.NumTrials,
		Digest:     digest,
		MeasuredAt: time.Now().UTC(),
	}
}

// bitBuilder packs appended bits into a little-endian byte slice. It exists
// so the quantisation passes above can focus on their logic without having
// to think about byte boundaries.
type bitBuilder struct {
	bytes_ []byte
	length int
}

func (b *bitBuilder) appendBit(v bool) {
	byteIdx := b.length >> 3
	bitIdx := uint(b.length & 7)
	for len(b.bytes_) <= byteIdx {
		b.bytes_ = append(b.bytes_, 0)
	}
	if v {
		b.bytes_[byteIdx] |= 1 << bitIdx
	}
	b.length++
}

func (b *bitBuilder) bytes() []byte {
	return b.bytes_
}

func grandMedian(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	return cp[len(cp)/2]
}

func percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	if p <= 0 {
		return cp[0]
	}
	if p >= 1 {
		return cp[len(cp)-1]
	}
	idx := int(p * float64(len(cp)-1))
	return cp[idx]
}
