package puf

import (
	"bytes"
	"math/rand"
	"testing"
)

// TestHamming74RoundTripAllNibbles checks that every 4-bit data
// nibble round-trips through Encode→Decode unchanged. Sixteen cases
// is exhaustive; doing it as a loop guards against regressions in
// the parity equations or the bit-layout shuffling code.
func TestHamming74RoundTripAllNibbles(t *testing.T) {
	for n := uint8(0); n < 16; n++ {
		cw := HammingEncode4to7(n)
		got := HammingDecode7to4(cw)
		if got != n {
			t.Fatalf("nibble %d: encoded to %07b, decoded back as %d", n, cw, got)
		}
	}
}

// TestHamming74CorrectsAnySingleBitFlip flips each of the seven
// codeword bits in turn and confirms the decoder still returns the
// original nibble. This is the property the fuzzy extractor relies
// on for its per-block error tolerance, so a missed correction here
// would silently corrupt the derived key.
func TestHamming74CorrectsAnySingleBitFlip(t *testing.T) {
	for n := uint8(0); n < 16; n++ {
		cw := HammingEncode4to7(n)
		for bit := 0; bit < 7; bit++ {
			flipped := cw ^ (1 << bit)
			got := HammingDecode7to4(flipped)
			if got != n {
				t.Fatalf("nibble %d: flipping codeword bit %d produced %d", n, bit, got)
			}
		}
	}
}

// TestEncodeDecodeHamming74Stream feeds a pseudo-random 256-bit
// payload through the stream-oriented helpers and checks the result
// matches. 256 bits is a representative size for the live fuzzy
// extractor (128-bit key has 128 information bits → 224 codeword
// bits); doubling that exercises the code path without making the
// failure message unreadable when something breaks.
func TestEncodeDecodeHamming74Stream(t *testing.T) {
	r := rand.New(rand.NewSource(0xC0FFEE))
	const dataBits = 256
	data := make([]byte, dataBits/8)
	r.Read(data)

	enc, encBits := EncodeHamming74(data, dataBits)
	if encBits != dataBits/4*7 {
		t.Fatalf("encoded length: got %d want %d", encBits, dataBits/4*7)
	}
	dec, decBits := DecodeHamming74(enc, encBits)
	if decBits != dataBits {
		t.Fatalf("decoded length: got %d want %d", decBits, dataBits)
	}
	if !bytes.Equal(dec, data) {
		t.Fatalf("round-trip mismatch:\n  data=%x\n  back=%x", data, dec)
	}
}

// TestEncodeDecodeHamming74StreamWithErrors injects exactly one bit
// flip into each 7-bit codeword block and confirms the decoder still
// recovers the original payload. This is the worst case the fuzzy
// extractor is designed to handle on a healthy host.
func TestEncodeDecodeHamming74StreamWithErrors(t *testing.T) {
	r := rand.New(rand.NewSource(0xBADBEEF))
	const dataBits = 128
	data := make([]byte, dataBits/8)
	r.Read(data)

	enc, encBits := EncodeHamming74(data, dataBits)
	// Flip one bit per 7-bit block at a deterministic offset.
	for blk := 0; blk < encBits/7; blk++ {
		flip := blk*7 + (blk*3+1)%7
		enc[flip>>3] ^= 1 << uint(flip&7)
	}
	dec, _ := DecodeHamming74(enc, encBits)
	if !bytes.Equal(dec, data) {
		t.Fatalf("single-bit-per-block recovery failed:\n  want %x\n  got  %x", data, dec)
	}
}
