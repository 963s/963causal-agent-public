package puf

// Hamming(7, 4) systematic encoder/decoder. Each block carries four
// information bits (data) in the high four positions and three parity
// bits in the low three positions, ordered by their parity-check
// index. The minimum distance is three, so any single bit-flip in a
// 7-bit block is corrected; a double-flip is detected (syndrome ≠ 0)
// but mis-corrected — that is the price of using such a small code,
// and it is acceptable for PAL because the pre-selected bit pool runs
// at BER 0% on this hardware (cmd/puf-ber, 49 cycles, 2026-04-17),
// giving 14 % margin per block before correction fails.
//
// Layout of one 7-bit codeword (LSB-first when written into a packed
// byte stream):
//
//   bit 0 → p1   parity over data bits {d1, d2, d4}
//   bit 1 → p2   parity over data bits {d1, d3, d4}
//   bit 2 → d1
//   bit 3 → p4   parity over data bits {d2, d3, d4}
//   bit 4 → d2
//   bit 5 → d3
//   bit 6 → d4
//
// This is the canonical "Hamming(7,4) systematic with parity at
// power-of-two positions" layout. The choice matches the textbook
// presentation so the decoder syndrome equations stay obvious.
//
// All public functions operate on []byte slices with bits packed
// little-endian (bit i of byte j = byte (8*j + i)) — the same packing
// the bitBuilder type produces, so encoded codewords concatenate
// naturally with quantiser output.

// HammingEncode4to7 takes the low four bits of data (d1..d4 in bits
// 0..3 respectively) and returns the 7-bit codeword in the low seven
// bits of the result. The high bit is always zero.
func HammingEncode4to7(data uint8) uint8 {
	d1 := (data >> 0) & 1
	d2 := (data >> 1) & 1
	d3 := (data >> 2) & 1
	d4 := (data >> 3) & 1
	p1 := d1 ^ d2 ^ d4
	p2 := d1 ^ d3 ^ d4
	p4 := d2 ^ d3 ^ d4
	return p1 | (p2 << 1) | (d1 << 2) | (p4 << 3) | (d2 << 4) | (d3 << 5) | (d4 << 6)
}

// HammingDecode7to4 returns the four data bits recovered from a
// possibly-corrupted 7-bit codeword. The decoder corrects any single
// bit-flip: a syndrome of zero means the codeword is intact; any
// non-zero syndrome is interpreted as the position (1-indexed) of
// the flipped bit, which is then xor'd back. Two-bit errors silently
// mis-correct — see the package comment for why that is acceptable.
func HammingDecode7to4(code uint8) uint8 {
	c := code & 0x7F
	b1 := (c >> 0) & 1
	b2 := (c >> 1) & 1
	b3 := (c >> 2) & 1
	b4 := (c >> 3) & 1
	b5 := (c >> 4) & 1
	b6 := (c >> 5) & 1
	b7 := (c >> 6) & 1

	// Syndrome bits (s1, s2, s4 in textbook notation).
	s1 := b1 ^ b3 ^ b5 ^ b7
	s2 := b2 ^ b3 ^ b6 ^ b7
	s4 := b4 ^ b5 ^ b6 ^ b7
	syn := s1 | (s2 << 1) | (s4 << 2)
	if syn != 0 {
		// syn is the 1-indexed position (1..7) of the flipped bit.
		c ^= 1 << (syn - 1)
		// Re-extract the data bits from the corrected codeword.
		b3 = (c >> 2) & 1
		b5 = (c >> 4) & 1
		b6 = (c >> 5) & 1
		b7 = (c >> 6) & 1
	}
	return b3 | (b5 << 1) | (b6 << 2) | (b7 << 3)
}

// EncodeHamming74 takes a packed bit slice carrying len*4 information
// bits (4 per byte if len is a byte, but the function actually reads
// bit-by-bit from the slice via bitOf) and returns a packed bit slice
// carrying len*7 codeword bits. The output length in bits is exactly
// 7 * (input bits / 4), so the input must be a multiple of four bits.
//
// The function is intentionally bit-oriented rather than byte-oriented
// because PAL fingerprints are bit-packed and may not be aligned on a
// byte boundary; passing them through a byte-oriented Hamming would
// require an extra packing/unpacking dance.
func EncodeHamming74(data []byte, dataBits int) ([]byte, int) {
	if dataBits%4 != 0 {
		return nil, 0
	}
	blocks := dataBits / 4
	codeBits := blocks * 7
	var b bitBuilder
	for blk := 0; blk < blocks; blk++ {
		var nibble uint8
		for i := 0; i < 4; i++ {
			if bitOf(data, blk*4+i) != 0 {
				nibble |= 1 << uint(i)
			}
		}
		cw := HammingEncode4to7(nibble)
		for i := 0; i < 7; i++ {
			b.appendBit(cw&(1<<uint(i)) != 0)
		}
	}
	return b.bytes(), codeBits
}

// DecodeHamming74 inverts EncodeHamming74: every 7 input bits become
// 4 output bits, with single-bit-flip correction inside each 7-bit
// block. The output bit-length is exactly 4 * (input bits / 7).
func DecodeHamming74(code []byte, codeBits int) ([]byte, int) {
	if codeBits%7 != 0 {
		return nil, 0
	}
	blocks := codeBits / 7
	dataBits := blocks * 4
	var b bitBuilder
	for blk := 0; blk < blocks; blk++ {
		var cw uint8
		for i := 0; i < 7; i++ {
			if bitOf(code, blk*7+i) != 0 {
				cw |= 1 << uint(i)
			}
		}
		nibble := HammingDecode7to4(cw)
		for i := 0; i < 4; i++ {
			b.appendBit(nibble&(1<<uint(i)) != 0)
		}
	}
	return b.bytes(), dataBits
}
