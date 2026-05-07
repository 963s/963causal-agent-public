// Package probe — x86_64 hardware counter reads.
//
// RDTSC  reads the Time Stamp Counter. Under hypervisors with
//        TSC_OFFSETTING, the VM sees a linearly-offset TSC and
//        reads are not trapped (native performance).
// RDTSCP reads TSC + aux (CPU id), serializing prior loads.
//        This path CAN be configured to trap (via RDTSCP exit
//        control), producing measurable latency divergence.
//
// LFENCE before RDTSC orders prior instructions so the counter
// reads are not speculated ahead of timed work. We omit LFENCE
// here because our consumers only care about the relative rate of
// two readings, and the extra serialization skews latency.
//
//go:build amd64

#include "textflag.h"

// func readTSC() uint64
TEXT ·readTSC(SB), NOSPLIT, $0-8
	RDTSC
	SHLQ  $32, DX
	ORQ   DX, AX
	MOVQ  AX, ret+0(FP)
	RET

// func readTSCP() uint64
TEXT ·readTSCP(SB), NOSPLIT, $0-8
	BYTE $0x0F; BYTE $0x01; BYTE $0xF9 // RDTSCP
	SHLQ  $32, DX
	ORQ   DX, AX
	MOVQ  AX, ret+0(FP)
	RET
