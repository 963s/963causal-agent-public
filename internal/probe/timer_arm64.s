// Package probe — ARM64 hardware counter reads.
//
// CNTVCT_EL0 and CNTPCT_EL0 are defined by the ARM Generic Timer
// architecture (ARMv8-A). Both advance at the rate of CNTFRQ_EL0,
// which is a fixed crystal-derived frequency (typically 24 MHz or
// 54 MHz on server-class parts).
//
// CNTVCT_EL0 = CNTPCT_EL0 - CNTVOFF_EL2
//
//   * On bare metal, CNTVOFF_EL2 = 0, so VCT == PCT exactly.
//   * Under a hypervisor that manipulates VM time (pause/resume, live
//     migration, rogue time skew), CNTVOFF_EL2 changes dynamically and
//     the ratio Δ(VCT)/Δ(PCT) diverges from 1.0.
//   * Reading CNTPCT_EL0 may trap to EL2 if CNTHCTL_EL2.EL0PCTEN=0,
//     producing a measurable latency jump (~1000+ cycles vs ~15 cycles).
//
// These are the lowest-level, least-forgeable time sources available
// to userspace on ARM64. Used by the MSTC probe.
//
//go:build arm64

#include "textflag.h"

// func readCNTVCT() uint64
TEXT ·readCNTVCT(SB), NOSPLIT, $0-8
	MRS   CNTVCT_EL0, R0
	MOVD  R0, ret+0(FP)
	RET

// func readCNTPCT() uint64
TEXT ·readCNTPCT(SB), NOSPLIT, $0-8
	MRS   CNTPCT_EL0, R0
	MOVD  R0, ret+0(FP)
	RET

// func readCNTFRQ() uint64
TEXT ·readCNTFRQ(SB), NOSPLIT, $0-8
	MRS   CNTFRQ_EL0, R0
	MOVD  R0, ret+0(FP)
	RET
