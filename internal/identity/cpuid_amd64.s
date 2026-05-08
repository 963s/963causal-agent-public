// Copyright 2026 963causal. All rights reserved.
// Direct CPUID reads for amd64 — bypasses /proc/cpuinfo entirely so a
// rootkit that intercepts sys_read or mounts a FUSE overlay on /proc
// cannot forge the CPU identity fed into the hardware fingerprint.
//
// Only the three leaves we need are exposed:
//   cpuidLeaf0_amd64   — max leaf + 12-byte vendor string
//   cpuidLeaf1_amd64   — EAX encodes family/model/stepping
//   cpuidBrand_amd64   — 48-byte brand string from leaves 0x80000002-4
//
// The Go ABI1 calling convention on amd64: first six integer args in
// DI, SI, DX, CX, R8, R9; return in AX, DX.
// These stubs do NOT use any callee-saved registers, so no stack frame
// is needed for the simple cases.

#include "textflag.h"

// func cpuidLeaf0Asm() (maxLeaf uint32, vendorB, vendorD, vendorC uint32)
TEXT ·cpuidLeaf0Asm(SB), NOSPLIT, $0-16
    XORL AX, AX       // leaf 0
    XORL CX, CX       // sub-leaf 0
    CPUID
    MOVL AX, maxLeaf+0(FP)
    MOVL BX, vendorB+4(FP)
    MOVL DX, vendorD+8(FP)
    MOVL CX, vendorC+12(FP)
    RET

// func cpuidLeaf1Asm() (eax, ebx, ecx, edx uint32)
TEXT ·cpuidLeaf1Asm(SB), NOSPLIT, $0-16
    MOVL $1, AX
    XORL CX, CX
    CPUID
    MOVL AX, eax+0(FP)
    MOVL BX, ebx+4(FP)
    MOVL CX, ecx+8(FP)
    MOVL DX, edx+12(FP)
    RET

// func cpuidBrandAsm(out *[48]byte)
// Reads leaves 0x80000002, 0x80000003, 0x80000004 into a caller-provided
// 48-byte buffer. Each leaf returns 16 bytes (EAX‖EBX‖ECX‖EDX).
TEXT ·cpuidBrandAsm(SB), NOSPLIT, $0-8
    MOVQ out+0(FP), DI

    MOVL $0x80000002, AX
    XORL CX, CX
    CPUID
    MOVL AX,  0(DI)
    MOVL BX,  4(DI)
    MOVL CX,  8(DI)
    MOVL DX, 12(DI)

    MOVL $0x80000003, AX
    XORL CX, CX
    CPUID
    MOVL AX, 16(DI)
    MOVL BX, 20(DI)
    MOVL CX, 24(DI)
    MOVL DX, 28(DI)

    MOVL $0x80000004, AX
    XORL CX, CX
    CPUID
    MOVL AX, 32(DI)
    MOVL BX, 36(DI)
    MOVL CX, 40(DI)
    MOVL DX, 44(DI)

    RET
