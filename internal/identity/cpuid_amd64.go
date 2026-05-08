// Package identity — direct hardware CPU identification.
//
// Build constraints:
//   - cpuid_amd64.s  implements the three Asm symbols on x86-64
//   - cpuid_arm64.go implements the equivalent via ARM64 system registers
//
// Together these give cpuIDFromHardware() on both architectures.
// The /proc/cpuinfo path remains as a human-readable companion but is
// NO LONGER the source of truth for the fingerprint — a rootkit that
// intercepts sys_read and returns a fake model string will disagree with
// the direct register read, which surfaces as an enrollment mismatch.

package identity

import "strings"

// cpuidLeaf0Asm returns the max supported CPUID leaf and the 12-byte
// vendor string packed into three uint32s (B, D, C order = "GenuineIntel"
// / "AuthenticAMD" etc.). Implemented in cpuid_amd64.s.
func cpuidLeaf0Asm() (maxLeaf, vendorB, vendorD, vendorC uint32)

// cpuidLeaf1Asm returns EAX from CPUID leaf 1, which encodes:
//
//	bits [3:0]   = Stepping ID
//	bits [7:4]   = Model
//	bits [11:8]  = Family
//	bits [19:16] = Extended Model
//	bits [27:20] = Extended Family
func cpuidLeaf1Asm() (eax, ebx, ecx, edx uint32)

// cpuidBrandAsm fills a 48-byte buffer with the null-terminated
// processor brand string from leaves 0x80000002–0x80000004.
func cpuidBrandAsm(out *[48]byte)

// CPUIDInfo holds directly-read hardware CPU identity fields.
// All fields come from the CPUID instruction and cannot be spoofed
// without modifying the hardware or intercepting CPUID itself
// (which requires Ring-0 / hypervisor level access and produces
// measurable timing artefacts that MSTC would detect).
type CPUIDInfo struct {
	Vendor  string // e.g. "GenuineIntel", "AuthenticAMD"
	Brand   string // full brand string, e.g. "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz"
	Family  uint32 // Extended Family + Family
	Model   uint32 // Extended Model + Model
	Stepping uint32
}

// ReadCPUID returns the CPU identity directly from hardware registers.
// On amd64 this issues three CPUID calls. On arm64 the implementation
// is in cpuid_arm64.go using the MIDR_EL1 system register via
// runtime/internal/sys or a cgo-free inline asm equivalent.
func ReadCPUID() CPUIDInfo {
	return readCPUIDPlatform()
}

// CPUIDString returns a compact, stable string representation of the
// CPUID reading suitable for inclusion in the hardware fingerprint.
// Format: "<vendor>/<family>/<model>/<stepping>/<brand>"
func CPUIDString(info CPUIDInfo) string {
	brand := strings.TrimRight(info.Brand, "\x00 ")
	return strings.Join([]string{
		info.Vendor,
		uint32ToHex(info.Family),
		uint32ToHex(info.Model),
		uint32ToHex(info.Stepping),
		brand,
	}, "/")
}

func uint32ToHex(v uint32) string {
	const hx = "0123456789abcdef"
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = hx[v&0xf]
		v >>= 4
	}
	return string(b)
}
