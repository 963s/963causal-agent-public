//go:build arm64

package identity

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readCPUIDPlatform implements the arm64 path.
//
// ARM64 restricts userspace access to most system registers. The MIDR_EL1
// (Main ID Register) is readable from EL0 only when the kernel sets
// SCTLR_EL1.UCT; on Linux 5.7+ this is gated by the hwcap CPUID feature
// (HWCAP_CPUID). Where that isn't available we fall back to the kernel-
// exposed /sys/devices/system/cpu/cpu0/regs/identification/midr_el1 file,
// which is NOT spoofable via /proc (it lives in sysfs's own devtmpfs).
//
// The path /sys/devices/system/cpu/ is mounted by the kernel at boot from
// the real hardware registers and is NOT affected by /proc-level rootkits
// (FUSE or sys_read interception targets the vfs layer; devtmpfs for sysfs
// uses the kernfs layer which cannot be intercepted without a kernel module
// that would itself be detected by the Kernel Sentinel).
func readCPUIDPlatform() CPUIDInfo {
	midr := readMIDR()
	// MIDR_EL1 layout:
	//   bits [3:0]   = Revision
	//   bits [7:4]   = PartNum (low 4 bits)
	//   bits [15:4]  = PartNum (full 12 bits)
	//   bits [19:16] = Architecture
	//   bits [23:20] = Variant
	//   bits [31:24] = Implementer
	implementer := (midr >> 24) & 0xff
	variant := (midr >> 20) & 0xf
	partnum := (midr >> 4) & 0xfff
	revision := midr & 0xf

	vendor := armImplementerName(implementer)
	brand := fmt.Sprintf("ARM MIDR_EL1=0x%08x (impl=0x%02x part=0x%03x var=%d rev=%d)",
		midr, implementer, partnum, variant, revision)

	return CPUIDInfo{
		Vendor:   vendor,
		Brand:    brand,
		Family:   implementer,
		Model:    partnum,
		Stepping: revision,
	}
}

// readMIDR reads the MIDR_EL1 value from sysfs.
// Returns 0 on failure (caller will produce a degraded but non-empty string).
func readMIDR() uint64 {
	b, err := os.ReadFile("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1")
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(b))
	// Kernel exports as "0x<hex>"
	s = strings.TrimPrefix(s, "0x")
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0
	}
	return v
}

// armImplementerName maps the MIDR Implementer byte to a human-readable name.
// Source: ARM IHI0076B §E1.2.
func armImplementerName(impl uint64) string {
	switch impl {
	case 0x41:
		return "ARM"
	case 0x42:
		return "Broadcom"
	case 0x43:
		return "Cavium"
	case 0x44:
		return "DEC"
	case 0x46:
		return "Fujitsu"
	case 0x48:
		return "HiSilicon"
	case 0x49:
		return "Infineon"
	case 0x4d:
		return "Motorola"
	case 0x4e:
		return "NVIDIA"
	case 0x50:
		return "APM"
	case 0x51:
		return "Qualcomm"
	case 0x53:
		return "Samsung"
	case 0x56:
		return "Marvell"
	case 0x61:
		return "Apple"
	case 0x69:
		return "Intel"
	case 0xc0:
		return "Ampere"
	default:
		return fmt.Sprintf("impl=0x%02x", impl)
	}
}
