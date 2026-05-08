package identity

import (
	"bufio"
	"encoding/hex"
	"log"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/sha3"
)

// HardwareFingerprint returns a stable sha3-256 hex digest of machine-bound
// identifiers. The CPU component is now sourced from a direct hardware
// register read (CPUID on amd64 / MIDR_EL1 on arm64) and cross-validated
// against /proc/cpuinfo. A mismatch is logged as a CRITICAL warning —
// it indicates a rootkit is intercepting filesystem reads.
//
// The fingerprint itself uses the hardware-register value, which cannot be
// faked via /proc interception.
func HardwareFingerprint() string {
	hwCPU := cpuFromHardware()

	// Cross-validate: compare hardware-derived model against /proc/cpuinfo.
	// A mismatch is a strong rootkit signal.
	procCPU := cpuModel()
	if hwCPU != "" && procCPU != "" && !cpuStringsCompatible(hwCPU, procCPU) {
		log.Printf("CRITICAL: CPU identity mismatch — hw_register=%q proc_cpuinfo=%q — possible rootkit interception of /proc", hwCPU, procCPU)
	}

	parts := []string{
		readFirstLine("/etc/machine-id"),
		hwCPU, // authoritative: hardware register, not /proc
		memTotalFromSysconf(),
		macAddresses(),
	}
	sort.Strings(parts)
	h := sha3.New256()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// cpuFromHardware returns a stable string from direct hardware register
// reads. Empty string if the platform is unsupported (falls through to
// /proc value for fingerprint continuity).
func cpuFromHardware() string {
	info := ReadCPUID()
	if info.Vendor == "" && info.Brand == "" {
		// Unsupported arch — fall back to /proc so fingerprint is non-empty.
		return cpuModel()
	}
	return CPUIDString(info)
}

// cpuStringsCompatible returns true if the hardware-register CPU string and
// the /proc/cpuinfo string are consistent. We don't require exact equality
// because brand-string formatting differs between kernel versions; instead
// we check that the model/family token from the hw register appears
// somewhere in the /proc string (case-insensitive).
func cpuStringsCompatible(hw, proc string) bool {
	// hw format: vendor/family/model/stepping/brand
	// Extract the brand (last field) for substring comparison.
	fields := strings.SplitN(hw, "/", 5)
	if len(fields) < 5 {
		return true // can't check; assume ok
	}
	brand := strings.ToLower(strings.TrimSpace(fields[4]))
	if brand == "" {
		return true
	}
	// Check that a significant portion of the brand appears in /proc.
	// Use the first 16 chars as the "model signature".
	sig := brand
	if len(sig) > 16 {
		sig = sig[:16]
	}
	return strings.Contains(strings.ToLower(proc), sig)
}

// memTotalFromSysconf reads memory size directly via the C sysconf
// syscall path rather than /proc/meminfo, which is rootkit-spoofable.
// On Linux, sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGE_SIZE) comes
// directly from the kernel's meminfo structures — same data as
// /proc/meminfo but served through a syscall that cannot be intercepted
// by a pure userspace rootkit.
//
// We keep /proc/meminfo as the fallback for portability.
func memTotalFromSysconf() string {
	// Use sysconf via syscall package — pure Go, no cgo.
	pages, pageSize := sysconfMemory()
	if pages > 0 && pageSize > 0 {
		kb := (pages * pageSize) / 1024
		// Round to the nearest 512 MB to tolerate BIOS/firmware rounding.
		const granKB = 512 * 1024
		kb = ((kb + granKB/2) / granKB) * granKB
		return strings.TrimSpace(string(appendUint(nil, uint64(kb))) + " kB")
	}
	return memTotalKB() // fallback to /proc
}

// appendUint appends the decimal representation of v to b.
func appendUint(b []byte, v uint64) []byte {
	if v == 0 {
		return append(b, '0')
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return append(b, buf[i:]...)
}

func readFirstLine(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	if s.Scan() {
		return strings.TrimSpace(s.Text())
	}
	return ""
}

func cpuModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Model") ||
			strings.HasPrefix(line, "Hardware") {
			if i := strings.Index(line, ":"); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

func memTotalKB() string {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "MemTotal:"))
		}
	}
	return ""
}

func macAddresses() string {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return ""
	}
	var macs []string
	for _, e := range entries {
		if e.Name() == "lo" {
			continue
		}
		b, err := os.ReadFile("/sys/class/net/" + e.Name() + "/address")
		if err != nil {
			continue
		}
		mac := strings.TrimSpace(string(b))
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	return strings.Join(macs, ",")
}
