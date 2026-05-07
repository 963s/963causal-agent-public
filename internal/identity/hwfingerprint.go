package identity

import (
	"bufio"
	"encoding/hex"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/sha3"
)

// HardwareFingerprint returns a stable sha3-256 hex digest of machine-bound
// identifiers. Values are sorted before hashing so that device ordering does
// not perturb the fingerprint.
func HardwareFingerprint() string {
	parts := []string{
		readFirstLine("/etc/machine-id"),
		cpuModel(),
		memTotalKB(),
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
