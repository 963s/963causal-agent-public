//go:build !amd64 && !arm64

package identity

// readCPUIDPlatform returns an empty CPUIDInfo on architectures we have
// not yet implemented direct register access for. The hwfingerprint will
// fall through to the /proc path for the cpu_model component.
func readCPUIDPlatform() CPUIDInfo {
	return CPUIDInfo{}
}
