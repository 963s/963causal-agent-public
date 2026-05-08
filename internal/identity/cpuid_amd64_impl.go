//go:build amd64

package identity

// readCPUIDPlatform implements the amd64 path by calling the three
// assembly stubs in cpuid_amd64.s.
func readCPUIDPlatform() CPUIDInfo {
	_, vb, vd, vc := cpuidLeaf0Asm()
	// Vendor is BDC order (not BCD): "GenuineIntel" = EBX="Genu" EDX="ineI" ECX="ntel"
	vendor := u32ToStr(vb) + u32ToStr(vd) + u32ToStr(vc)

	eax, _, _, _ := cpuidLeaf1Asm()
	stepping := eax & 0xf
	model := (eax >> 4) & 0xf
	family := (eax >> 8) & 0xf
	extModel := (eax >> 16) & 0xf
	extFamily := (eax >> 20) & 0xff
	if family == 0xf {
		family += extFamily
	}
	if family == 0x6 || family == 0xf {
		model += extModel << 4
	}

	var brand [48]byte
	cpuidBrandAsm(&brand)

	return CPUIDInfo{
		Vendor:   vendor,
		Brand:    string(brand[:]),
		Family:   family,
		Model:    model,
		Stepping: stepping,
	}
}

// u32ToStr converts a little-endian uint32 to its 4-byte ASCII string.
func u32ToStr(v uint32) string {
	return string([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
}
