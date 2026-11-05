//go:build with_mips_low_memory

package tun

const (
	mipsTCPInitialBuffer = 32 * 1024
	mipsTCPMaximumBuffer = 128 * 1024
)
