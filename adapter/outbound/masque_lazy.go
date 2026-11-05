package outbound

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/metacubex/mipstack"
)

func (w *Masque) startDevice(ctx context.Context) error {
	w.deviceMutex.Lock()
	defer w.deviceMutex.Unlock()
	if err := w.runCtx.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.runDevice {
		return nil
	}
	device := w.tunDevice
	if device == nil {
		var err error
		if device, err = newIPStack(w.option.IPStack, w.localPrefixes, uint32(w.option.MTU)); err != nil {
			return fmt.Errorf("create device: %w", err)
		}
	}
	if err := device.Start(); err != nil {
		if device != w.tunDevice {
			_ = device.Close()
		}
		return err
	}
	w.tunDevice, w.runDevice = device, true
	return nil
}

// Unusual inputs still go through the selected backend's constructor so its
// validation errors remain configuration errors instead of first-dial errors.
func ipStackNeedsEagerValidation(prefixes []netip.Prefix, mtu uint32) bool {
	if mipstack.ValidateConfig(mipstack.Config{LocalAddresses: prefixes, MTU: mtu}) != nil {
		return true
	}
	// gVisor rejects a repeated address that mipstack accepts.
	for i, prefix := range prefixes {
		for _, other := range prefixes[:i] {
			if prefix.Addr() == other.Addr() {
				return true
			}
		}
	}
	return false
}
