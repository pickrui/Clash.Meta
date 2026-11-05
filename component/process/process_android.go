//go:build android

package process

import "github.com/metacubex/mihomo/constant"

type PackageNameResolver func(metadata *constant.Metadata)

var DefaultPackageNameResolver PackageNameResolver

func FindPackageName(metadata *constant.Metadata) {
	if resolver := DefaultPackageNameResolver; resolver != nil {
		resolver(metadata)
	}
}
