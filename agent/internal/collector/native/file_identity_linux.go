//go:build linux

package native

import (
	"os"
	"syscall"
)

func platformFileIdentity(info os.FileInfo) (uint64, uint64) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0
	}
	return uint64(stat.Dev), uint64(stat.Ino)
}
