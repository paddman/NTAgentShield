//go:build !linux

package native

import "os"

func platformFileIdentity(_ os.FileInfo) (uint64, uint64) {
	return 0, 0
}
