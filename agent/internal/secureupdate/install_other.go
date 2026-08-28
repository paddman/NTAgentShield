//go:build !windows

package secureupdate

import "fmt"

func InstallWindowsServiceUpdate(_, _, _ string) error {
	return fmt.Errorf("Windows Service update installation is only available on Windows")
}
