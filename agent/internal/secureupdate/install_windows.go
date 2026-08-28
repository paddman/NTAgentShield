//go:build windows

package secureupdate

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func InstallWindowsServiceUpdate(stagedPath, targetPath, serviceName string) error {
	stagedPath, err := filepath.Abs(stagedPath)
	if err != nil {
		return err
	}
	targetPath, err = filepath.Abs(targetPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.VolumeName(stagedPath), filepath.VolumeName(targetPath)) {
		return fmt.Errorf("staged update and target must be on the same Windows volume")
	}
	if serviceName == "" || strings.ContainsAny(serviceName, "\r\n\x00") {
		return fmt.Errorf("Windows service name is invalid")
	}
	if err := runSC("stop", serviceName); err != nil && !strings.Contains(err.Error(), "1062") {
		return err
	}
	if err := waitServiceState(serviceName, "STOPPED", 60*time.Second); err != nil {
		return err
	}

	backupPath := targetPath + ".previous"
	_ = os.Remove(backupPath)
	if err := os.Rename(targetPath, backupPath); err != nil {
		return fmt.Errorf("backup current Agent binary: %w", err)
	}
	installed := false
	defer func() {
		if !installed {
			_ = os.Remove(targetPath)
			_ = os.Rename(backupPath, targetPath)
			_ = runSC("start", serviceName)
		}
	}()
	if err := os.Rename(stagedPath, targetPath); err != nil {
		return fmt.Errorf("install staged Agent binary: %w", err)
	}
	if err := runSC("start", serviceName); err != nil {
		return err
	}
	if err := waitServiceState(serviceName, "RUNNING", 60*time.Second); err != nil {
		return err
	}
	installed = true
	_ = os.Remove(backupPath)
	return nil
}

func runSC(arguments ...string) error {
	command := exec.Command("sc.exe", arguments...)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Run(); err != nil {
		return fmt.Errorf("sc.exe %s failed: %s: %w", strings.Join(arguments, " "), output.String(), err)
	}
	return nil
}

func waitServiceState(serviceName, expected string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		command := exec.Command("sc.exe", "query", serviceName)
		output, err := command.CombinedOutput()
		if err == nil && strings.Contains(strings.ToUpper(string(output)), "STATE") &&
			strings.Contains(strings.ToUpper(string(output)), expected) {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("Windows service %s did not reach state %s", serviceName, expected)
}
