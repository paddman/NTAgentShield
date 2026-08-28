//go:build windows

package servicehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"
)

const (
	serviceStopped      = 1
	serviceStartPending = 2
	serviceStopPending  = 3
	serviceRunning      = 4

	serviceWin32OwnProcess   = 0x00000010
	serviceAcceptStop        = 0x00000001
	serviceAcceptShutdown    = 0x00000004
	serviceAcceptPreshutdown = 0x00000100

	serviceControlStop        = 1
	serviceControlShutdown    = 5
	serviceControlPreshutdown = 15

	errorFailedServiceControllerConnect syscall.Errno = 1063
)

var (
	advapi32                          = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDispatcherW   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = advapi32.NewProc("SetServiceStatus")

	hostMu     sync.Mutex
	hostName   string
	hostRun    func(context.Context) error
	hostCancel context.CancelFunc
	hostHandle uintptr
	hostResult error
)

type serviceTableEntry struct {
	serviceName *uint16
	serviceProc uintptr
}

type serviceStatus struct {
	serviceType             uint32
	currentState            uint32
	controlsAccepted        uint32
	win32ExitCode           uint32
	serviceSpecificExitCode uint32
	checkPoint              uint32
	waitHint                uint32
}

// Run starts the Agent through the Windows Service Control Manager. When the
// process is launched interactively, it falls back to a Ctrl+C-aware console.
func Run(name string, run func(context.Context) error) error {
	if name == "" || run == nil {
		return errors.New("service name and run function are required")
	}
	namePointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("encode service name: %w", err)
	}

	hostMu.Lock()
	hostName = name
	hostRun = run
	hostCancel = nil
	hostHandle = 0
	hostResult = nil
	hostMu.Unlock()

	callback := syscall.NewCallback(serviceMain)
	table := [2]serviceTableEntry{
		{serviceName: namePointer, serviceProc: callback},
		{},
	}
	result, _, callErr := procStartServiceCtrlDispatcherW.Call(
		uintptr(unsafe.Pointer(&table[0])),
	)
	if result == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == errorFailedServiceControllerConnect {
			return runConsole(run)
		}
		return fmt.Errorf("StartServiceCtrlDispatcherW: %w", callErr)
	}
	hostMu.Lock()
	defer hostMu.Unlock()
	return hostResult
}

func runConsole(run func(context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return run(ctx)
}

func serviceMain(_ uintptr, _ uintptr) uintptr {
	hostMu.Lock()
	name := hostName
	run := hostRun
	hostMu.Unlock()

	namePointer, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		setResult(err)
		return 0
	}
	handler := syscall.NewCallback(serviceControlHandler)
	handle, _, callErr := procRegisterServiceCtrlHandlerExW.Call(
		uintptr(unsafe.Pointer(namePointer)),
		handler,
		0,
	)
	if handle == 0 {
		setResult(fmt.Errorf("RegisterServiceCtrlHandlerExW: %w", callErr))
		return 0
	}

	ctx, cancel := context.WithCancel(context.Background())
	hostMu.Lock()
	hostHandle = handle
	hostCancel = cancel
	hostMu.Unlock()
	defer cancel()

	_ = reportStatus(serviceStartPending, 0, 1, 15000, 0)
	_ = reportStatus(
		serviceRunning,
		serviceAcceptStop|serviceAcceptShutdown|serviceAcceptPreshutdown,
		0,
		0,
		0,
	)
	runErr := run(ctx)
	_ = reportStatus(serviceStopPending, 0, 1, 15000, 0)
	exitCode := uint32(0)
	if runErr != nil {
		exitCode = 1
	}
	_ = reportStatus(serviceStopped, 0, 0, 0, exitCode)
	setResult(runErr)
	return 0
}

func serviceControlHandler(control uintptr, _ uintptr, _ uintptr, _ uintptr) uintptr {
	switch uint32(control) {
	case serviceControlStop, serviceControlShutdown, serviceControlPreshutdown:
		hostMu.Lock()
		cancel := hostCancel
		hostMu.Unlock()
		_ = reportStatus(serviceStopPending, 0, 1, 15000, 0)
		if cancel != nil {
			cancel()
		}
	}
	return 0
}

func reportStatus(
	state uint32,
	accepted uint32,
	checkpoint uint32,
	waitHint uint32,
	exitCode uint32,
) error {
	hostMu.Lock()
	handle := hostHandle
	hostMu.Unlock()
	if handle == 0 {
		return nil
	}
	status := serviceStatus{
		serviceType:      serviceWin32OwnProcess,
		currentState:     state,
		controlsAccepted: accepted,
		win32ExitCode:    exitCode,
		checkPoint:       checkpoint,
		waitHint:         waitHint,
	}
	result, _, callErr := procSetServiceStatus.Call(
		handle,
		uintptr(unsafe.Pointer(&status)),
	)
	if result == 0 {
		return fmt.Errorf("SetServiceStatus: %w", callErr)
	}
	return nil
}

func setResult(err error) {
	hostMu.Lock()
	hostResult = err
	hostMu.Unlock()
}
