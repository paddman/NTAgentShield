//go:build !linux && !windows

package tools

import (
	"context"
	"errors"
	"net/netip"
)

type unsupportedNetworkBackend struct{}

func newNetworkContainmentBackend(ContainmentOptions) (networkContainmentBackend, error) {
	return unsupportedNetworkBackend{}, nil
}

func (unsupportedNetworkBackend) Isolate(context.Context) (map[string]interface{}, error) {
	return nil, errors.New("host isolation is only implemented on Windows and Linux")
}
func (unsupportedNetworkBackend) Release(context.Context) (map[string]interface{}, error) {
	return nil, errors.New("host isolation release is only implemented on Windows and Linux")
}
func (unsupportedNetworkBackend) Block(context.Context, netip.Addr) (map[string]interface{}, error) {
	return nil, errors.New("firewall IP containment is only implemented on Windows and Linux")
}
func (unsupportedNetworkBackend) Unblock(context.Context, netip.Addr) (map[string]interface{}, error) {
	return nil, errors.New("firewall IP containment is only implemented on Windows and Linux")
}
func (unsupportedNetworkBackend) OpenPort(context.Context, PortRule) (map[string]interface{}, error) {
	return nil, errors.New("firewall port containment is only implemented on Windows")
}
func (unsupportedNetworkBackend) ClosePort(context.Context, PortRule) (map[string]interface{}, error) {
	return nil, errors.New("firewall port containment is only implemented on Windows")
}
