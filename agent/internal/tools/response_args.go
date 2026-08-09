package tools

import (
	"errors"
	"fmt"
	"math"
)

func rejectUnknownArgs(args map[string]interface{}, allowed ...string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range args {
		if _, ok := allowedSet[key]; !ok {
			return fmt.Errorf("unsupported argument %q", key)
		}
	}
	return nil
}

func exactPIDArg(args map[string]interface{}) (int, error) {
	value, ok := args["pid"]
	if !ok {
		return 0, errors.New("pid is required")
	}
	switch typed := value.(type) {
	case int:
		return typed, nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed || typed < 0 || typed > 2147483647 {
			return 0, errors.New("pid must be an exact positive 32-bit integer")
		}
		return int(typed), nil
	default:
		return 0, errors.New("pid must be an exact integer")
	}
}

func exactPortArg(args map[string]interface{}) (int, error) {
	value, ok := args["port"]
	if !ok {
		return 0, errors.New("port is required")
	}
	switch typed := value.(type) {
	case int:
		if typed < 1 || typed > 65535 {
			return 0, errors.New("port must be an exact integer between 1 and 65535")
		}
		return typed, nil
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed || typed < 1 || typed > 65535 {
			return 0, errors.New("port must be an exact integer between 1 and 65535")
		}
		return int(typed), nil
	default:
		return 0, errors.New("port must be an exact integer between 1 and 65535")
	}
}
