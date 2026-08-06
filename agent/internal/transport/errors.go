package transport

import (
	"encoding/json"
	"fmt"
	"strings"
)

type GatewayError struct {
	StatusCode int
	Code       string
}

func (e *GatewayError) Error() string {
	if e == nil {
		return "evidence gateway request failed"
	}
	code := strings.TrimSpace(e.Code)
	if code == "" {
		code = "request_rejected"
	}
	return fmt.Sprintf("evidence gateway returned HTTP %d: %s", e.StatusCode, code)
}

func (e *GatewayError) Retryable() bool {
	if e == nil {
		return false
	}
	return e.StatusCode == 408 || e.StatusCode == 425 || e.StatusCode == 429 || e.StatusCode >= 500
}

func DecodeGatewayError(statusCode int, content []byte) error {
	var payload struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(content, &payload)
	code := strings.TrimSpace(payload.Error)
	if code == "" {
		code = "request_rejected"
	}
	if len(code) > 128 {
		code = code[:128]
	}
	return &GatewayError{StatusCode: statusCode, Code: code}
}
