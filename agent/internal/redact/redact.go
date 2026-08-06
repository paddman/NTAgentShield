package redact

import (
	"regexp"
	"strings"

	"github.com/paddman/NTAgentShield/internal/model"
)

var patterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}`), `${1}[REDACTED]`},
	{regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*([^\s,;]+)`), `${1}=[REDACTED]`},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), `[REDACTED_AWS_ACCESS_KEY]`},
	{regexp.MustCompile(`(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |OPENSSH )?PRIVATE KEY-----`), `[REDACTED_PRIVATE_KEY]`},
	{regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`), `[REDACTED_PAYMENT_NUMBER]`},
}

func String(value string) string {
	out := value
	for _, pattern := range patterns {
		out = pattern.re.ReplaceAllString(out, pattern.replacement)
	}
	return out
}

func Event(event *model.Event) {
	if event == nil {
		return
	}
	event.Message = String(event.Message)
	event.Process.CommandLine = String(event.Process.CommandLine)
	event.HTTP.Query = String(event.HTTP.Query)
	event.HTTP.UserAgent = String(event.HTTP.UserAgent)
	event.Attributes = mapValue(event.Attributes).(map[string]interface{})
}

func mapValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case string:
		return String(typed)
	case []string:
		result := make([]string, len(typed))
		for i, item := range typed {
			result[i] = String(item)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(typed))
		for i, item := range typed {
			result[i] = mapValue(item)
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "api_key") || strings.Contains(lower, "apikey") {
				result[key] = "[REDACTED]"
				continue
			}
			result[key] = mapValue(item)
		}
		return result
	default:
		return value
	}
}
