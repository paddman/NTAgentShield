package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

var (
	singleQuoted = regexp.MustCompile(`'(?:''|[^'])*'`)
	doubleQuoted = regexp.MustCompile(`"(?:""|[^"])*"`)
	number       = regexp.MustCompile(`\b\d+(?:\.\d+)?\b`)
	whitespace   = regexp.MustCompile(`\s+`)
	verbs        = regexp.MustCompile(`(?i)\b(select|insert|update|delete|merge|create|alter|drop|truncate|grant|revoke|execute|exec|call|copy|load|set|show|use)\b`)
)

func SQL(query string) string {
	out := singleQuoted.ReplaceAllString(query, "?")
	out = doubleQuoted.ReplaceAllString(out, "?")
	out = number.ReplaceAllString(out, "?")
	out = strings.ToLower(strings.TrimSpace(out))
	out = whitespace.ReplaceAllString(out, " ")
	return out
}

func SQLFingerprint(query string) string {
	sum := sha256.Sum256([]byte(SQL(query)))
	return hex.EncodeToString(sum[:])
}

func SQLVerbs(query string) []string {
	matches := verbs.FindAllString(strings.ToLower(query), -1)
	set := map[string]struct{}{}
	for _, match := range matches {
		set[match] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for verb := range set {
		result = append(result, verb)
	}
	sort.Strings(result)
	return result
}
