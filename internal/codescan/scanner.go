package codescan

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/paddman/NTAgentShield/internal/model"
	"github.com/paddman/NTAgentShield/internal/redact"
)

const defaultMaxFileSize = 2 * 1024 * 1024

type Finding struct {
	RuleID      string         `json:"rule_id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    model.Severity `json:"severity"`
	Confidence  int            `json:"confidence"`
	CWE         string         `json:"cwe,omitempty"`
	Path        string         `json:"path"`
	Line        int            `json:"line"`
	Excerpt     string         `json:"excerpt"`
}

type Result struct {
	Root         string    `json:"root"`
	FilesScanned int       `json:"files_scanned"`
	FilesSkipped int       `json:"files_skipped"`
	Findings     []Finding `json:"findings"`
}

type lineRule struct {
	id          string
	title       string
	description string
	severity    model.Severity
	confidence  int
	cwe         string
	pattern     *regexp.Regexp
}

type Scanner struct {
	maxFileSize int64
	rules       []lineRule
}

func New() *Scanner {
	return &Scanner{
		maxFileSize: defaultMaxFileSize,
		rules: []lineRule{
			{
				id:          "NTS-CODE-001",
				title:       "Possible hard-coded credential or API secret",
				description: "A credential-like variable is assigned a long string literal. The excerpt is redacted before reporting.",
				severity:    model.SeverityHigh,
				confidence:  78,
				cwe:         "CWE-798",
				pattern:     regexp.MustCompile(`(?i)\b(api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|private[_-]?key)\b\s*[:=]\s*["'][^"']{8,}["']`),
			},
			{
				id:          "NTS-CODE-002",
				title:       "TLS certificate verification disabled",
				description: "The code appears to disable certificate verification, enabling man-in-the-middle attacks.",
				severity:    model.SeverityHigh,
				confidence:  92,
				cwe:         "CWE-295",
				pattern:     regexp.MustCompile(`(?i)(verify\s*=\s*false|insecureskipverify\s*:\s*true|rejectunauthorized\s*:\s*false|servercertificatecustomvalidationcallback\s*=\s*.*true)`),
			},
			{
				id:          "NTS-CODE-003",
				title:       "Unsafe deserialization primitive",
				description: "The code uses a deserialization API that can execute attacker-controlled object graphs when input is untrusted.",
				severity:    model.SeverityHigh,
				confidence:  86,
				cwe:         "CWE-502",
				pattern:     regexp.MustCompile(`(?i)(pickle\.loads?\s*\(|binaryformatter\b|objectinputstream\s*\(|yaml\.load\s*\(|unserialize\s*\()`),
			},
			{
				id:          "NTS-CODE-004",
				title:       "Command execution primitive requires data-flow review",
				description: "A process or shell execution API is present. Confirm that attacker-controlled input cannot reach it.",
				severity:    model.SeverityMedium,
				confidence:  70,
				cwe:         "CWE-78",
				pattern:     regexp.MustCompile(`(?i)(os\.system\s*\(|subprocess\..*shell\s*=\s*true|child_process\.(exec|execsync)\s*\(|runtime\.getruntime\(\)\.exec\s*\(|process\.start\s*\(|\b(shell_exec|passthru|proc_open|popen)\s*\()`),
			},
			{
				id:          "NTS-CODE-005",
				title:       "Possible SQL query built by string concatenation",
				description: "A SQL statement appears near string concatenation. Replace it with parameterized queries after confirming the data flow.",
				severity:    model.SeverityMedium,
				confidence:  66,
				cwe:         "CWE-89",
				pattern:     regexp.MustCompile(`(?i)["']\s*(select|insert|update|delete)\b[^\n]*["'][^\n]*(\+|\.\s*\$|format\s*\(|sprintf\s*\()`),
			},
			{
				id:          "NTS-CODE-006",
				title:       "Potentially dangerous dynamic code evaluation",
				description: "Dynamic evaluation is present and should not receive untrusted content.",
				severity:    model.SeverityHigh,
				confidence:  82,
				cwe:         "CWE-95",
				pattern:     regexp.MustCompile(`(?i)(\beval\s*\(|new\s+function\s*\(|compile\s*\([^,]+,[^,]+,[^)]*["']exec["'])`),
			},
			{
				id:          "NTS-CODE-007",
				title:       "Broad network exposure in infrastructure code",
				description: "The configuration exposes a resource to all IPv4 addresses. Confirm that this is intentional and protected upstream.",
				severity:    model.SeverityMedium,
				confidence:  72,
				cwe:         "CWE-284",
				pattern:     regexp.MustCompile(`(?i)(0\.0\.0\.0/0|cidr_ipv4\s*=\s*["']0\.0\.0\.0/0["'])`),
			},
		},
	}
}

func (s *Scanner) Scan(ctx context.Context, root string) (Result, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return Result{}, err
	}
	result := Result{Root: absolute, Findings: []Finding{}}
	err = filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if entry.IsDir() {
			if path != absolute && shouldSkipDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !isSupportedFile(entry.Name()) {
			result.FilesSkipped++
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > s.maxFileSize {
			result.FilesSkipped++
			return nil
		}
		findings, err := s.scanFile(absolute, path)
		if err != nil {
			return err
		}
		result.FilesScanned++
		result.Findings = append(result.Findings, findings...)
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Path == result.Findings[j].Path {
			if result.Findings[i].Line == result.Findings[j].Line {
				return result.Findings[i].RuleID < result.Findings[j].RuleID
			}
			return result.Findings[i].Line < result.Findings[j].Line
		}
		return result.Findings[i].Path < result.Findings[j].Path
	})
	return result, nil
}

func (s *Scanner) scanFile(root, path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	relative, _ := filepath.Rel(root, path)
	relative = filepath.ToSlash(relative)
	findings := []Finding{}
	lines := []string{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), int(s.maxFileSize))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		lines = append(lines, line)
		for _, rule := range s.rules {
			if rule.pattern.MatchString(line) {
				findings = append(findings, findingFromRule(rule, relative, lineNumber, line))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	content := strings.ToLower(strings.Join(lines, "\n"))
	if isPHP(path) && strings.Contains(content, "eval(") && (strings.Contains(content, "base64_decode(") || strings.Contains(content, "gzinflate(")) {
		findings = append(findings, Finding{
			RuleID:      "NTS-CODE-008",
			Title:       "PHP dynamic-evaluation chain resembles a web shell",
			Description: "The file combines dynamic evaluation with encoded or compressed payload decoding. This is a high-signal pattern that requires immediate review.",
			Severity:    model.SeverityCritical,
			Confidence:  94,
			CWE:         "CWE-95",
			Path:        relative,
			Line:        firstLineContaining(lines, "eval("),
			Excerpt:     "[dynamic evaluation and encoded payload chain]",
		})
	}
	if isGitHubWorkflow(path) && strings.Contains(content, "pull_request_target:") && strings.Contains(content, "github.event.pull_request.head") {
		findings = append(findings, Finding{
			RuleID:      "NTS-CODE-009",
			Title:       "Potential pull_request_target workflow injection",
			Description: "A privileged pull_request_target workflow references pull-request head content. Untrusted fork code may gain access to repository secrets.",
			Severity:    model.SeverityCritical,
			Confidence:  92,
			CWE:         "CWE-829",
			Path:        relative,
			Line:        firstLineContaining(lines, "pull_request_target"),
			Excerpt:     "pull_request_target with pull-request head reference",
		})
	}
	if strings.EqualFold(filepath.Base(path), "Dockerfile") && regexp.MustCompile(`(?i)(curl|wget)[^\n|]*\|\s*(sh|bash)`).MatchString(content) {
		findings = append(findings, Finding{
			RuleID:      "NTS-CODE-010",
			Title:       "Remote script piped directly into a shell",
			Description: "The container build executes network content without pinning or verification, creating a supply-chain execution path.",
			Severity:    model.SeverityHigh,
			Confidence:  90,
			CWE:         "CWE-494",
			Path:        relative,
			Line:        firstLineMatching(lines, regexp.MustCompile(`(?i)(curl|wget).*\|\s*(sh|bash)`)),
			Excerpt:     "[remote content piped to shell]",
		})
	}
	return deduplicate(findings), nil
}

func findingFromRule(rule lineRule, path string, line int, excerpt string) Finding {
	return Finding{
		RuleID:      rule.id,
		Title:       rule.title,
		Description: rule.description,
		Severity:    rule.severity,
		Confidence:  rule.confidence,
		CWE:         rule.cwe,
		Path:        path,
		Line:        line,
		Excerpt:     safeExcerpt(excerpt),
	}
}

func safeExcerpt(value string) string {
	value = strings.TrimSpace(redact.String(value))
	if len(value) > 240 {
		value = value[:240] + "…"
	}
	return value
}

func shouldSkipDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".svn", ".hg", "node_modules", "vendor", "bin", "dist", "build", "data", ".idea", ".vscode":
		return true
	default:
		return false
	}
}

func isSupportedFile(name string) bool {
	if strings.EqualFold(name, "Dockerfile") || strings.EqualFold(name, "Jenkinsfile") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".java", ".php", ".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".ps1", ".sh", ".bash", ".sql", ".tf", ".hcl", ".yml", ".yaml", ".json", ".xml", ".config", ".conf":
		return true
	default:
		return false
	}
}

func isPHP(path string) bool { return strings.EqualFold(filepath.Ext(path), ".php") }

func isGitHubWorkflow(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	return strings.Contains(normalized, "/.github/workflows/") && (strings.HasSuffix(normalized, ".yml") || strings.HasSuffix(normalized, ".yaml"))
}

func firstLineContaining(lines []string, needle string) int {
	needle = strings.ToLower(needle)
	for i, line := range lines {
		if strings.Contains(strings.ToLower(line), needle) {
			return i + 1
		}
	}
	return 1
}

func firstLineMatching(lines []string, pattern *regexp.Regexp) int {
	for i, line := range lines {
		if pattern.MatchString(line) {
			return i + 1
		}
	}
	return 1
}

func deduplicate(findings []Finding) []Finding {
	seen := map[string]struct{}{}
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		key := fmt.Sprintf("%s|%s|%d", finding.RuleID, finding.Path, finding.Line)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, finding)
	}
	return result
}

var ErrNoFiles = errors.New("no supported source files found")
