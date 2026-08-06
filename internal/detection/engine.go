package detection

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/paddman/NTAgentShield/internal/model"
)

type Rule interface {
	ID() string
	Evaluate(model.Event) []model.Finding
}

type Engine struct {
	rules []Rule
	auth  *authFailureTracker
}

func New() *Engine {
	return &Engine{
		rules: []Rule{
			promptInjectionRule{},
			encodedPowerShellRule{},
			webWorkerShellRule{},
			sqlDangerRule{},
			pathTraversalRule{},
			defenseEvasionRule{},
			webShellWriteRule{},
		},
		auth: newAuthFailureTracker(10, 5*time.Minute),
	}
}

func (e *Engine) Inspect(event model.Event) []model.Finding {
	findings := make([]model.Finding, 0)
	for _, rule := range e.rules {
		findings = append(findings, rule.Evaluate(event)...)
	}
	if finding := e.auth.Inspect(event); finding != nil {
		findings = append(findings, *finding)
	}
	return findings
}

func eventText(event model.Event) string {
	attributes, _ := json.Marshal(event.Attributes)
	parts := []string{
		event.Message,
		event.Process.Image,
		event.Process.ParentImage,
		event.Process.CommandLine,
		event.HTTP.Path,
		event.HTTP.Query,
		event.HTTP.UserAgent,
		string(attributes),
	}
	return strings.ToLower(strings.Join(parts, "\n"))
}

type promptInjectionRule struct{}

var promptInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior)\s+(instructions|rules)`),
	regexp.MustCompile(`(?i)reveal\s+(the\s+)?(system|developer)\s+prompt`),
	regexp.MustCompile(`(?i)(call|invoke|use)\s+(the\s+)?(tool|function)`),
	regexp.MustCompile(`(?i)<\|(?:system|assistant|developer|tool)\|>`),
	regexp.MustCompile(`(?i)begin\s+(system|developer)\s+(message|instructions)`),
	regexp.MustCompile(`ไม่ต้องทำตามคำสั่งก่อนหน้า|เปิดเผย system prompt|เรียกใช้ tool|รันคำสั่งนี้`),
}

func (promptInjectionRule) ID() string { return "NTS-AI-001" }

func (r promptInjectionRule) Evaluate(event model.Event) []model.Finding {
	if !event.Trust.IsUntrusted() {
		return nil
	}
	text := eventText(event)
	for _, pattern := range promptInjectionPatterns {
		if pattern.MatchString(text) {
			finding := model.NewFinding(event, r.ID(), "Prompt-injection content in untrusted evidence", "Log, request, code, or network evidence contains text that attempts to influence an AI agent. The content remains evidence only and must never become an instruction.", "ai.prompt_injection", model.SeverityHigh, 88)
			finding.MITRETactics = []string{"AI Model Access", "Execution"}
			finding.RecommendedSteps = []string{"Keep the event marked untrusted", "Do not expose privileged tools to this context", "Review the originating request and related process activity"}
			return []model.Finding{finding}
		}
	}
	return nil
}

type encodedPowerShellRule struct{}

var encodedPowerShell = regexp.MustCompile(`(?i)(powershell(?:\.exe)?|pwsh(?:\.exe)?).*(?:-enc(?:odedcommand)?\b|frombase64string|invoke-expression|\biex\s*\()`)

func (encodedPowerShellRule) ID() string { return "NTS-WIN-001" }

func (r encodedPowerShellRule) Evaluate(event model.Event) []model.Finding {
	if !encodedPowerShell.MatchString(eventText(event)) {
		return nil
	}
	finding := model.NewFinding(event, r.ID(), "Encoded or in-memory PowerShell activity", "PowerShell command line contains encoding or in-memory execution primitives often used to hide payloads.", "execution.powershell", model.SeverityHigh, 84)
	finding.MITRETactics = []string{"Execution", "Defense Evasion"}
	finding.MITRETechniques = []string{"T1059.001"}
	finding.RecommendedSteps = []string{"Inspect the full process tree", "Hash the executable and referenced files", "Correlate outbound connections and script block logs"}
	return []model.Finding{finding}
}

func imageBase(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	return strings.ToLower(filepath.Base(path))
}

type webWorkerShellRule struct{}

func (webWorkerShellRule) ID() string { return "NTS-WEB-001" }

func (r webWorkerShellRule) Evaluate(event model.Event) []model.Finding {
	parent := imageBase(event.Process.ParentImage)
	child := imageBase(event.Process.Image)
	webParents := map[string]bool{"w3wp.exe": true, "nginx": true, "httpd": true, "apache2": true, "php-fpm": true, "java": true}
	shells := map[string]bool{"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "sh": true, "bash": true, "dash": true, "zsh": true, "curl": true, "wget": true, "nc": true, "ncat": true}
	if !webParents[parent] || !shells[child] {
		return nil
	}
	finding := model.NewFinding(event, r.ID(), "Web service spawned a command interpreter", fmt.Sprintf("Web worker %s created %s. This is a high-signal exploit or web-shell behavior unless explicitly expected.", parent, child), "exploit.web_worker_shell", model.SeverityCritical, 96)
	finding.MITRETactics = []string{"Initial Access", "Execution"}
	finding.MITRETechniques = []string{"T1190", "T1059"}
	finding.RecommendedSteps = []string{"Capture process memory and command line", "Review the triggering web request", "Hash newly written webroot files", "Consider isolating the host after operator approval"}
	return []model.Finding{finding}
}

type sqlDangerRule struct{}

var dangerousSQL = regexp.MustCompile(`(?i)\b(grant\s+all|create\s+user|alter\s+user|into\s+outfile|load_file\s*\(|xp_cmdshell|sp_configure|copy\s+.+\s+program|pg_read_file\s*\(|lo_export\s*\(|create\s+(?:or\s+replace\s+)?function)\b`)

func (sqlDangerRule) ID() string { return "NTS-DB-001" }

func (r sqlDangerRule) Evaluate(event model.Event) []model.Finding {
	if event.Kind != "database.query" || !dangerousSQL.MatchString(eventText(event)) {
		return nil
	}
	finding := model.NewFinding(event, r.ID(), "High-risk database operation", "Database telemetry contains privilege, file-system, operating-system, or executable-extension behavior that should not normally originate from an application account.", "database.high_risk_query", model.SeverityHigh, 86)
	finding.MITRETactics = []string{"Privilege Escalation", "Execution", "Collection"}
	finding.RecommendedSteps = []string{"Verify the database account and source application", "Compare the query fingerprint with the deployment baseline", "Review database audit logs and resulting file/process activity"}
	return []model.Finding{finding}
}

type pathTraversalRule struct{}

var traversal = regexp.MustCompile(`(?i)(?:\.\./|\.\.\\|%2e%2e(?:%2f|/|%5c)|/etc/passwd|/proc/self|win\.ini|web\.config|boot\.ini)`)

func (pathTraversalRule) ID() string { return "NTS-WEB-002" }

func (r pathTraversalRule) Evaluate(event model.Event) []model.Finding {
	if event.Kind != "web.request" || !traversal.MatchString(event.HTTP.Path+"?"+event.HTTP.Query) {
		return nil
	}
	finding := model.NewFinding(event, r.ID(), "Path traversal or sensitive-file probe", "The request path contains traversal encoding or a sensitive operating-system/application file target.", "web.path_traversal", model.SeverityMedium, 90)
	finding.MITRETactics = []string{"Reconnaissance", "Initial Access"}
	finding.MITRETechniques = []string{"T1190"}
	finding.RecommendedSteps = []string{"Inspect response status and bytes", "Correlate repeated paths from the same source", "Review file access and application errors"}
	return []model.Finding{finding}
}

type defenseEvasionRule struct{}

var defenseEvasion = regexp.MustCompile(`(?i)(wevtutil(?:\.exe)?\s+cl\b|auditctl\s+-e\s+0\b|set-mppreference\s+-disablerealtimemonitoring|rm\s+-[^\n]*\s+/var/log|clear-eventlog\b)`)

func (defenseEvasionRule) ID() string { return "NTS-EVADE-001" }

func (r defenseEvasionRule) Evaluate(event model.Event) []model.Finding {
	if !defenseEvasion.MatchString(eventText(event)) {
		return nil
	}
	finding := model.NewFinding(event, r.ID(), "Security logging or protection disabling behavior", "Command or telemetry indicates an attempt to clear logs or disable a defensive control.", "defense_evasion.control_disable", model.SeverityCritical, 94)
	finding.MITRETactics = []string{"Defense Evasion"}
	finding.MITRETechniques = []string{"T1070", "T1562.001"}
	finding.RecommendedSteps = []string{"Preserve the evidence journal", "Inspect the initiating identity and process tree", "Check whether protection settings actually changed"}
	return []model.Finding{finding}
}

type webShellWriteRule struct{}

func (webShellWriteRule) ID() string { return "NTS-WEB-003" }

func (r webShellWriteRule) Evaluate(event model.Event) []model.Finding {
	if event.Kind != "file.write" && event.File.Operation != "create" && event.File.Operation != "modify" {
		return nil
	}
	path := strings.ToLower(filepath.ToSlash(event.File.Path))
	webroot := strings.Contains(path, "/wwwroot/") || strings.Contains(path, "/inetpub/") || strings.Contains(path, "/var/www/") || strings.Contains(path, "/htdocs/")
	ext := strings.ToLower(filepath.Ext(path))
	dynamic := ext == ".php" || ext == ".aspx" || ext == ".asp" || ext == ".jsp" || ext == ".jspx"
	if !webroot || !dynamic {
		return nil
	}
	finding := model.NewFinding(event, r.ID(), "Executable server-side file written to a webroot", "A dynamic server-side file was created or modified in a web-accessible directory.", "persistence.web_shell_artifact", model.SeverityHigh, 82)
	finding.MITRETactics = []string{"Persistence"}
	finding.MITRETechniques = []string{"T1505.003"}
	finding.RecommendedSteps = []string{"Hash and quarantine only after approval", "Compare with deployment manifests", "Correlate the writing process and inbound request"}
	return []model.Finding{finding}
}

type authFailureTracker struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	entries   map[string][]time.Time
}

func newAuthFailureTracker(threshold int, window time.Duration) *authFailureTracker {
	return &authFailureTracker{threshold: threshold, window: window, entries: map[string][]time.Time{}}
}

func (t *authFailureTracker) Inspect(event model.Event) *model.Finding {
	failed := event.Kind == "auth.failure" || (event.Kind == "web.request" && (event.HTTP.Status == 401 || event.HTTP.Status == 403))
	if !failed {
		return nil
	}
	key := event.Network.SourceIP + "|" + event.Actor.User
	if key == "|" {
		return nil
	}
	now := event.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	cutoff := now.Add(-t.window)
	t.mu.Lock()
	defer t.mu.Unlock()
	kept := t.entries[key][:0]
	for _, timestamp := range t.entries[key] {
		if timestamp.After(cutoff) {
			kept = append(kept, timestamp)
		}
	}
	kept = append(kept, now)
	t.entries[key] = kept
	if len(kept) != t.threshold {
		return nil
	}
	finding := model.NewFinding(event, "NTS-AUTH-001", "Authentication failure burst", fmt.Sprintf("Observed %d authentication failures from the same source/account within %s.", len(kept), t.window), "credential_access.brute_force", model.SeverityHigh, 88)
	finding.MITRETactics = []string{"Credential Access"}
	finding.MITRETechniques = []string{"T1110"}
	finding.Attributes["failure_count"] = len(kept)
	finding.Attributes["window_seconds"] = int(t.window.Seconds())
	finding.RecommendedSteps = []string{"Review successful logins after the burst", "Check whether the source is an approved scanner", "Apply rate limiting or blocking through an approved response policy"}
	return &finding
}
