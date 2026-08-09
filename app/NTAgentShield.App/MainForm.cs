using System.Diagnostics;
using System.Drawing;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NTAgentShield.App;

public sealed class MainForm : Form
{
    private const string TaskName = "NTAgentShield";
    private const string DataDirectory = @"C:\ProgramData\NTAgentShield";
    private const string TokenPath = DataDirectory + @"\agent-api.token";
    private const string JournalPath = DataDirectory + @"\evidence.journal.jsonl";
    private const string ConfigPath = DataDirectory + @"\agent.json";
    private const string ControlPath = @"C:\Program Files\NTAgentShield\ntagentshieldctl.exe";
    private const string StatusUrl = "http://127.0.0.1:9477/v1/status";

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };
    private readonly System.Windows.Forms.Timer _refreshTimer = new() { Interval = 5000 };
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private readonly Label _statusValue;
    private readonly Label _eventsValue;
    private readonly Label _findingsValue;
    private readonly Label _inventoryValue;
    private readonly Label _buildValue;
    private readonly Label _updatedValue;
    private readonly TextBox _details;
    private string? _aiResult;

    public MainForm()
    {
        Text = "NTAgentShield";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(760, 500);
        Size = new Size(860, 560);
        BackColor = Color.FromArgb(18, 24, 38);
        ForeColor = Color.White;
        Font = new Font("Segoe UI", 10F);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            Padding = new Padding(24),
            BackColor = BackColor
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 76));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 150));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 54));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        Controls.Add(root);

        var header = new Panel { Dock = DockStyle.Fill };
        header.Controls.Add(new Label
        {
            Text = "NTAgentShield",
            AutoSize = true,
            Font = new Font("Segoe UI", 24F, FontStyle.Bold),
            ForeColor = Color.FromArgb(126, 211, 255),
            Location = new Point(0, 0)
        });
        header.Controls.Add(new Label
        {
            Text = "Windows security agent • local dashboard",
            AutoSize = true,
            ForeColor = Color.FromArgb(170, 184, 204),
            Location = new Point(4, 44)
        });
        root.Controls.Add(header, 0, 0);

        var metrics = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 5,
            RowCount = 1,
            BackColor = Color.FromArgb(27, 35, 54),
            Padding = new Padding(14)
        };
        for (var i = 0; i < metrics.ColumnCount; i++)
        {
            metrics.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20));
        }
        metrics.Controls.Add(CreateMetric("สถานะ", out _statusValue), 0, 0);
        metrics.Controls.Add(CreateMetric("Events", out _eventsValue), 1, 0);
        metrics.Controls.Add(CreateMetric("Findings", out _findingsValue), 2, 0);
        metrics.Controls.Add(CreateMetric("Inventory", out _inventoryValue), 3, 0);
        metrics.Controls.Add(CreateMetric("Build", out _buildValue), 4, 0);
        root.Controls.Add(metrics, 0, 1);

        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            BackColor = BackColor
        };
        actions.Controls.Add(CreateButton("รีเฟรช", async (_, _) => await RefreshStatusAsync()));
        actions.Controls.Add(CreateButton("เริ่ม Agent", async (_, _) => await ControlTaskAsync("Run")));
        actions.Controls.Add(CreateButton("หยุด Agent", async (_, _) => await ControlTaskAsync("End")));
        actions.Controls.Add(CreateButton("รีสตาร์ต", async (_, _) => await RestartTaskAsync()));
        actions.Controls.Add(CreateButton("เปิดข้อมูล", (_, _) => OpenDataDirectory()));
        actions.Controls.Add(CreateButton("AI Scan", async (_, _) => await RunAiScanAsync()));
        root.Controls.Add(actions, 0, 2);

        var detailPanel = new Panel { Dock = DockStyle.Fill, BackColor = Color.FromArgb(27, 35, 54), Padding = new Padding(14) };
        detailPanel.Controls.Add(new Label
        {
            Text = "รายละเอียด",
            Dock = DockStyle.Top,
            Height = 26,
            ForeColor = Color.FromArgb(170, 184, 204)
        });
        _details = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            BackColor = Color.FromArgb(27, 35, 54),
            ForeColor = Color.FromArgb(221, 231, 244),
            ScrollBars = ScrollBars.Vertical
        };
        detailPanel.Controls.Add(_details);
        root.Controls.Add(detailPanel, 0, 3);

        _updatedValue = new Label { AutoSize = true, Visible = false };
        _refreshTimer.Tick += async (_, _) => await RefreshStatusAsync();
        Shown += async (_, _) =>
        {
            _refreshTimer.Start();
            await RefreshStatusAsync();
        };
        FormClosed += (_, _) =>
        {
            _refreshTimer.Stop();
            _http.Dispose();
            _refreshGate.Dispose();
        };
    }

    private Panel CreateMetric(string title, out Label value)
    {
        var panel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(4) };
        var titleLabel = new Label
        {
            Text = title,
            AutoSize = true,
            Location = new Point(4, 4),
            ForeColor = Color.FromArgb(170, 184, 204)
        };
        value = new Label
        {
            Text = "—",
            AutoSize = true,
            Location = new Point(4, 32),
            Font = new Font("Segoe UI", 16F, FontStyle.Bold),
            ForeColor = Color.White,
            TextAlign = ContentAlignment.MiddleLeft
        };
        panel.Controls.Add(titleLabel);
        panel.Controls.Add(value);
        return panel;
    }

    private Button CreateButton(string text, EventHandler handler)
    {
        var button = new Button
        {
            Text = text,
            AutoSize = true,
            Height = 34,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(44, 58, 84),
            ForeColor = Color.White,
            Padding = new Padding(12, 0, 12, 0),
            Margin = new Padding(0, 0, 8, 0)
        };
        button.FlatAppearance.BorderColor = Color.FromArgb(70, 91, 126);
        button.Click += handler;
        return button;
    }

    private async Task RefreshStatusAsync()
    {
        if (!await _refreshGate.WaitAsync(0)) return;
        try
        {
            if (!File.Exists(TokenPath))
            {
                SetOffline("ยังไม่พบ API token — ให้ติดตั้งหรือเริ่ม Agent ก่อน");
                return;
            }

            var token = (await File.ReadAllTextAsync(TokenPath)).Trim();
            using var request = new HttpRequestMessage(HttpMethod.Get, StatusUrl);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await _http.SendAsync(request);
            response.EnsureSuccessStatusCode();
            var status = await response.Content.ReadFromJsonAsync<AgentStatus>();
            if (status is null)
            {
                SetOffline("Agent ส่งข้อมูลสถานะว่างกลับมา");
                return;
            }

            var running = string.Equals(status.Status, "running", StringComparison.OrdinalIgnoreCase);
            _statusValue.Text = running ? "Running" : status.Status ?? "Unknown";
            _statusValue.ForeColor = running ? Color.FromArgb(93, 219, 145) : Color.FromArgb(255, 183, 77);
            _eventsValue.Text = status.Events.ToString("N0");
            _findingsValue.Text = status.Findings.ToString("N0");
            _inventoryValue.Text = status.InventoryRuns.ToString("N0");
            _buildValue.Text = status.Build?.Version ?? "dev";
            _updatedValue.Text = DateTime.Now.ToString("HH:mm:ss");
            var details = $"Status: {status.Status}\r\n" +
                          $"Events: {status.Events:N0}   Findings: {status.Findings:N0}   Errors: {status.Errors:N0}\r\n" +
                          $"Inventory runs: {status.InventoryRuns:N0}\r\n" +
                          $"Host: {status.Hostname}\r\n" +
                          $"Agent ID: {status.AgentId}\r\n" +
                          $"Uptime: {status.Uptime}\r\n" +
                          $"Native sources: {status.NativeSources}\r\n" +
                          $"AI: {(status.AIEnabled ? "enabled" : "disabled")}\r\n" +
                          $"Transport: {(status.TransportEnabled ? "enabled" : "local-only")}\r\n" +
                          $"Last refresh: {_updatedValue.Text}";
            _details.Text = _aiResult is null ? details : details + "\r\n\r\n" + _aiResult;
        }
        catch (Exception error)
        {
            SetOffline(error.Message);
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private void SetOffline(string details)
    {
        _statusValue.Text = "Offline";
        _statusValue.ForeColor = Color.FromArgb(255, 105, 105);
        _details.Text = details;
    }

    private async Task ControlTaskAsync(string action)
    {
        try
        {
            await RunSchtasksAsync($"/{action} /TN \"{TaskName}\"");
            _details.Text = $"ส่งคำสั่ง {action} ให้ Agent แล้ว";
            await Task.Delay(1000);
            await RefreshStatusAsync();
        }
        catch (Exception error)
        {
            _details.Text = $"สั่งงานไม่สำเร็จ: {error.Message}";
        }
    }

    private async Task RestartTaskAsync()
    {
        try
        {
            await RunSchtasksAsync($"/End /TN \"{TaskName}\"");
        }
        catch
        {
            // The task may already be stopped; continue with the start command.
        }

        await Task.Delay(1000);
        await ControlTaskAsync("Run");
    }

    private async Task RunAiScanAsync()
    {
        string? temporaryEventPath = null;
        string? thaiReport = null;
        try
        {
            if (!File.Exists(ControlPath))
            {
                throw new FileNotFoundException("ไม่พบ ntagentshieldctl.exe", ControlPath);
            }

            _aiResult = "AI Scan กำลังทำงาน...";
            _details.Text = _aiResult;
            await RefreshStatusAsync();
            var evidence = await Task.Run(FindLatestEvidence);
            if (evidence is null)
            {
                _aiResult = "AI Scan: ยังไม่พบ event ที่มี finding";
                return;
            }

            thaiReport = BuildThaiReport(evidence);
            _aiResult = $"รายงานภาษาไทยจากหลักฐานจริง\r\n{thaiReport}\r\n\r\nกำลังขอความเห็นเพิ่มเติมจาก AI...";

            temporaryEventPath = Path.Combine(Path.GetTempPath(), $"ntagentshield-ai-{Guid.NewGuid():N}.json");
            await File.WriteAllTextAsync(temporaryEventPath, evidence.EventJson, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

            var startInfo = new ProcessStartInfo
            {
                FileName = ControlPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(ControlPath)!
            };
            startInfo.ArgumentList.Add("ai-analyze");
            startInfo.ArgumentList.Add("--config");
            startInfo.ArgumentList.Add(ConfigPath);
            startInfo.ArgumentList.Add("--event");
            startInfo.ArgumentList.Add(temporaryEventPath);
            startInfo.ArgumentList.Add("--objective");
            startInfo.ArgumentList.Add("วิเคราะห์ event และ finding ที่แนบมาเป็นภาษาไทยแบบเข้าใจง่าย ระบุสรุป ระดับความเสี่ยง หลักฐานจริง สิ่งที่อาจเกิดขึ้น ข้อมูลที่ยังขาด และขั้นตอนตรวจสอบต่อไปแบบอ่านอย่างเดียว ห้ามแต่งข้อมูลที่ไม่มีในหลักฐาน");

            var machineKey = Environment.GetEnvironmentVariable("NTAGENTSHIELD_AI_API_KEY", EnvironmentVariableTarget.Machine);
            if (!string.IsNullOrWhiteSpace(machineKey))
            {
                startInfo.Environment["NTAGENTSHIELD_AI_API_KEY"] = machineKey;
            }

            using var process = new Process { StartInfo = startInfo };
            process.Start();
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            var output = await outputTask;
            var error = await errorTask;
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? "AI Scan ล้มเหลว" : error.Trim());
            }

            using var result = JsonDocument.Parse(output);
            var content = result.RootElement.TryGetProperty("content", out var contentElement)
                ? contentElement.GetString()
                : output.Trim();
            var model = result.RootElement.TryGetProperty("model", out var modelElement)
                ? modelElement.GetString()
                : "configured model";
            var providerNote = HasThaiText(content)
                ? $"\r\n\r\nความคิดเห็นจาก AI ({model}):\r\n{content}"
                : $"\r\n\r\nAI เชื่อมต่อสำเร็จ ({model}) แต่ตอบกลับไม่ใช่ภาษาไทย จึงไม่แสดงข้อความดิบเพื่อป้องกันข้อมูลสับสน";
            _aiResult = $"รายงานภาษาไทยจากหลักฐานจริง\r\n{thaiReport}{providerNote}";
        }
        catch (Exception error)
        {
            _aiResult = thaiReport is null
                ? $"AI Scan ไม่สำเร็จ: {error.Message}"
                : $"รายงานภาษาไทยจากหลักฐานจริง\r\n{thaiReport}\r\n\r\nAI ไม่สามารถเชื่อมต่อได้ในรอบนี้: {error.Message}";
        }
        finally
        {
            if (temporaryEventPath is not null)
            {
                try { File.Delete(temporaryEventPath); } catch { }
            }
            await RefreshStatusAsync();
        }
    }

    private static JournalEvidence? FindLatestEvidence()
    {
        if (!File.Exists(JournalPath)) return null;

        string? latestEventId = null;
        JournalEvidence? latestEvent = null;
        JournalEvidence? selectedEvent = null;
        using var stream = new FileStream(JournalPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                if (!root.TryGetProperty("kind", out var kindElement) ||
                    !root.TryGetProperty("payload", out var payload))
                {
                    continue;
                }

                var kind = kindElement.GetString();
                if (kind == "event" && payload.ValueKind == JsonValueKind.Object &&
                    payload.TryGetProperty("id", out var idElement))
                {
                    latestEventId = idElement.GetString();
                    latestEvent = new JournalEvidence
                    {
                        EventJson = payload.GetRawText(),
                        EventId = latestEventId,
                        EventKind = GetString(payload, "kind"),
                        EventSeverity = GetString(payload, "severity"),
                        EventMessage = GetString(payload, "message")
                    };
                }
                else if (kind == "finding" && latestEventId is not null &&
                         payload.TryGetProperty("evidence_event_ids", out var evidenceIds) &&
                         evidenceIds.ValueKind == JsonValueKind.Array &&
                         evidenceIds.EnumerateArray().Any(item => item.GetString() == latestEventId))
                {
                    if (latestEvent is not null)
                    {
                        var findingEvidence = new JournalEvidence
                        {
                            FindingTitle = GetString(payload, "title"),
                            FindingRule = GetString(payload, "rule_id"),
                            FindingSeverity = GetString(payload, "severity"),
                            FindingConfidence = GetNumber(payload, "confidence")
                        };
                        selectedEvent = CloneEvidence(latestEvent, findingEvidence);
                    }
                }
            }
            catch (JsonException)
            {
                // Ignore a partially written journal line and continue scanning.
            }
        }

        return selectedEvent ?? latestEvent;
    }

    private static JournalEvidence CloneEvidence(JournalEvidence source, JournalEvidence finding)
    {
        return new JournalEvidence
        {
            EventJson = source.EventJson,
            EventId = source.EventId,
            EventKind = source.EventKind,
            EventSeverity = source.EventSeverity,
            EventMessage = source.EventMessage,
            FindingTitle = finding.FindingTitle,
            FindingRule = finding.FindingRule,
            FindingSeverity = finding.FindingSeverity,
            FindingConfidence = finding.FindingConfidence
        };
    }

    private static string? GetString(JsonElement value, string property)
    {
        return value.TryGetProperty(property, out var item) && item.ValueKind == JsonValueKind.String
            ? item.GetString()
            : null;
    }

    private static int? GetNumber(JsonElement value, string property)
    {
        return value.TryGetProperty(property, out var item) && item.TryGetInt32(out var number)
            ? number
            : null;
    }

    private static string BuildThaiReport(JournalEvidence evidence)
    {
        var severity = evidence.FindingSeverity ?? evidence.EventSeverity;
        var risk = severity?.ToLowerInvariant() switch
        {
            "critical" => "วิกฤต",
            "high" => "สูง / ควรตรวจสอบทันที",
            "medium" => "ปานกลาง / น่าสงสัย",
            "low" => "ต่ำ",
            _ => "ข้อมูลสำหรับตรวจสอบ"
        };
        var finding = TranslateFinding(evidence.FindingTitle);
        var eventDescription = TranslateEvent(evidence.EventMessage, evidence.EventKind);
        var confidence = evidence.FindingConfidence.HasValue ? $"ความมั่นใจของ rule: {evidence.FindingConfidence}%\r\n" : string.Empty;

        return $"สรุป: พบเหตุการณ์ที่ rule ของ Agent ทำเครื่องหมายไว้ ควรตรวจสอบเพิ่มเติม แต่ยังไม่ใช่การยืนยันว่าเครื่องถูกโจมตี\r\n" +
               $"ระดับความเสี่ยง: {risk}\r\n" +
               $"สิ่งที่พบ: {finding}\r\n" +
               $"เหตุการณ์: {eventDescription}\r\n" +
               $"หลักฐาน: Event ID {evidence.EventId ?? "ไม่พบ"}\r\n" +
               (string.IsNullOrWhiteSpace(evidence.FindingRule) ? string.Empty : $"Rule: {evidence.FindingRule}\r\n") +
               confidence +
               "ข้อมูลที่ยังขาด: process tree, command line เต็ม, ผู้ใช้ที่เกี่ยวข้อง, ไฟล์หรือ hash และ network connection ที่สัมพันธ์กัน\r\n" +
               "ขั้นตอนต่อไป: ตรวจสอบ Windows Event ที่เกี่ยวข้องและ process tree แบบอ่านอย่างเดียว เก็บหลักฐานก่อนแก้ไขระบบ\r\n" +
               "ข้อควรระวัง: การหยุด process, block IP, แยกเครื่อง, ปิดบัญชี หรือลบไฟล์ ต้องได้รับอนุมัติจากมนุษย์ก่อน";
    }

    private static string TranslateEvent(string? message, string? kind)
    {
        if (!string.IsNullOrWhiteSpace(message) && message.StartsWith("Windows event ", StringComparison.OrdinalIgnoreCase))
        {
            return "พบ Windows event: " + message["Windows event ".Length..];
        }
        return string.IsNullOrWhiteSpace(message) ? $"ประเภท {kind ?? "ไม่ระบุ"}" : message;
    }

    private static string TranslateFinding(string? title)
    {
        return title switch
        {
            "Encoded or in-memory PowerShell activity" => "พบการใช้ PowerShell แบบเข้ารหัสหรือทำงานในหน่วยความจำ",
            "New externally reachable listening socket" => "พบพอร์ตใหม่ที่เปิดรับการเชื่อมต่อจากภายนอก",
            "Prompt injection or control-disable text" => "พบข้อความที่พยายามหลอกหรือสั่งให้ระบบป้องกันหยุดทำงาน",
            _ when string.IsNullOrWhiteSpace(title) => "พบพฤติกรรมที่ควรตรวจสอบ",
            _ => title!
        };
    }

    private static bool HasThaiText(string? value)
    {
        return !string.IsNullOrWhiteSpace(value) && value.Any(character => character is >= '\u0E00' and <= '\u0E7F');
    }

    private sealed class JournalEvidence
    {
        public string EventJson { get; set; } = string.Empty;
        public string? EventId { get; set; }
        public string? EventKind { get; set; }
        public string? EventSeverity { get; set; }
        public string? EventMessage { get; set; }
        public string? FindingTitle { get; set; }
        public string? FindingRule { get; set; }
        public string? FindingSeverity { get; set; }
        public int? FindingConfidence { get; set; }
    }

    private static async Task RunSchtasksAsync(string arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };
        process.Start();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new InvalidOperationException(error.Trim());
    }

    private static void OpenDataDirectory()
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"\"{DataDirectory}\"",
            UseShellExecute = true
        });
    }

    private sealed class AgentStatus
    {
        [JsonPropertyName("status")] public string? Status { get; set; }
        [JsonPropertyName("agent_id")] public string? AgentId { get; set; }
        [JsonPropertyName("hostname")] public string? Hostname { get; set; }
        [JsonPropertyName("uptime")] public string? Uptime { get; set; }
        [JsonPropertyName("events")] public long Events { get; set; }
        [JsonPropertyName("findings")] public long Findings { get; set; }
        [JsonPropertyName("errors")] public long Errors { get; set; }
        [JsonPropertyName("native_sources")] public int NativeSources { get; set; }
        [JsonPropertyName("ai_enabled")] public bool AIEnabled { get; set; }
        [JsonPropertyName("inventory_runs")] public long InventoryRuns { get; set; }
        [JsonPropertyName("transport_enabled")] public bool TransportEnabled { get; set; }
        [JsonPropertyName("build")] public BuildInfo? Build { get; set; }
    }

    private sealed class BuildInfo
    {
        [JsonPropertyName("version")] public string? Version { get; set; }
    }
}
