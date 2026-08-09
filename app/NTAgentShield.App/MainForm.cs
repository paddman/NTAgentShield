using System.Diagnostics;
using System.Drawing;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace NTAgentShield.App;

public sealed class MainForm : Form
{
    private const string TaskName = "NTAgentShield";
    private const string DataDirectory = @"C:\ProgramData\NTAgentShield";
    private const string TokenPath = DataDirectory + @"\agent-api.token";
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
        panel.Controls.Add(new Label
        {
            Text = title,
            Dock = DockStyle.Top,
            Height = 28,
            ForeColor = Color.FromArgb(170, 184, 204)
        });
        value = new Label
        {
            Text = "—",
            Dock = DockStyle.Fill,
            AutoEllipsis = true,
            Font = new Font("Segoe UI", 16F, FontStyle.Bold),
            ForeColor = Color.White
        };
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
            _details.Text = $"Host: {status.Hostname}\r\n" +
                            $"Agent ID: {status.AgentId}\r\n" +
                            $"Uptime: {status.Uptime}\r\n" +
                            $"Native sources: {status.NativeSources}\r\n" +
                            $"Transport: {(status.TransportEnabled ? "enabled" : "local-only")}\r\n" +
                            $"Last refresh: {_updatedValue.Text}";
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
        [JsonPropertyName("native_sources")] public int NativeSources { get; set; }
        [JsonPropertyName("inventory_runs")] public long InventoryRuns { get; set; }
        [JsonPropertyName("transport_enabled")] public bool TransportEnabled { get; set; }
        [JsonPropertyName("build")] public BuildInfo? Build { get; set; }
    }

    private sealed class BuildInfo
    {
        [JsonPropertyName("version")] public string? Version { get; set; }
    }
}
