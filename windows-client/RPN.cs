// RPN.exe — one-file residential VPN client (plain WireGuard, no Tailscale).
//
// On first run (elevated): installs the embedded WireGuard driver, generates a
// keypair locally, registers this device with the hub's provisioning API (gets a
// stable 10.99.0.x), and writes its tunnel config. Connect routes ALL traffic out
// the India Pi exit; Disconnect restores normal networking.
//
// The private key is generated on THIS machine and never leaves it — only the
// public key is sent to the server. A stable per-machine device_id (Windows
// MachineGuid) is also sent so the hub maps this device to the SAME node every
// time — even after a reinstall or a lost config regenerates the keypair.

using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Reflection;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace RpnApp
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            Application.Run(new MainForm());
        }
    }

    public class MainForm : Form
    {
        // ---- configuration (baked in) ----
        const string ProvisionUrl = "https://magicstreamer.duckdns.org:8446/provision";
        const string AccessCode   = "ff0cd793b82fb6c27b562bc4d4fae6d4";
        const string TunnelName   = "rpn";
        const string MsiResource  = "wireguard.msi";

        static readonly string WgDir      = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).Replace(" (x86)", ""), "WireGuard");
        static readonly string WireGuard  = Path.Combine(@"C:\Program Files\WireGuard", "wireguard.exe");
        static readonly string WgCli      = Path.Combine(@"C:\Program Files\WireGuard", "wg.exe");
        static readonly string DataDir    = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RPN");
        static readonly string ConfPath   = Path.Combine(DataDir, TunnelName + ".conf");
        const string ServiceName = "WireGuardTunnel$" + TunnelName;

        // ---- UI ----
        Label _status   = new Label();
        Label _ipLabel  = new Label();
        Button _connect = new Button();
        Button _disconnect = new Button();
        TextBox _log    = new TextBox();

        public MainForm()
        {
            Text = "RPN — India Exit";
            ClientSize = new Size(420, 340);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            BackColor = Color.FromArgb(24, 26, 32);

            var title = new Label {
                Text = "RPN", Font = new Font("Segoe UI", 22, FontStyle.Bold),
                ForeColor = Color.White, AutoSize = true, Location = new Point(20, 14)
            };
            var subtitle = new Label {
                Text = "residential exit · WireGuard", Font = new Font("Segoe UI", 9),
                ForeColor = Color.Gray, AutoSize = true, Location = new Point(24, 56)
            };

            _status.Text = "Starting…";
            _status.Font = new Font("Segoe UI", 13, FontStyle.Bold);
            _status.ForeColor = Color.Gold;
            _status.AutoSize = false;
            _status.TextAlign = ContentAlignment.MiddleCenter;
            _status.Size = new Size(380, 30);
            _status.Location = new Point(20, 92);

            _ipLabel.Text = "";
            _ipLabel.Font = new Font("Segoe UI", 9);
            _ipLabel.ForeColor = Color.Silver;
            _ipLabel.AutoSize = false;
            _ipLabel.TextAlign = ContentAlignment.MiddleCenter;
            _ipLabel.Size = new Size(380, 20);
            _ipLabel.Location = new Point(20, 124);

            _connect.Text = "Connect";
            _connect.Font = new Font("Segoe UI", 12, FontStyle.Bold);
            _connect.Size = new Size(180, 48);
            _connect.Location = new Point(24, 156);
            _connect.FlatStyle = FlatStyle.Flat;
            _connect.BackColor = Color.FromArgb(46, 160, 67);
            _connect.ForeColor = Color.White;
            _connect.Click += async (s, e) => await DoConnect();

            _disconnect.Text = "Disconnect";
            _disconnect.Font = new Font("Segoe UI", 12, FontStyle.Bold);
            _disconnect.Size = new Size(180, 48);
            _disconnect.Location = new Point(216, 156);
            _disconnect.FlatStyle = FlatStyle.Flat;
            _disconnect.BackColor = Color.FromArgb(60, 64, 72);
            _disconnect.ForeColor = Color.White;
            _disconnect.Click += async (s, e) => await DoDisconnect();

            _log.Multiline = true;
            _log.ReadOnly = true;
            _log.ScrollBars = ScrollBars.Vertical;
            _log.BackColor = Color.FromArgb(16, 18, 22);
            _log.ForeColor = Color.Gray;
            _log.Font = new Font("Consolas", 8);
            _log.BorderStyle = BorderStyle.FixedSingle;
            _log.Size = new Size(372, 96);
            _log.Location = new Point(24, 218);

            Controls.AddRange(new Control[] { title, subtitle, _status, _ipLabel, _connect, _disconnect, _log });

            SetButtons(false);
            Load += async (s, e) => await Startup();
        }

        // ---------- helpers ----------
        void Log(string m)
        {
            if (InvokeRequired) { BeginInvoke((Action)(() => Log(m))); return; }
            _log.AppendText(m + Environment.NewLine);
        }
        void SetStatus(string text, Color color)
        {
            if (InvokeRequired) { BeginInvoke((Action)(() => SetStatus(text, color))); return; }
            _status.Text = text; _status.ForeColor = color;
        }
        void SetIp(string text)
        {
            if (InvokeRequired) { BeginInvoke((Action)(() => SetIp(text))); return; }
            _ipLabel.Text = text;
        }
        void SetButtons(bool ready)
        {
            if (InvokeRequired) { BeginInvoke((Action)(() => SetButtons(ready))); return; }
            bool up = IsTunnelUp();
            _connect.Enabled = ready && !up;
            _disconnect.Enabled = ready && up;
        }

        static string Run(string exe, string args, string stdin = null)
        {
            var psi = new ProcessStartInfo(exe, args) {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                RedirectStandardInput = stdin != null
            };
            using (var p = Process.Start(psi))
            {
                if (stdin != null) { p.StandardInput.Write(stdin); p.StandardInput.Close(); }
                string outp = p.StandardOutput.ReadToEnd();
                string err  = p.StandardError.ReadToEnd();
                p.WaitForExit();
                if (p.ExitCode != 0 && err.Length > 0) throw new Exception(exe + ": " + err.Trim());
                return outp.Trim();
            }
        }

        bool IsTunnelUp()
        {
            try { using (var sc = new ServiceController(ServiceName)) return sc.Status == ServiceControllerStatus.Running; }
            catch { return false; }
        }

        // ---------- startup: install + provision ----------
        async Task Startup()
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                await Task.Run(() => EnsureWireGuard());
                await Task.Run(() => EnsureProvisioned());
                SetStatus(IsTunnelUp() ? "Connected" : "Ready", IsTunnelUp() ? Color.LimeGreen : Color.Gold);
                SetButtons(true);
                await RefreshIp();
            }
            catch (Exception ex)
            {
                SetStatus("Setup failed", Color.OrangeRed);
                Log("ERROR: " + ex.Message);
                MessageBox.Show(ex.Message, "RPN setup failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        void EnsureWireGuard()
        {
            if (File.Exists(WireGuard)) { Log("WireGuard already installed."); return; }
            SetStatus("Installing WireGuard…", Color.Gold);
            Log("Extracting bundled WireGuard installer…");
            string msi = Path.Combine(Path.GetTempPath(), "rpn-wireguard.msi");
            var asm = Assembly.GetExecutingAssembly();
            using (var rs = asm.GetManifestResourceStream(MsiResource))
            {
                if (rs == null) throw new Exception("embedded WireGuard MSI not found");
                using (var fs = File.Create(msi)) rs.CopyTo(fs);
            }
            Log("Installing WireGuard driver (silent)…");
            Run("msiexec.exe", "/i \"" + msi + "\" /qn /norestart DO_NOT_LAUNCH=1");
            for (int i = 0; i < 30 && !File.Exists(WireGuard); i++) System.Threading.Thread.Sleep(500);
            if (!File.Exists(WireGuard)) throw new Exception("WireGuard install did not complete");
            try { File.Delete(msi); } catch { }
            Log("WireGuard installed.");
        }

        void EnsureProvisioned()
        {
            if (File.Exists(ConfPath)) { Log("Already registered (config present)."); return; }
            SetStatus("Registering device…", Color.Gold);
            Log("Generating keypair…");
            string priv = Run(WgCli, "genkey");
            string pub  = Run(WgCli, "pubkey", priv + "\n");
            Log("Public key: " + pub.Substring(0, 12) + "…");

            Log("Registering with hub…");
            string body = "{\"code\":\"" + AccessCode + "\",\"pubkey\":\"" + pub +
                          "\",\"name\":\"" + JsonEscape(Environment.MachineName) +
                          "\",\"device_id\":\"" + JsonEscape(DeviceId()) + "\"}";
            string resp = HttpPostJson(ProvisionUrl, body);

            string ip       = Match(resp, "assigned_ip");
            string hubPub    = Match(resp, "hub_pubkey");
            string endpoint  = Match(resp, "endpoint");
            string dns       = Match(resp, "dns");
            string keepalive = Match(resp, "keepalive");
            if (ip == null || hubPub == null || endpoint == null)
                throw new Exception("provisioning failed: " + resp);
            Log("Assigned " + ip);

            var conf = new StringBuilder();
            conf.AppendLine("[Interface]");
            conf.AppendLine("PrivateKey = " + priv);
            conf.AppendLine("Address = " + ip);
            conf.AppendLine("DNS = " + (dns ?? "1.1.1.1"));
            conf.AppendLine();
            conf.AppendLine("[Peer]");
            conf.AppendLine("PublicKey = " + hubPub);
            conf.AppendLine("AllowedIPs = 0.0.0.0/0, ::/0");
            conf.AppendLine("Endpoint = " + endpoint);
            conf.AppendLine("PersistentKeepalive = " + (keepalive ?? "25"));
            File.WriteAllText(ConfPath, conf.ToString());
            Log("Config written.");
        }

        // ---------- connect / disconnect ----------
        async Task DoConnect()
        {
            SetButtons(false);
            SetStatus("Connecting…", Color.Gold);
            try
            {
                if (!File.Exists(ConfPath)) { await Task.Run(() => EnsureProvisioned()); }
                await Task.Run(() => Run(WireGuard, "/installtunnelservice \"" + ConfPath + "\""));
                for (int i = 0; i < 20 && !IsTunnelUp(); i++) await Task.Delay(400);
                SetStatus(IsTunnelUp() ? "Connected" : "Connect failed", IsTunnelUp() ? Color.LimeGreen : Color.OrangeRed);
                Log(IsTunnelUp() ? "Tunnel up." : "Tunnel did not start.");
            }
            catch (Exception ex) { SetStatus("Connect failed", Color.OrangeRed); Log("ERROR: " + ex.Message); }
            SetButtons(true);
            await RefreshIp();
        }

        async Task DoDisconnect()
        {
            SetButtons(false);
            SetStatus("Disconnecting…", Color.Gold);
            try
            {
                await Task.Run(() => Run(WireGuard, "/uninstalltunnelservice " + TunnelName));
                for (int i = 0; i < 20 && IsTunnelUp(); i++) await Task.Delay(400);
                SetStatus("Disconnected", Color.Gold);
                Log("Tunnel down.");
            }
            catch (Exception ex) { SetStatus("Disconnect failed", Color.OrangeRed); Log("ERROR: " + ex.Message); }
            SetButtons(true);
            await RefreshIp();
        }

        async Task RefreshIp()
        {
            SetIp("checking IP…");
            string ip = await Task.Run(() => {
                try {
                    using (var wc = new WebClient()) return wc.DownloadString("https://api.ipify.org").Trim();
                } catch { return "(offline)"; }
            });
            SetIp("Public IP: " + ip + (ip == "122.164.83.7" ? "  ✓ India" : ""));
        }

        // ---------- tiny helpers ----------
        // Stable per-Windows-install identity. Survives app reinstall / lost config,
        // so the hub always maps this physical machine back to the SAME node instead
        // of allocating a new 10.99.0.x every time the keypair is regenerated.
        static string DeviceId()
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var k = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography"))
                {
                    var g = k?.GetValue("MachineGuid") as string;
                    if (!string.IsNullOrEmpty(g)) return g.Trim();
                }
            }
            catch { }
            // Fallback: a GUID persisted in ProgramData (still stable across reinstalls
            // as long as ProgramData\RPN survives).
            try
            {
                string idFile = Path.Combine(DataDir, "device-id");
                if (File.Exists(idFile))
                {
                    string s = File.ReadAllText(idFile).Trim();
                    if (s.Length > 0) return s;
                }
                Directory.CreateDirectory(DataDir);
                string g2 = Guid.NewGuid().ToString();
                File.WriteAllText(idFile, g2);
                return g2;
            }
            catch { return Environment.MachineName; }
        }

        static string JsonEscape(string s) { return s.Replace("\\", "\\\\").Replace("\"", "\\\""); }
        static string Match(string json, string key)
        {
            var m = Regex.Match(json, "\"" + key + "\"\\s*:\\s*\"?([^\",}]+)\"?");
            return m.Success ? m.Groups[1].Value.Trim() : null;
        }
        static string HttpPostJson(string url, string body)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "POST"; req.ContentType = "application/json"; req.Timeout = 20000;
            var bytes = Encoding.UTF8.GetBytes(body);
            req.ContentLength = bytes.Length;
            using (var s = req.GetRequestStream()) s.Write(bytes, 0, bytes.Length);
            try
            {
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var sr = new StreamReader(resp.GetResponseStream()))
                    return sr.ReadToEnd();
            }
            catch (WebException we)
            {
                if (we.Response != null)
                    using (var sr = new StreamReader(we.Response.GetResponseStream()))
                        throw new Exception("server: " + sr.ReadToEnd());
                throw;
            }
        }
    }
}
