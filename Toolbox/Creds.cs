// Creds: the saved secrets on this machine - Wi-Fi network profiles (SSID, security, and the stored key when
// running elevated) and the Windows Credential Manager vault (generic and domain credentials). Wi-Fi comes
// from netsh wlan (a system binary, no console flash); the vault from CredEnumerate in advapi32.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace PSTools
{
    public class WifiProfile
    {
        public string Ssid = "", Authentication = "", Cipher = "", Key = "", Connection = "", Where = "user"; public bool AutoConnect;
        public bool HasKey { get { return Key.Length > 0; } }
        public string Security { get { return Authentication.Length > 0 ? Authentication + (Cipher.Length > 0 && Cipher != "None" ? " / " + Cipher : "") : ""; } }
        public string Risk
        {
            get
            {
                string a = Authentication.ToLowerInvariant();
                if (a.Contains("open") || a == "none") return "high";
                if (a.Contains("wep")) return "high";
                if (a.Contains("wpa-") || a == "wpapsk" || a.Contains("wpa personal") && !a.Contains("wpa2") && !a.Contains("wpa3")) return "medium";
                return "";
            }
        }
        public string RiskWhy { get { string a = Authentication.ToLowerInvariant(); if (a.Contains("open") || a == "none") return "open network - traffic is unencrypted"; if (a.Contains("wep")) return "WEP is broken - trivially crackable"; if (Risk == "medium") return "legacy WPA - upgrade to WPA2/WPA3"; return ""; } }
    }

    public class VaultCred
    {
        public string Target = "", User = "", Type = "", Persist = "", Preview = ""; public DateTime Written; public bool HasSecret;
        public string When { get { return Written == DateTime.MinValue ? "" : Written.ToString("yyyy-MM-dd HH:mm"); } }
        public string Risk { get { return Type == "domain password" && HasSecret ? "low" : ""; } }
    }

    public static class Creds
    {
        // ── Wi-Fi via netsh ──
        public static List<WifiProfile> Wifi(out string note, bool revealKeys)
        {
            note = ""; List<WifiProfile> list = new List<WifiProfile>();
            string profiles = Netsh("wlan show profiles");
            if (profiles == null) { note = "no wireless interface, or the WLAN service is not running"; return list; }
            List<string> names = new List<string>(); List<string[]> scoped = new List<string[]>();
            foreach (Match m in Regex.Matches(profiles, @"(All User|Current User) Profile\s*:\s*(.+)")) { string scope = m.Groups[1].Value.StartsWith("All") ? "all users" : "current user"; scoped.Add(new string[] { m.Groups[2].Value.Trim(), scope }); }
            if (scoped.Count == 0) { note = "no saved Wi-Fi profiles"; return list; }
            foreach (string[] sc in scoped)
            {
                string name = sc[0]; WifiProfile w = new WifiProfile(); w.Ssid = name; w.Where = sc[1];
                string detail = Netsh("wlan show profile name=\"" + name + "\"" + (revealKeys ? " key=clear" : "")); if (detail == null) { list.Add(w); continue; }
                w.Authentication = First(detail, @"Authentication\s*:\s*(.+)"); w.Cipher = First(detail, @"Cipher\s*:\s*(.+)");
                string conn = First(detail, @"Connection mode\s*:\s*(.+)"); w.AutoConnect = conn.IndexOf("automatic", StringComparison.OrdinalIgnoreCase) >= 0; w.Connection = conn;
                if (revealKeys) w.Key = First(detail, @"Key Content\s*:\s*(.+)");
                list.Add(w);
            }
            list.Sort(delegate (WifiProfile a, WifiProfile b) { return string.Compare(a.Ssid, b.Ssid, StringComparison.OrdinalIgnoreCase); });
            return list;
        }
        static string First(string text, string rx) { Match m = Regex.Match(text ?? "", rx); return m.Success ? m.Groups[1].Value.Trim() : ""; }
        static string Netsh(string args)
        {
            try
            {
                ProcessStartInfo si = new ProcessStartInfo("netsh.exe", args); si.UseShellExecute = false; si.CreateNoWindow = true; si.RedirectStandardOutput = true; si.RedirectStandardError = true; si.StandardOutputEncoding = Encoding.Default;
                using (Process p = Process.Start(si)) { string o = p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd(); p.WaitForExit(15000); return o; }
            }
            catch { return null; }
        }

        // ── Credential Manager vault ──
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CREDENTIAL { public uint Flags; public uint Type; public IntPtr TargetName; public IntPtr Comment; public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten; public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist; public uint AttributeCount; public IntPtr Attributes; public IntPtr TargetAlias; public IntPtr UserName; }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredEnumerate(string filter, uint flag, out uint count, out IntPtr credentials);
        [DllImport("advapi32.dll")] static extern void CredFree(IntPtr buffer);

        public static List<VaultCred> Vault(out string note, bool revealPreview)
        {
            note = ""; List<VaultCred> list = new List<VaultCred>();
            uint count; IntPtr ptr;
            if (!CredEnumerate(null, 0, out count, out ptr)) { int err = Marshal.GetLastWin32Error(); note = err == 1168 ? "no saved credentials in this vault" : "could not read the vault (error " + err + ")"; return list; }
            try
            {
                for (int i = 0; i < count; i++)
                {
                    IntPtr p = Marshal.ReadIntPtr(ptr, i * IntPtr.Size); CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
                    VaultCred v = new VaultCred(); v.Target = c.TargetName != IntPtr.Zero ? Marshal.PtrToStringUni(c.TargetName) : ""; v.User = c.UserName != IntPtr.Zero ? Marshal.PtrToStringUni(c.UserName) : "";
                    v.Type = TypeName(c.Type); v.Persist = c.Persist == 1 ? "session" : c.Persist == 2 ? "this computer" : c.Persist == 3 ? "roaming" : ""; v.HasSecret = c.CredentialBlobSize > 0;
                    try { long ft = ((long)c.LastWritten.dwHighDateTime << 32) | (uint)c.LastWritten.dwLowDateTime; if (ft > 0) v.Written = DateTime.FromFileTime(ft); } catch { }
                    if (v.HasSecret) { v.Preview = revealPreview ? Reveal(c) : Mask((int)c.CredentialBlobSize); }
                    list.Add(v);
                }
            }
            finally { CredFree(ptr); }
            list.Sort(delegate (VaultCred a, VaultCred b) { return string.Compare(a.Target, b.Target, StringComparison.OrdinalIgnoreCase); });
            return list;
        }
        static string TypeName(uint t) { switch (t) { case 1: return "generic"; case 2: return "domain password"; case 3: return "domain certificate"; case 4: return "domain visible password"; case 5: return "generic certificate"; case 6: return "domain extended"; default: return "type " + t; } }
        static string Mask(int bytes) { return "•••••• (" + bytes + " bytes)"; }
        static string Reveal(CREDENTIAL c)
        {
            try
            {
                if (c.CredentialBlobSize == 0 || c.CredentialBlob == IntPtr.Zero) return "";
                byte[] b = new byte[c.CredentialBlobSize]; Marshal.Copy(c.CredentialBlob, b, 0, b.Length);
                // domain-password blobs are unicode; if it decodes cleanly show a masked preview, else note binary
                try { string s = Encoding.Unicode.GetString(b); if (IsPrintable(s)) return MaskValue(s); } catch { }
                return "•••••• (" + b.Length + " bytes, binary)";
            }
            catch { return ""; }
        }
        static bool IsPrintable(string s) { if (s.Length == 0) return false; foreach (char ch in s) if (ch != '\t' && ch != '\r' && ch != '\n' && (ch < 32 || ch == 0xFFFD)) return false; return true; }
        static string MaskValue(string s) { s = s.TrimEnd('\0'); if (s.Length == 0) return ""; if (s.Length <= 4) return new string('•', s.Length); return s.Substring(0, 2) + new string('•', Math.Min(10, s.Length - 3)) + s.Substring(s.Length - 1); }
    }
}
