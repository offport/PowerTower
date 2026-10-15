// RemoteAuditSupport.cs - the append-only journal, the credential store, the target-list parser and the
// scriptable FakeTransport the tests drive. Compiled into PowerTowerCli.exe and Tests.exe only (with
// RemoteAudit.cs), never PowerTowerCollect.exe and never the SHARED set. No CLI or GUI type is used here.
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PSTools
{
    // ───────────────────────────── the append-only run journal ─────────────────────────────
    /// <summary>One NDJSON line per target result, opened append-only so a crash cannot truncate earlier runs.
    /// A line never contains a secret - only the redacted user (domain\user). The reader tolerates malformed and
    /// over-long lines (it skips them) so a corrupt journal cannot crash or hang the tool.</summary>
    public class RunJournal
    {
        public readonly string Path; const int MaxLine = 64 * 1024;
        public RunJournal(string path) { Path = path; }
        public void Append(RunResult r)
        {
            try
            {
                Dictionary<string, object> d = new Dictionary<string, object>();
                d["utc"] = JsonWrite.Stamp(r.WhenUtc); d["runId"] = r.RunId; d["host"] = r.Host; d["user"] = r.User;   // user is domain\user, never a secret
                d["transport"] = r.Transport; d["status"] = r.Status; d["bytes"] = r.Bytes; d["sha256"] = r.Sha;
                d["verified"] = r.Verified; d["partial"] = r.Partial; d["leftClean"] = r.LeftClean; d["seconds"] = Math.Round(r.Seconds, 1); d["detail"] = RemoteAudit.Scrub(r.Detail);
                string line = JsonWrite.Text(d, false); if (line.Length > MaxLine) line = line.Substring(0, MaxLine);
                string dir = System.IO.Path.GetDirectoryName(Path); if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                using (FileStream fs = new FileStream(Path, FileMode.Append, FileAccess.Write, FileShare.Read))
                using (StreamWriter w = new StreamWriter(fs, new UTF8Encoding(false))) { w.WriteLine(line); }
            }
            catch { /* journaling must never take the run down */ }
        }
        /// <summary>Every well-formed entry; malformed or over-long lines are skipped, not thrown on.</summary>
        public List<Dictionary<string, object>> Read()
        {
            List<Dictionary<string, object>> list = new List<Dictionary<string, object>>();
            if (!File.Exists(Path)) return list;
            try { foreach (string raw in File.ReadAllLines(Path)) { string line = raw; if (line.Length == 0 || line.Length > MaxLine) continue; try { Dictionary<string, object> d = Json.Obj(Json.Parse(line)); if (d != null) list.Add(d); } catch { } } }
            catch { }
            return list;
        }
    }

    // ───────────────────────────── the credential store ─────────────────────────────
    public sealed class CredEntry : IDisposable
    {
        public string Label = "", User = ""; public byte[] Secret = new byte[0];
        public void Zero() { if (Secret != null) Array.Clear(Secret, 0, Secret.Length); }
        public void Dispose() { Zero(); }
    }

    /// <summary>creds.ptv per engagement. DPAPI (default): ProtectedData, CurrentUser scope, engagement id as
    /// entropy - useless if copied to another user or machine. Passphrase file: PBKDF2-SHA256 (200k) + AES-256-CBC +
    /// HMAC-SHA256 (encrypt-then-MAC), the same construction the bundle uses, for a portable jump box (passphrase
    /// from a prompt or env var, never argv). Secrets are bytes, zeroed after use; the plaintext never touches disk,
    /// a log, the journal, a bundle or settings.ini.</summary>
    public static class CredStore
    {
        const byte V = 1; static readonly byte[] MagicDpapi = Encoding.ASCII.GetBytes("PTVD"), MagicPass = Encoding.ASCII.GetBytes("PTVP");

        public static void SaveDpapi(string path, List<CredEntry> entries, string engagementId)
        { byte[] plain = Serialize(entries); try { WriteWith(path, MagicDpapi, BundleCrypto.Protect(plain, "creds:" + engagementId)); } finally { Array.Clear(plain, 0, plain.Length); } }
        public static void SavePass(string path, List<CredEntry> entries, byte[] passphrase)
        { byte[] plain = Serialize(entries); try { WriteWith(path, MagicPass, Encrypt(plain, passphrase)); } finally { Array.Clear(plain, 0, plain.Length); } }
        public static List<CredEntry> Load(string path, byte[] passphrase, string engagementId)
        {
            byte[] all = File.ReadAllBytes(path);
            if (all.Length < 5) throw new BundleException("creds.ptv is too short to be valid");
            byte[] magic = new byte[4]; Array.Copy(all, magic, 4); byte[] body = new byte[all.Length - 5]; Array.Copy(all, 5, body, 0, body.Length);
            byte[] plain;
            if (Same(magic, MagicDpapi)) plain = BundleCrypto.Unprotect(body, "creds:" + engagementId);
            else if (Same(magic, MagicPass)) { if (passphrase == null) throw new BundleException("this creds.ptv is passphrase-protected - supply the passphrase (prompt or env var, never on the command line)"); plain = Decrypt(body, passphrase); }
            else throw new BundleException("not a PowerTower credential file");
            try { return Deserialize(plain); } finally { Array.Clear(plain, 0, plain.Length); }
        }

        static void WriteWith(string path, byte[] magic, byte[] body)
        {
            string dir = System.IO.Path.GetDirectoryName(path); if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            try { if (File.Exists(path)) File.SetAttributes(path, FileAttributes.Normal); } catch { }   // a re-save must be able to overwrite the previous (hidden) file
            string tmp = path + ".tmp-" + Guid.NewGuid().ToString("N").Substring(0, 8);   // PT-71: write to a temp file, then replace, so the old store is never truncated in place
            using (FileStream fs = File.Create(tmp)) { fs.Write(magic, 0, 4); fs.WriteByte(V); fs.Write(body, 0, body.Length); fs.Flush(); }
            try { if (File.Exists(path)) File.Replace(tmp, path, null); else File.Move(tmp, path); } catch { try { if (File.Exists(path)) File.Delete(path); File.Move(tmp, path); } finally { try { if (File.Exists(tmp)) File.Delete(tmp); } catch { } } }
            try { File.SetAttributes(path, File.GetAttributes(path) | FileAttributes.Hidden); } catch { }
        }
        static byte[] Serialize(List<CredEntry> entries)
        { using (MemoryStream ms = new MemoryStream()) { WriteInt(ms, entries.Count); foreach (CredEntry e in entries) { WriteStr(ms, e.Label); WriteStr(ms, e.User); WriteBytes(ms, e.Secret); } return ms.ToArray(); } }
        static List<CredEntry> Deserialize(byte[] b)
        {
            List<CredEntry> l = new List<CredEntry>(); int i = 0; int n = ReadInt(b, ref i);
            if (n < 0 || n > 100000) throw new BundleException("credential file is corrupt");
            for (int k = 0; k < n; k++) { CredEntry e = new CredEntry(); e.Label = ReadStr(b, ref i); e.User = ReadStr(b, ref i); e.Secret = ReadBytes(b, ref i); l.Add(e); }
            return l;
        }
        static void WriteInt(Stream s, int v) { for (int i = 0; i < 4; i++) s.WriteByte((byte)(v >> (i * 8))); }
        static void WriteStr(Stream s, string v) { WriteBytes(s, Encoding.UTF8.GetBytes(v ?? "")); }
        static void WriteBytes(Stream s, byte[] v) { v = v ?? new byte[0]; WriteInt(s, v.Length); s.Write(v, 0, v.Length); }
        static int ReadInt(byte[] b, ref int i) { if (i + 4 > b.Length) throw new BundleException("credential file is truncated"); int v = b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24); i += 4; return v; }
        static string ReadStr(byte[] b, ref int i) { return Encoding.UTF8.GetString(ReadBytes(b, ref i)); }
        static byte[] ReadBytes(byte[] b, ref int i) { int n = ReadInt(b, ref i); if (n < 0 || i + n > b.Length) throw new BundleException("credential file is truncated"); byte[] v = new byte[n]; Array.Copy(b, i, v, 0, n); i += n; return v; }
        static bool Same(byte[] a, byte[] b) { if (a.Length != b.Length) return false; for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false; return true; }

        const int Iter = 200000;
        static byte[] Encrypt(byte[] plain, byte[] pass)
        {
            byte[] salt = Rand(16), iv = Rand(16); byte[] aesKey, macKey; Keys(pass, salt, out aesKey, out macKey);
            try
            {
                using (Aes aes = new AesManaged())
                {
                    aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = aesKey; aes.IV = iv;
                    using (ICryptoTransform enc = aes.CreateEncryptor())
                    {
                        byte[] cipher = enc.TransformFinalBlock(plain, 0, plain.Length);
                        using (MemoryStream ms = new MemoryStream())
                        {
                            ms.Write(salt, 0, 16); ms.Write(iv, 0, 16); ms.Write(cipher, 0, cipher.Length);
                            byte[] bodyb = ms.ToArray(); byte[] mac; using (HMACSHA256 h = new HMACSHA256(macKey)) mac = h.ComputeHash(bodyb);
                            byte[] outb = new byte[bodyb.Length + 32]; Array.Copy(bodyb, outb, bodyb.Length); Array.Copy(mac, 0, outb, bodyb.Length, 32); return outb;
                        }
                    }
                }
            }
            finally { Array.Clear(aesKey, 0, aesKey.Length); Array.Clear(macKey, 0, macKey.Length); }
        }
        static byte[] Decrypt(byte[] blob, byte[] pass)
        {
            if (blob.Length < 16 + 16 + 32) throw new BundleException("credential file is corrupt");
            byte[] salt = new byte[16]; Array.Copy(blob, 0, salt, 0, 16); byte[] aesKey, macKey; Keys(pass, salt, out aesKey, out macKey);
            try
            {
                byte[] bodyb = new byte[blob.Length - 32]; Array.Copy(blob, bodyb, bodyb.Length); byte[] mac = new byte[32]; Array.Copy(blob, blob.Length - 32, mac, 0, 32);
                byte[] calc; using (HMACSHA256 h = new HMACSHA256(macKey)) calc = h.ComputeHash(bodyb);
                if (!Same(mac, calc)) throw new BundleException("wrong passphrase or the credential file was tampered with");
                byte[] iv = new byte[16]; Array.Copy(bodyb, 16, iv, 0, 16);
                using (Aes aes = new AesManaged())
                {
                    aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.Key = aesKey; aes.IV = iv;
                    using (ICryptoTransform dec = aes.CreateDecryptor()) return dec.TransformFinalBlock(bodyb, 32, bodyb.Length - 32);
                }
            }
            finally { Array.Clear(aesKey, 0, aesKey.Length); Array.Clear(macKey, 0, macKey.Length); }
        }
        static void Keys(byte[] pass, byte[] salt, out byte[] aesKey, out byte[] macKey)
        {
            using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(pass, salt, Iter))
            {
                byte[] master = kdf.GetBytes(32);
                using (HMACSHA256 h = new HMACSHA256(master)) { aesKey = h.ComputeHash(Encoding.ASCII.GetBytes("ptv/1 aes")); macKey = h.ComputeHash(Encoding.ASCII.GetBytes("ptv/1 mac")); }
                Array.Clear(master, 0, master.Length);
            }
        }
        static byte[] Rand(int n) { byte[] b = new byte[n]; using (RNGCryptoServiceProvider r = new RNGCryptoServiceProvider()) r.GetBytes(b); return b; }
    }

    // ───────────────────────────── the target list ─────────────────────────────
    /// <summary>A target from a CSV line or a --target value. Hostnames are validated hard: no UNC prefix, no path
    /// separators or traversal, no injection or control characters, length-capped - a hostile host string is skipped
    /// with a reason, never passed to a transport or a command line.</summary>
    public static class TargetList
    {
        public static TargetSpec Parse(string line, out string error)
        {
            error = null; if (line == null) { error = "empty"; return null; }
            string s = line.Trim(); if (s.Length == 0 || s.StartsWith("#")) { error = "blank"; return null; }
            string[] f = s.Split(','); TargetSpec t = new TargetSpec(); t.SourceLine = s;
            t.Host = f[0].Trim();
            if (!ValidHost(t.Host, out error)) return null;
            if (f.Length > 1) { t.CredLabel = f[1].Trim(); foreach (char c in t.CredLabel) if (!(char.IsLetterOrDigit(c) || c == '.' || c == '_' || c == '-')) { error = "the credential label has an illegal character '" + c + "'"; return null; } }
            if (f.Length > 2) { int to; if (int.TryParse(f[2].Trim(), out to) && to > 0 && to <= 86400) t.TimeoutSec = to; else if (f[2].Trim().Length > 0) { error = "the timeout must be a whole number of seconds (1-86400)"; return null; } }
            if (f.Length > 3) { List<string> canon; if (!ValidModules(f[3].Split(';', ' '), out canon, out error)) return null; t.Modules = canon; }   // PT-67: modules are allow-listed; a line with any other value is refused whole
            return t;
        }
        /// <summary>PT-67: a module must be an exact (case-insensitive) name from Collector.AllModules and nothing else -
        /// no metacharacter, quote, space trick or unknown word survives. Returns the lower-case canonical set; on any
        /// other value it fails and names it, so the caller rejects the whole target line.</summary>
        public static bool ValidModules(System.Collections.Generic.IEnumerable<string> mods, out List<string> canonical, out string why)
        {
            canonical = new List<string>(); why = null;
            foreach (string m in mods)
            {
                string raw = (m ?? "").Trim(); if (raw.Length == 0) continue;
                string lo = raw.ToLowerInvariant(); bool charsOk = lo.Length > 0; foreach (char c in lo) if (c < 'a' || c > 'z') charsOk = false;
                bool known = false; if (charsOk) foreach (string k in Collector.AllModules) if (lo == k) { known = true; break; }
                if (!known) { why = "'" + raw + "' is not a known module - allowed: " + string.Join(", ", Collector.AllModules); return false; }
                if (!canonical.Contains(lo)) canonical.Add(lo);
            }
            return true;
        }
        static readonly string Banned = "\\/*?\"<>|%$@ \t&;!`'(){}[]^";   // ':' is NOT here: it is legal in an IPv6 literal (validated below) and rejected in a hostname label by the letter/digit check
        /// <summary>Accept a hostname, FQDN or IPv4/IPv6 literal; reject everything a transport or shell could misread.</summary>
        public static bool ValidHost(string h, out string why)
        {
            why = null;
            if (string.IsNullOrEmpty(h)) { why = "empty host"; return false; }
            if (h.Length > 255) { why = "host name is too long"; return false; }
            if (h.StartsWith("\\\\") || h.StartsWith("//")) { why = "a UNC path is not a host name"; return false; }
            if (h.IndexOf("..") >= 0) { why = "'..' is not allowed in a host name"; return false; }
            foreach (char c in h) { if (c < 32) { why = "control character in the host name"; return false; } if (Banned.IndexOf(c) >= 0) { why = "'" + c + "' is not allowed in a host name"; return false; } }
            if (h.IndexOf(':') >= 0) { System.Net.IPAddress ip; if (!System.Net.IPAddress.TryParse(h, out ip)) { why = "not a valid IPv6 address"; return false; } return true; }
            foreach (string label in h.Split('.')) { if (label.Length == 0) { why = "empty label in the host name"; return false; } if (label.Length > 63) { why = "a label in the host name is too long"; return false; } foreach (char c in label) if (!(char.IsLetterOrDigit(c) || c == '-' || c == '_')) { why = "'" + c + "' is not allowed in a host name"; return false; } }
            return true;
        }
    }

    // ───────────────────────────── a fully scriptable fake transport (tests only) ─────────────────────────────
    /// <summary>Every failure in scope-plan 2.5 is a knob here, so the controller flow is tested end to end without a
    /// real target. It records that Connect was reached at most once (LogonAttempts) and whether the secret was ever
    /// read (LastSecretSeen), so tests prove no credential is used before the gate and preflight pass.</summary>
    public class FakeTransport : ITransport
    {
        public bool Smb445 = true, Rpc135 = true, WinRm5985 = false; public bool PreflightThrows;
        public string ConnectThrowCode;                 // LOGON_FAILURE / TOKEN_FILTER / ADMIN_SHARE / PORT_DOWN / null
        public bool ExeVanishes, Hangs, Reboot, BadHash, PartialModule, DeleteFails, StageThrows, NoBundle, BadDoneJson, ConnectThrowMessageWithSecret;
        public int ExitCode; public byte[] Bundle = Encoding.UTF8.GetBytes("PTB0fake-bundle-bytes");
        public int ConnectCalls, LogonAttempts, ExecCalls, WaitCalls, DeleteCalls, FetchCalls, CopyCalls;
        public string LastSecretSeen;
        public List<StagedDir> Stale = new List<StagedDir>();
        readonly Dictionary<string, byte[]> remote = new Dictionary<string, byte[]>(); bool connected, dirDeleted;

        public Preflight Preflight() { if (PreflightThrows) throw new Exception("host unreachable"); Preflight p = new Preflight(); p.Smb445 = Smb445; p.Rpc135 = Rpc135; p.WinRm5985 = WinRm5985; return p; }
        public void Connect(string host, NetworkCred cred, string stageDirName)
        {
            ConnectCalls++; LogonAttempts++;
            if (cred != null) LastSecretSeen = cred.SecretUtf8();   // a real transport reads the secret here, at connect time
            if (ConnectThrowMessageWithSecret) throw new TransportException(PtStage.Connect, "CONNECT", "logon failed for " + host + " as " + cred.User + " with password " + cred.SecretUtf8());
            if (ConnectThrowCode == "LOGON_FAILURE") throw new TransportException(PtStage.Connect, "LOGON_FAILURE", "logon failed");
            if (ConnectThrowCode == "TOKEN_FILTER") throw new TransportException(PtStage.Connect, "TOKEN_FILTER", "ADMIN$ denied after logon");
            if (ConnectThrowCode == "ADMIN_SHARE") throw new TransportException(PtStage.Connect, "ADMIN_SHARE", "ADMIN$ missing");
            if (ConnectThrowCode == "PORT_DOWN") throw new TransportException(PtStage.Connect, "PORT_DOWN", "port closed");
            connected = true; dirDeleted = false;
        }
        public void Copy(byte[] data, string remoteName) { CopyCalls++; if (StageThrows) throw new TransportException(PtStage.Stage, "ADMIN_SHARE", "disk full"); remote[remoteName] = data; }
        public int Exec(string remoteExeName, string args)
        {
            ExecCalls++;
            if (ExeVanishes) { remote.Remove(remoteExeName); throw new TransportException(PtStage.Exec, "EXE_GONE", "the staged exe is gone"); }
            if (!Hangs)
            {
                if (!NoBundle) remote["bundle.ptb"] = Bundle;
                if (BadDoneJson) { remote["done.json"] = Encoding.UTF8.GetBytes("{ this is : not json "); return 4321; }
                string sha = BadHash ? new string('0', 64) : RemoteAudit.Sha256Hex(Bundle);
                Dictionary<string, object> done = new Dictionary<string, object>(); done["bundle"] = "bundle.ptb"; done["bytes"] = Bundle.Length; done["sha256"] = sha;
                List<object> mods = new List<object>(); Dictionary<string, object> m = new Dictionary<string, object>(); m["name"] = "inventory"; m["status"] = PartialModule ? "partial" : "ok"; mods.Add(m); done["modules"] = mods;
                remote["done.json"] = Encoding.UTF8.GetBytes(JsonWrite.Text(done, false));
            }
            else { remote["bundle.ptb"] = Bundle; }   // a hang leaves a partial bundle but no done.json
            return 4321;
        }
        public ExecResult Wait(int handle, int timeoutMs) { WaitCalls++; ExecResult r = new ExecResult(); if (Reboot) { r.SessionLost = true; return r; } if (Hangs) { r.TimedOut = true; return r; } r.Exited = true; r.ExitCode = ExitCode; return r; }
        public byte[] Fetch(string remoteName) { FetchCalls++; byte[] v; return remote.TryGetValue(remoteName, out v) ? v : null; }
        public void Delete() { DeleteCalls++; if (DeleteFails) throw new TransportException(PtStage.Clean, "DENIED", "cannot delete"); remote.Clear(); dirDeleted = true; }
        public bool Exists() { return connected && !dirDeleted; }
        public List<StagedDir> Sweep(string prefix, int maxAgeMs) { return Stale; }
        public void Close() { connected = false; }
    }
}
