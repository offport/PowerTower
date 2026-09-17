// Secrets: walk a folder or drive for exposed secrets - private keys, cloud API keys, tokens, passwords in
// .env / config files, connection strings. Regex-based, so it errs toward showing candidates; each hit is
// shown with the file, line, kind and a masked preview (never the whole secret in the grid).
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace PSTools
{
    public class SecretHit
    {
        public string Path = "", File = "", Kind = "", Preview = "", Match = ""; public int Line; public string Severity = "medium"; public double Entropy;
        public string Where { get { return Trust.Location(Path); } }
    }

    public class SecretRule
    {
        public string Kind, Severity; public Regex Rx; public bool NeedsEntropy;
        public SecretRule(string kind, string sev, string pattern, bool entropy) { Kind = kind; Severity = sev; Rx = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant); NeedsEntropy = entropy; }
    }

    public class SecretsScan
    {
        public IList<string> Roots = new List<string>(); public volatile bool Cancel;
        public long FilesScanned, FilesSkipped, BytesRead; public string Current = "";
        public int MaxFileKB = 1024; public bool SkipBinaries = true;
        readonly FastWalk walk = new FastWalk();

        // file extensions worth reading; plus a set of exact filenames that are always interesting
        static readonly HashSet<string> Exts = new HashSet<string>(new string[] { ".env", ".txt", ".config", ".json", ".xml", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".properties", ".ps1", ".psm1", ".bat", ".cmd", ".sh", ".bash", ".py", ".js", ".ts", ".rb", ".php", ".java", ".cs", ".go", ".sql", ".pem", ".key", ".ppk", ".pfx", ".p12", ".pub", ".tf", ".tfvars", ".md", ".log", ".htpasswd", ".npmrc", ".netrc", ".gitconfig", ".dockercfg" }, StringComparer.OrdinalIgnoreCase);
        static readonly HashSet<string> Names = new HashSet<string>(new string[] { ".env", ".env.local", ".env.production", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".netrc", "credentials", "web.config", "app.config", "appsettings.json", "unattend.xml", "sysprep.xml", ".git-credentials", "wp-config.php", ".htpasswd", "known_hosts", ".pgpass", "secrets.yml", "docker-compose.yml" }, StringComparer.OrdinalIgnoreCase);

        public static readonly List<SecretRule> Rules = new List<SecretRule>(new SecretRule[] {
            new SecretRule("Private key (PEM)", "high", @"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", false),
            new SecretRule("AWS access key", "high", @"\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b", false),
            new SecretRule("AWS secret key", "high", @"(?i)aws.{0,20}(secret|private).{0,20}[:=]\s*['""]?[A-Za-z0-9/+=]{40}['""]?", false),
            new SecretRule("Google API key", "high", @"\bAIza[0-9A-Za-z\-_]{35}\b", false),
            new SecretRule("Google OAuth token", "high", @"\bya29\.[0-9A-Za-z\-_]+", false),
            new SecretRule("GitHub token", "high", @"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b", false),
            new SecretRule("Slack token", "high", @"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", false),
            new SecretRule("Stripe key", "high", @"\b(sk|rk)_(live|test)_[0-9A-Za-z]{20,}\b", false),
            new SecretRule("Twilio key", "high", @"\bSK[0-9a-fA-F]{32}\b", false),
            new SecretRule("SendGrid key", "high", @"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b", false),
            new SecretRule("Slack webhook", "medium", @"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", false),
            new SecretRule("JWT", "medium", @"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", false),
            new SecretRule("Private key (PuTTY)", "high", @"PuTTY-User-Key-File-\d", false),
            new SecretRule("Connection string password", "high", @"(?i)(password|pwd)\s*=\s*[^;\s""']{4,}", false),
            new SecretRule("Bearer token", "medium", @"(?i)authorization\s*[:=]\s*['""]?bearer\s+[A-Za-z0-9\-._~+/]{16,}", false),
            new SecretRule("Generic API key", "medium", @"(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret)\s*[:=]\s*['""]?[A-Za-z0-9\-_./+]{16,}['""]?", true),
            new SecretRule("Generic password", "low", @"(?i)\b(password|passwd|passphrase)\s*[:=]\s*['""]?[^\s""']{6,}['""]?", false),
        });

        public void Run(Action<SecretHit> onHit, Action progress)
        {
            walk.Roots = Roots;
            walk.Run(delegate (FileInfo fi)
            {
                if (Cancel) { walk.Stop(); return; }
                Current = fi.FullName;
                bool interesting = Names.Contains(fi.Name) || Exts.Contains(fi.Extension) || fi.Name.StartsWith(".env", StringComparison.OrdinalIgnoreCase);
                if (!interesting) { FilesSkipped++; return; }
                if (fi.Length > (long)MaxFileKB * 1024) { FilesSkipped++; return; }
                if (fi.Length == 0) { FilesScanned++; return; }
                try
                {
                    byte[] bytes = File.ReadAllBytes(fi.FullName); BytesRead += bytes.Length; FilesScanned++;
                    if (SkipBinaries && LooksBinary(bytes)) return;
                    string text = Decode(bytes);
                    ScanText(fi.FullName, fi.Name, text, onHit);
                }
                catch { }
                if (progress != null) progress();
            });
        }
        public void Stop() { Cancel = true; walk.Stop(); }
        public long DirsScanned { get { return walk.DirsScanned; } }
        public long Denied { get { return walk.Denied; } }

        public void ScanText(string path, string name, string text, Action<SecretHit> onHit)
        {
            string[] lines = text.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i]; if (line.Length < 8 || line.Length > 4000) continue;
                string trimmed = line.TrimStart();
                if (trimmed.StartsWith("//") || trimmed.StartsWith("#") && name.EndsWith(".md", StringComparison.OrdinalIgnoreCase)) { }
                foreach (SecretRule rule in Rules)
                {
                    Match m = rule.Rx.Match(line); if (!m.Success) continue;
                    string val = m.Value; double ent = Entropy(LongestToken(val));
                    if (rule.NeedsEntropy && ent < 3.2) continue;
                    if (IsPlaceholder(val)) continue;
                    SecretHit h = new SecretHit(); h.Path = path; h.File = name; h.Kind = rule.Kind; h.Severity = rule.Severity; h.Line = i + 1; h.Match = val.Length > 200 ? val.Substring(0, 200) : val; h.Preview = Mask(m.Value.Trim()); h.Entropy = Math.Round(ent, 1);
                    onHit(h); break; // one hit per line is enough
                }
            }
        }

        static string LongestToken(string s) { string best = ""; foreach (string t in Regex.Split(s, @"[^A-Za-z0-9+/=_\-\.]")) if (t.Length > best.Length) best = t; return best; }
        static bool IsPlaceholder(string s)
        {
            string low = s.ToLowerInvariant();
            foreach (string p in new string[] { "example", "your_", "yourkey", "placeholder", "xxxx", "<", "changeme", "dummy", "sample", "test_key", "000000", "123456", "redacted", "*****", "insert", "todo", "n/a", "none" }) if (low.Contains(p)) return true;
            return false;
        }
        static string Mask(string s)
        {
            int eq = s.IndexOf('='); if (eq < 0) eq = s.IndexOf(':');
            string prefix = eq > 0 && eq < 40 ? s.Substring(0, eq + 1) + " " : "";
            string secret = eq > 0 && eq < 40 ? s.Substring(eq + 1).Trim().Trim('"', '\'') : s;
            if (secret.Length <= 8) return prefix + secret.Substring(0, Math.Min(2, secret.Length)) + new string('•', Math.Max(1, secret.Length - 2));
            return prefix + secret.Substring(0, 4) + new string('•', Math.Min(12, secret.Length - 8)) + secret.Substring(secret.Length - 4);
        }
        static double Entropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0; Dictionary<char, int> f = new Dictionary<char, int>(); foreach (char c in s) { int n; f.TryGetValue(c, out n); f[c] = n + 1; }
            double e = 0; foreach (int n in f.Values) { double p = (double)n / s.Length; e -= p * Math.Log(p, 2); } return e;
        }
        static bool LooksBinary(byte[] b) { int n = Math.Min(b.Length, 8000), nul = 0; for (int i = 0; i < n; i++) if (b[i] == 0) nul++; return nul > n / 100; }
        static string Decode(byte[] b)
        {
            if (b.Length >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) return Encoding.UTF8.GetString(b, 3, b.Length - 3);
            if (b.Length >= 2 && b[0] == 0xFF && b[1] == 0xFE) return Encoding.Unicode.GetString(b, 2, b.Length - 2);
            if (b.Length >= 2 && b[0] == 0xFE && b[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(b, 2, b.Length - 2);
            try { return new UTF8Encoding(false, true).GetString(b); } catch { return Encoding.Default.GetString(b); }
        }
    }
}
