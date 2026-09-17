// File engines (no UI): a fast parallel file walker, password-based AES-256 file encryption with a
// built-in decrypt, secure wipe, wildcard/substring name search, and a hash sweep (find files whose
// MD5/SHA-1/SHA-256 matches one you supply). Pure .NET Framework, no external libraries.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PSTools
{
    /// <summary>One entry in a folder listing or a search result.</summary>
    public class FileEntry
    {
        public string Name = "", Path = "", Dir = "", Ext = ""; public bool IsDir; public long Size; public DateTime Modified; public FileAttributes Attributes;
        public string Kind { get { return IsDir ? "folder" : (Ext.Length > 0 ? Ext.TrimStart('.') : "file"); } }
        public string AttrText { get { List<string> l = new List<string>(); if ((Attributes & FileAttributes.Hidden) != 0) l.Add("hidden"); if ((Attributes & FileAttributes.System) != 0) l.Add("system"); if ((Attributes & FileAttributes.ReadOnly) != 0) l.Add("read-only"); if ((Attributes & FileAttributes.ReparsePoint) != 0) l.Add("link"); if ((Attributes & FileAttributes.Encrypted) != 0) l.Add("EFS"); if ((Attributes & FileAttributes.Compressed) != 0) l.Add("compressed"); return string.Join(", ", l.ToArray()); } }
        public bool Encrypted { get { return !IsDir && Path.EndsWith(FileCrypto.Ext, StringComparison.OrdinalIgnoreCase); } }
    }

    /// <summary>A multithreaded directory walker. Enumerates FileInfo objects (Length/dates come free from the
    /// find data), skips reparse points so links can't loop, and streams every file to a visitor.</summary>
    public class FastWalk
    {
        public IList<string> Roots = new List<string>(); public volatile bool Cancel; public int Threads = Math.Max(2, Math.Min(16, Environment.ProcessorCount));
        public long DirsScanned, FilesSeen, Denied; public string Current = "";
        readonly object gate = new object(); readonly Stack<string> stack = new Stack<string>(); int idle, total;

        /// <summary>Runs the walk on the calling thread's worker pool; returns when everything is enumerated or cancelled.</summary>
        public void Run(Action<FileInfo> onFile)
        {
            stack.Clear(); foreach (string r in Roots) if (!string.IsNullOrEmpty(r)) stack.Push(r);
            total = Math.Max(1, Threads); idle = 0;
            List<Thread> workers = new List<Thread>();
            for (int i = 0; i < total; i++) { Thread t = new Thread(delegate () { Worker(onFile); }); t.IsBackground = true; t.Name = "walk" + i; workers.Add(t); t.Start(); }
            foreach (Thread t in workers) t.Join();
        }
        public void Stop() { lock (gate) { Cancel = true; Monitor.PulseAll(gate); } }

        void Worker(Action<FileInfo> onFile)
        {
            while (true)
            {
                string dir;
                lock (gate)
                {
                    while (stack.Count == 0)
                    {
                        idle++;
                        if (idle >= total || Cancel) { Monitor.PulseAll(gate); return; }
                        Monitor.Wait(gate); idle--;
                        if (Cancel) return;
                    }
                    if (Cancel) return; dir = stack.Pop();
                }
                Current = dir;
                try
                {
                    DirectoryInfo di = new DirectoryInfo(dir);
                    foreach (FileInfo fi in di.EnumerateFiles()) { if (Cancel) return; try { onFile(fi); } catch { } Interlocked.Increment(ref FilesSeen); }
                    List<string> subs = new List<string>();
                    foreach (DirectoryInfo sd in di.EnumerateDirectories()) { if (Cancel) return; try { if ((sd.Attributes & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; } subs.Add(sd.FullName); }
                    if (subs.Count > 0) lock (gate) { foreach (string s in subs) stack.Push(s); Monitor.PulseAll(gate); }
                }
                catch (UnauthorizedAccessException) { Interlocked.Increment(ref Denied); }
                catch { }
                Interlocked.Increment(ref DirsScanned);
            }
        }

        /// <summary>The fixed drives, each as a root path, for a whole-machine walk.</summary>
        public static List<string> FixedDrives()
        {
            List<string> l = new List<string>();
            try { foreach (DriveInfo d in DriveInfo.GetDrives()) { try { if (d.IsReady && (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable)) l.Add(d.RootDirectory.FullName); } catch { } } } catch { }
            return l;
        }
    }

    /// <summary>Wildcard and substring matching for file names.</summary>
    public static class Wildcard
    {
        public static bool HasWildcard(string q) { return q != null && (q.IndexOf('*') >= 0 || q.IndexOf('?') >= 0); }
        public static bool Match(string name, string query, bool caseSensitive)
        {
            if (string.IsNullOrEmpty(query)) return true; if (name == null) return false;
            StringComparison sc = caseSensitive ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
            if (!HasWildcard(query)) return name.IndexOf(query, sc) >= 0;
            return GlobMatch(name, query, caseSensitive);
        }
        static bool GlobMatch(string s, string p, bool cs)
        {
            if (!cs) { s = s.ToLowerInvariant(); p = p.ToLowerInvariant(); }
            int si = 0, pi = 0, star = -1, mark = 0;
            while (si < s.Length)
            {
                if (pi < p.Length && (p[pi] == '?' || p[pi] == s[si])) { si++; pi++; }
                else if (pi < p.Length && p[pi] == '*') { star = pi++; mark = si; }
                else if (star != -1) { pi = star + 1; si = ++mark; }
                else return false;
            }
            while (pi < p.Length && p[pi] == '*') pi++;
            return pi == p.Length;
        }
    }

    /// <summary>MD5 / SHA-1 / SHA-256 in one streaming pass, and target-hash parsing for the sweep.</summary>
    public static class Hashes
    {
        public static string AlgoOf(string hex) { if (hex == null) return null; int n = hex.Length; return n == 32 ? "MD5" : n == 40 ? "SHA1" : n == 64 ? "SHA256" : null; }
        public static bool LooksHex(string s) { if (string.IsNullOrEmpty(s)) return false; foreach (char c in s) if (!Uri.IsHexDigit(c)) return false; return true; }
        static string Hex(byte[] b) { StringBuilder sb = new StringBuilder(b.Length * 2); foreach (byte x in b) sb.Append(x.ToString("x2")); return sb.ToString(); }

        /// <summary>Computes the requested algorithms for one file in a single read. Keys: "MD5" / "SHA1" / "SHA256".</summary>
        public static Dictionary<string, string> Compute(string path, bool md5, bool sha1, bool sha256)
        {
            List<KeyValuePair<string, HashAlgorithm>> algos = new List<KeyValuePair<string, HashAlgorithm>>();
            if (md5) algos.Add(new KeyValuePair<string, HashAlgorithm>("MD5", MD5.Create()));
            if (sha1) algos.Add(new KeyValuePair<string, HashAlgorithm>("SHA1", SHA1.Create()));
            if (sha256) algos.Add(new KeyValuePair<string, HashAlgorithm>("SHA256", SHA256.Create()));
            Dictionary<string, string> outp = new Dictionary<string, string>();
            try
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 20, FileOptions.SequentialScan))
                {
                    byte[] buf = new byte[1 << 20]; int n;
                    while ((n = fs.Read(buf, 0, buf.Length)) > 0) foreach (KeyValuePair<string, HashAlgorithm> a in algos) a.Value.TransformBlock(buf, 0, n, null, 0);
                    foreach (KeyValuePair<string, HashAlgorithm> a in algos) { a.Value.TransformFinalBlock(buf, 0, 0); outp[a.Key] = Hex(a.Value.Hash); }
                }
            }
            finally { foreach (KeyValuePair<string, HashAlgorithm> a in algos) a.Value.Clear(); }
            return outp;
        }

        // A hash is a run of exactly 32 / 40 / 64 hex digits, bounded so it is not part of a longer hex run.
        // The (?<![0-9a-fA-F]) / (?![0-9a-fA-F]) look-arounds keep a 64-char SHA-256 from also matching as MD5/SHA-1.
        static readonly Regex HashRx = new Regex(@"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])", RegexOptions.Compiled);
        static readonly Regex HexRunRx = new Regex(@"(?<![0-9a-fA-F])[0-9a-fA-F]{8,128}(?![0-9a-fA-F])", RegexOptions.Compiled);

        /// <summary>Pulls every MD5/SHA-1/SHA-256 out of arbitrary text (a paste, a log, a CSV, JSON, an IOC report),
        /// wherever they appear — not just space-separated. Returns a lowercase set plus which algorithms are present;
        /// `bad` counts hex runs that look hash-ish but are the wrong length. Case- and delimiter-insensitive.</summary>
        public static HashSet<string> ParseTargets(string text, out bool md5, out bool sha1, out bool sha256, out int bad)
        {
            md5 = sha1 = sha256 = false; bad = 0; HashSet<string> set = new HashSet<string>();
            if (string.IsNullOrEmpty(text)) return set;
            foreach (Match m in HashRx.Matches(text))
            {
                string h = m.Value.ToLowerInvariant(); set.Add(h);
                if (h.Length == 32) md5 = true; else if (h.Length == 40) sha1 = true; else sha256 = true;
            }
            // count near-misses (hex runs that aren't a valid hash length) so the UI can warn
            foreach (Match m in HexRunRx.Matches(text)) { int n = m.Length; if (n != 32 && n != 40 && n != 64) bad++; }
            return set;
        }

        /// <summary>Read a file and extract every hash from it (any text format; binary is rejected). Caps the read at 64 MB.</summary>
        public static HashSet<string> FromFile(string path, out bool md5, out bool sha1, out bool sha256, out int bad, out string note)
        {
            md5 = sha1 = sha256 = false; bad = 0; note = "";
            try
            {
                FileInfo fi = new FileInfo(path); if (!fi.Exists) { note = "file not found"; return new HashSet<string>(); }
                if (fi.Length > 64L * 1024 * 1024) { note = "file is larger than 64 MB"; return new HashSet<string>(); }
                byte[] bytes = File.ReadAllBytes(path);
                int nul = 0, cap = Math.Min(bytes.Length, 8000); for (int i = 0; i < cap; i++) if (bytes[i] == 0) nul++;
                if (nul > cap / 50) { note = "that looks like a binary file, not a list of hashes"; return new HashSet<string>(); }
                string text; if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) text = Encoding.UTF8.GetString(bytes, 3, bytes.Length - 3);
                else if (bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) text = Encoding.Unicode.GetString(bytes, 2, bytes.Length - 2);
                else text = Encoding.UTF8.GetString(bytes);
                return ParseTargets(text, out md5, out sha1, out sha256, out bad);
            }
            catch (Exception ex) { note = ex.Message; return new HashSet<string>(); }
        }
    }

    /// <summary>Password-based file encryption: AES-256-CBC with PBKDF2 key derivation and an HMAC-SHA256 tag
    /// (encrypt-then-MAC). The container is self-describing so Decrypt needs only the file and the password.
    /// A lost password is unrecoverable by design.</summary>
    public static class FileCrypto
    {
        public const string Ext = ".enc";
        static readonly byte[] Magic = Encoding.ASCII.GetBytes("PSTBOX01"); // 8 bytes
        const int SaltLen = 16, IvLen = 16, CheckLen = 8, MacLen = 32, Iterations = 200000;
        const int HeaderLen = 8 + SaltLen + IvLen + 4 + CheckLen; // 52

        public static bool IsEncrypted(string path)
        {
            try { using (FileStream fs = File.OpenRead(path)) { byte[] m = new byte[8]; if (fs.Read(m, 0, 8) < 8) return false; for (int i = 0; i < 8; i++) if (m[i] != Magic[i]) return false; return true; } }
            catch { return false; }
        }

        static void Derive(string password, byte[] salt, out byte[] aesKey, out byte[] macKey, out byte[] check)
        {
            using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password ?? "", salt, Iterations))
            { aesKey = kdf.GetBytes(32); macKey = kdf.GetBytes(32); check = kdf.GetBytes(CheckLen); }
        }

        /// <summary>Encrypts inPath to outPath. progress(0..1) is optional. Throws on I/O errors.</summary>
        public static void Encrypt(string inPath, string outPath, string password, Action<double> progress)
        {
            byte[] salt = new byte[SaltLen], iv = new byte[IvLen];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) { rng.GetBytes(salt); rng.GetBytes(iv); }
            byte[] aesKey, macKey, check; Derive(password, salt, out aesKey, out macKey, out check);
            long total = 0; try { total = new FileInfo(inPath).Length; } catch { }
            using (FileStream outFs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                outFs.Write(Magic, 0, 8); outFs.Write(salt, 0, SaltLen); outFs.Write(iv, 0, IvLen);
                outFs.Write(BitConverter.GetBytes(Iterations), 0, 4); outFs.Write(check, 0, CheckLen);
                using (Aes aes = Aes.Create()) { aes.KeySize = 256; aes.Key = aesKey; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                    using (ICryptoTransform enc = aes.CreateEncryptor())
                    using (CryptoStream cs = new CryptoStream(outFs, enc, CryptoStreamMode.Write))
                    using (FileStream inFs = new FileStream(inPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan))
                    {
                        byte[] buf = new byte[1 << 20]; int n; long done = 0;
                        while ((n = inFs.Read(buf, 0, buf.Length)) > 0) { cs.Write(buf, 0, n); done += n; if (progress != null && total > 0) progress((double)done / total * 0.9); }
                        cs.FlushFinalBlock();
                    }
                }
            }
            // append HMAC over the whole file so a torn write is caught on decrypt
            byte[] tag = MacOfFile(outPath, macKey);
            using (FileStream outFs = new FileStream(outPath, FileMode.Append, FileAccess.Write, FileShare.None)) outFs.Write(tag, 0, tag.Length);
            if (progress != null) progress(1);
        }

        static byte[] MacOfFile(string path, byte[] macKey)
        {
            using (HMACSHA256 mac = new HMACSHA256(macKey))
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan))
            { byte[] buf = new byte[1 << 20]; int n; while ((n = fs.Read(buf, 0, buf.Length)) > 0) mac.TransformBlock(buf, 0, n, null, 0); mac.TransformFinalBlock(buf, 0, 0); return mac.Hash; }
        }
        static byte[] MacOfRange(string path, byte[] macKey, long length)
        {
            using (HMACSHA256 mac = new HMACSHA256(macKey))
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan))
            { byte[] buf = new byte[1 << 20]; long left = length; int n; while (left > 0 && (n = fs.Read(buf, 0, (int)Math.Min(buf.Length, left))) > 0) { mac.TransformBlock(buf, 0, n, null, 0); left -= n; } mac.TransformFinalBlock(buf, 0, 0); return mac.Hash; }
        }

        public class CryptoException : Exception { public CryptoException(string m) : base(m) { } }

        /// <summary>Header + password + integrity check without producing output. True if this file will decrypt with this password.</summary>
        public static bool Verify(string path, string password)
        {
            try { ReadAndCheck(path, password); return true; } catch { return false; }
        }
        static void ReadAndCheck(string path, string password)
        {
            using (FileStream fs = File.OpenRead(path))
            {
                if (fs.Length < HeaderLen + MacLen + 16) throw new CryptoException("not a valid encrypted file");
                byte[] head = new byte[HeaderLen]; ReadFull(fs, head, HeaderLen);
                for (int i = 0; i < 8; i++) if (head[i] != Magic[i]) throw new CryptoException("not a PowerTower encrypted file");
                byte[] salt = new byte[SaltLen]; Array.Copy(head, 8, salt, 0, SaltLen);
                byte[] check = new byte[CheckLen]; Array.Copy(head, 8 + SaltLen + IvLen + 4, check, 0, CheckLen);
                byte[] aesKey, macKey, check2; Derive(password, salt, out aesKey, out macKey, out check2);
                bool ok = true; for (int i = 0; i < CheckLen; i++) if (check[i] != check2[i]) ok = false;
                if (!ok) throw new CryptoException("wrong password");
                long macAt = fs.Length - MacLen; fs.Position = macAt; byte[] stored = new byte[MacLen]; ReadFull(fs, stored, MacLen);
                byte[] actual = MacOfRange(path, macKey, macAt);
                for (int i = 0; i < MacLen; i++) if (stored[i] != actual[i]) throw new CryptoException("wrong password or the file is corrupted");
            }
        }

        /// <summary>Decrypts inPath to outPath. Throws CryptoException on a wrong password or a corrupted file (before touching outPath's content beyond truncation).</summary>
        public static void Decrypt(string inPath, string outPath, string password, Action<double> progress)
        {
            ReadAndCheck(inPath, password); // fail fast, no partial output on bad password
            byte[] head = new byte[HeaderLen];
            using (FileStream fs = File.OpenRead(inPath)) ReadFull(fs, head, HeaderLen);
            byte[] salt = new byte[SaltLen]; Array.Copy(head, 8, salt, 0, SaltLen);
            byte[] iv = new byte[IvLen]; Array.Copy(head, 8 + SaltLen, iv, 0, IvLen);
            byte[] aesKey, macKey, check; Derive(password, salt, out aesKey, out macKey, out check);
            long fileLen = new FileInfo(inPath).Length; long cipherLen = fileLen - HeaderLen - MacLen;
            using (FileStream inFs = new FileStream(inPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan))
            {
                inFs.Position = HeaderLen;
                using (Aes aes = Aes.Create()) { aes.KeySize = 256; aes.Key = aesKey; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                    using (ICryptoTransform dec = aes.CreateDecryptor())
                    using (FileStream outFs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
                    using (CryptoStream cs = new CryptoStream(outFs, dec, CryptoStreamMode.Write))
                    {
                        byte[] buf = new byte[1 << 20]; long left = cipherLen, done = 0; int n;
                        while (left > 0 && (n = inFs.Read(buf, 0, (int)Math.Min(buf.Length, left))) > 0) { cs.Write(buf, 0, n); left -= n; done += n; if (progress != null && cipherLen > 0) progress((double)done / cipherLen); }
                        cs.FlushFinalBlock();
                    }
                }
            }
            if (progress != null) progress(1);
        }
        static void ReadFull(Stream s, byte[] buf, int len) { int off = 0; while (off < len) { int n = s.Read(buf, off, len - off); if (n <= 0) throw new EndOfStreamException(); off += n; } }

        public static string DefaultEncName(string path) { return path + Ext; }
        public static string DefaultDecName(string path) { return path.EndsWith(Ext, StringComparison.OrdinalIgnoreCase) ? path.Substring(0, path.Length - Ext.Length) : path + ".decrypted"; }

        /// <summary>Overwrites a file's bytes with random data (passes times), truncates, renames, then deletes it.
        /// Note: on SSDs, wear-levelling means the original blocks may still exist physically; this defeats casual recovery, not forensics.</summary>
        public static void SecureWipe(string path, int passes, Action<double> progress)
        {
            long len = 0; try { len = new FileInfo(path).Length; } catch { }
            if (len > 0)
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    byte[] buf = new byte[Math.Min(1 << 20, Math.Max(4096, len))];
                    for (int p = 0; p < Math.Max(1, passes); p++)
                    {
                        fs.Position = 0; long left = len;
                        while (left > 0) { int n = (int)Math.Min(buf.Length, left); if (p == passes - 1) Array.Clear(buf, 0, n); else rng.GetBytes(buf); fs.Write(buf, 0, n); left -= n; }
                        fs.Flush(true); if (progress != null) progress((double)(p + 1) / Math.Max(1, passes));
                    }
                    fs.SetLength(0);
                }
            }
            string dir = System.IO.Path.GetDirectoryName(path); string tmp = System.IO.Path.Combine(dir, Guid.NewGuid().ToString("N"));
            try { File.Move(path, tmp); File.Delete(tmp); } catch { File.Delete(path); }
        }
    }
}
