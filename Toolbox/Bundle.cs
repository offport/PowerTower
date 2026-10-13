// Bundle.cs - the collection bundle (.ptb) and the engagement file.
// A collector gathers everything about one host into one JSON document, seals it, and hands it on: `enrich` adds
// the vulnerability findings on a connected box, `report` renders the deliverables. The JSON writer here is the
// twin of Json.Parse (Vuln.cs) - the same shapes (object, array, string, number, bool, null) - so a bundle written
// here reads back with Json.Parse into the same tree. Sealing is AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC); the
// key comes from a passphrase (PBKDF2-SHA256) or is random and wrapped to the engagement's RSA public key
// (OAEP-SHA256), so the host that produced a bundle cannot read it back. Pure logic: no UI, no network.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace PSTools
{
    // ───────────────────────────── JSON writer ─────────────────────────────
    /// <summary>Serialises the tree Json.Parse produces (Dictionary&lt;string,object&gt;, List&lt;object&gt;, string, double, bool, null) plus the obvious extras: int/long, DateTime as ISO-8601 UTC, any IDictionary or IEnumerable.</summary>
    public static class JsonWrite
    {
        public static string Text(object v) { return Text(v, true); }
        public static string Text(object v, bool pretty) { StringBuilder sb = new StringBuilder(); Write(sb, v, pretty, 0); if (pretty) sb.Append('\n'); return sb.ToString(); }
        static void Indent(StringBuilder sb, bool pretty, int depth) { if (!pretty) return; sb.Append('\n'); for (int i = 0; i < depth; i++) sb.Append("  "); }
        static void Write(StringBuilder sb, object v, bool pretty, int depth)
        {
            if (depth > Json.MaxDepth) throw new FormatException("nesting too deep (more than " + Json.MaxDepth + " levels)");   // PT-23: a declared error, not a stack overflow
            if (v == null) { sb.Append("null"); return; }
            string s = v as string; if (s != null) { sb.Append(Json.Quote(s)); return; }
            if (v is bool) { sb.Append((bool)v ? "true" : "false"); return; }
            if (v is DateTime) { sb.Append('"').Append(Stamp((DateTime)v)).Append('"'); return; }
            if (v is double || v is float) { double d = Convert.ToDouble(v, CultureInfo.InvariantCulture); sb.Append(double.IsNaN(d) || double.IsInfinity(d) ? "null" : d.ToString("R", CultureInfo.InvariantCulture)); return; }
            if (v is int || v is long || v is short || v is byte || v is uint || v is ulong || v is decimal) { sb.Append(Convert.ToString(v, CultureInfo.InvariantCulture)); return; }
            if (v is Enum) { sb.Append(Json.Quote(v.ToString())); return; }
            IDictionary dict = v as IDictionary;
            if (dict != null)
            {
                sb.Append('{'); bool first = true;
                foreach (DictionaryEntry e in dict) { if (!first) sb.Append(','); first = false; Indent(sb, pretty, depth + 1); sb.Append(Json.Quote(Convert.ToString(e.Key, CultureInfo.InvariantCulture))).Append(pretty ? ": " : ":"); Write(sb, e.Value, pretty, depth + 1); }
                if (!first) Indent(sb, pretty, depth); sb.Append('}'); return;
            }
            IEnumerable list = v as IEnumerable;
            if (list != null)
            {
                sb.Append('['); bool first = true;
                foreach (object o in list) { if (!first) sb.Append(','); first = false; Indent(sb, pretty, depth + 1); Write(sb, o, pretty, depth + 1); }
                if (!first) Indent(sb, pretty, depth); sb.Append(']'); return;
            }
            sb.Append(Json.Quote(Convert.ToString(v, CultureInfo.InvariantCulture)));
        }
        /// <summary>ISO-8601 in UTC to the second: the one timestamp form in every bundle.</summary>
        public static string Stamp(DateTime d) { return (d.Kind == DateTimeKind.Utc ? d : d.ToUniversalTime()).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture); }
        public static DateTime? Date(object o) { if (o is DateTime) return (DateTime)o; string s = o as string; DateTime d; if (s != null && DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out d)) return d; return null; }
        /// <summary>A value that may be a JSON number (double) or an int, as int.</summary>
        public static int Int(object o, int def) { double? n = Json.N(o); return n.HasValue ? (int)n.Value : def; }
        public static long Long(object o, long def) { double? n = Json.N(o); return n.HasValue ? (long)n.Value : def; }
        public static bool Bool(object o) { return o is bool && (bool)o; }
        public static List<string> Strings(object o) { List<string> l = new List<string>(); foreach (object x in Json.Arr(o)) { string s = Json.S(x); if (s != null) l.Add(s); } return l; }
    }

    // ───────────────────────────── the bundle ─────────────────────────────
    public class BundleException : Exception { public BundleException(string m) : base(m) { } }

    /// <summary>One collection run on one host: a manifest plus named sections, each section the plain tree Json.Parse and JsonWrite share.</summary>
    public class Bundle
    {
        public const string Schema = "ptb/1";
        public Dictionary<string, object> Manifest = new Dictionary<string, object>();
        public readonly Dictionary<string, object> Sections = new Dictionary<string, object>();
        public Bundle() { Manifest["schema"] = Schema; }
        public object this[string section] { get { object o; return Sections.TryGetValue(section, out o) ? o : null; } set { Sections[section] = value; } }
        public string Host { get { return Json.GetS(Manifest, "host") ?? ""; } }
        public string RunId { get { return Json.GetS(Manifest, "runId") ?? ""; } }
        public string Platform { get { return Json.GetS(Manifest, "platform") ?? ""; } }
        public List<object> Modules { get { object m; if (!Manifest.TryGetValue("modules", out m) || !(m is List<object>)) { m = new List<object>(); Manifest["modules"] = m; } return (List<object>)m; } }
        /// <summary>Record a module's outcome in the manifest: ok · partial · skipped · failed.</summary>
        public void Module(string name, string status, int count, long ms, List<string> errors)
        {
            Dictionary<string, object> m = new Dictionary<string, object>(); m["name"] = name; m["status"] = status; m["count"] = count; m["durationMs"] = ms; m["errors"] = errors == null ? new List<string>() : new List<string>(errors); Modules.Add(m);
        }
        public string ModuleStatus(string name) { foreach (object m in Modules) if (Json.GetS(m, "name") == name) return Json.GetS(m, "status"); return null; }
        public object ToTree() { Dictionary<string, object> t = new Dictionary<string, object>(); t["manifest"] = Manifest; foreach (KeyValuePair<string, object> s in Sections) t[s.Key] = s.Value; return t; }
        public string ToJson(bool pretty) { return JsonWrite.Text(ToTree(), pretty); }
        public static Bundle FromJson(string json)
        {
            Dictionary<string, object> t; try { t = Json.Obj(Json.Parse(json)); } catch (Exception ex) { throw new BundleException("not a bundle: " + ex.Message); }
            if (t == null) throw new BundleException("not a bundle: the document is not a JSON object");
            Dictionary<string, object> m = Json.Obj(Json.Get(t, "manifest")); if (m == null) throw new BundleException("not a bundle: no manifest");
            string schema = Json.GetS(m, "schema") ?? ""; if (schema != Schema) throw new BundleException("bundle schema '" + schema + "' is not supported (this build reads " + Schema + ")");
            Bundle b = new Bundle(); b.Manifest = m; foreach (KeyValuePair<string, object> p in t) if (p.Key != "manifest") b.Sections[p.Key] = p.Value;
            return b;
        }
        public void Save(string path, BundleKey key) { byte[] plain = Encoding.UTF8.GetBytes(ToJson(false)); File.WriteAllBytes(path, BundleCrypto.Seal(plain, key)); }
        public static Bundle Load(string path, BundleKey key) { return FromJson(Encoding.UTF8.GetString(BundleCrypto.Open(File.ReadAllBytes(path), key))); }
        /// <summary>The sealing mode of a file without opening it ("plain", "passphrase", "public-key"), or null when it is not a bundle.</summary>
        public static string ModeOf(string path)
        {
            try
            {
                using (FileStream fs = File.OpenRead(path))
                {
                    byte[] head = new byte[8]; if (fs.Read(head, 0, 8) < 8 || !BundleCrypto.HasMagic(head)) return null;
                    int n = BitConverter.ToInt32(head, 4); if (n < 2 || n > 1 << 20) return null; byte[] h = new byte[n]; if (fs.Read(h, 0, n) < n) return null;
                    return Json.GetS(Json.Parse(Encoding.UTF8.GetString(h)), "mode");
                }
            }
            catch { return null; }
        }
    }

    /// <summary>How a bundle is sealed: to an engagement public key (the collector never holds anything that opens its own output), with a passphrase, or - explicitly - not at all.</summary>
    public class BundleKey
    {
        public string PublicXml, PrivateXml, Passphrase; public bool Plain, AllowLegacyKdf;   // AllowLegacyKdf: knowingly open a bundle whose header carries a lower PBKDF2 count than this build writes
        public static BundleKey ToPublic(string xml) { BundleKey k = new BundleKey(); k.PublicXml = xml; return k; }
        public static BundleKey WithPrivate(string xml) { BundleKey k = new BundleKey(); k.PrivateXml = xml; return k; }
        public static BundleKey FromPassphrase(string p) { BundleKey k = new BundleKey(); k.Passphrase = p ?? ""; return k; }
        public static BundleKey None() { BundleKey k = new BundleKey(); k.Plain = true; return k; }
        public string Mode { get { return Plain ? "plain" : Passphrase != null ? "passphrase" : "public-key"; } }
    }

    /// <summary>The .ptb wire format: "PTB1" · header length (4, little-endian) · header JSON · body · tag (32). Header: mode, cipher, mac, iv, and either kdf {salt, iterations} or key {id, wrapped}. Tag = HMAC-SHA256 over everything before it (plain mode: SHA-256, integrity only).</summary>
    public static class BundleCrypto
    {
        static readonly byte[] Magic = Encoding.ASCII.GetBytes("PTB1");
        public const int Iterations = 600000;   // PBKDF2-SHA256 for the passphrase mode; the header carries the count, so it can rise later
        public static bool HasMagic(byte[] b) { if (b == null || b.Length < 4) return false; for (int i = 0; i < 4; i++) if (b[i] != Magic[i]) return false; return true; }
        static byte[] Random(int n) { byte[] b = new byte[n]; using (RNGCryptoServiceProvider r = new RNGCryptoServiceProvider()) r.GetBytes(b); return b; }
        static void Derive(string pass, byte[] salt, int iterations, out byte[] aesKey, out byte[] macKey)
        {
            // one 32-byte PBKDF2 block, then an HMAC expand into the two keys: half the cost of deriving 64 bytes from PBKDF2, for the sealer and any attacker alike
            byte[] master; using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(pass ?? "", salt, iterations, HashAlgorithmName.SHA256)) master = kdf.GetBytes(32);
            using (HMACSHA256 h = new HMACSHA256(master)) { aesKey = h.ComputeHash(Encoding.ASCII.GetBytes("ptb/1 aes")); macKey = h.ComputeHash(Encoding.ASCII.GetBytes("ptb/1 mac")); }
        }
        static byte[] Aes(byte[] data, byte[] key, byte[] iv, bool encrypt)
        {
            using (System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create())
            {
                aes.KeySize = 256; aes.Key = key; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform t = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor()) return t.TransformFinalBlock(data, 0, data.Length);
            }
        }
        static byte[] Tag(byte[] macKey, byte[] data, int count)
        {
            if (macKey == null) { using (SHA256 h = SHA256.Create()) return h.ComputeHash(data, 0, count); }
            using (HMACSHA256 h = new HMACSHA256(macKey)) return h.ComputeHash(data, 0, count);
        }
        static bool Same(byte[] a, int aOff, byte[] b) { if (aOff + b.Length > a.Length) return false; int diff = 0; for (int i = 0; i < b.Length; i++) diff |= a[aOff + i] ^ b[i]; return diff == 0; }
        static RSA Rsa(string xml)
        {
            RSACng r = new RSACng();
            try { r.FromXmlString(xml); } catch (Exception ex) { r.Dispose(); throw new BundleException("not an RSA key: " + ex.Message); }
            return r;
        }
        public static void NewKeyPair(int bits, out string publicXml, out string privateXml) { using (RSACng r = new RSACng(bits)) { publicXml = r.ToXmlString(false); privateXml = r.ToXmlString(true); } }
        /// <summary>A short, stable id of a public key (first 16 hex of SHA-256 over its XML), kept in every sealed header so the wrong key is named, not guessed.</summary>
        public static string KeyId(string publicXml) { return Sha256Hex(Encoding.UTF8.GetBytes(publicXml ?? "")).Substring(0, 16); }
        public static string PublicOf(string privateXml) { using (RSA r = Rsa(privateXml)) return r.ToXmlString(false); }
        public static string Sha256Hex(byte[] b) { using (SHA256 h = SHA256.Create()) { byte[] d = h.ComputeHash(b); StringBuilder sb = new StringBuilder(64); foreach (byte x in d) sb.Append(x.ToString("x2")); return sb.ToString(); } }
        public static string FileSha256(string path) { using (FileStream fs = File.OpenRead(path)) using (SHA256 h = SHA256.Create()) { byte[] d = h.ComputeHash(fs); StringBuilder sb = new StringBuilder(64); foreach (byte x in d) sb.Append(x.ToString("x2")); return sb.ToString(); } }

        public static byte[] Seal(byte[] plain, BundleKey key)
        {
            if (key == null) throw new BundleException("no sealing key given - pass a public key, a passphrase, or ask for plain explicitly");
            Dictionary<string, object> h = new Dictionary<string, object>(); h["mode"] = key.Mode; h["cipher"] = key.Plain ? "none" : "AES-256-CBC"; h["mac"] = key.Plain ? "SHA-256" : "HMAC-SHA256";
            byte[] aesKey = null, macKey = null, iv = Random(16); h["iv"] = Convert.ToBase64String(iv);
            if (key.Plain) { }
            else if (key.Passphrase != null)
            {
                byte[] salt = Random(16); Derive(key.Passphrase, salt, Iterations, out aesKey, out macKey);
                Dictionary<string, object> kdf = new Dictionary<string, object>(); kdf["name"] = "PBKDF2-SHA256/HMAC-expand"; kdf["salt"] = Convert.ToBase64String(salt); kdf["iterations"] = Iterations; h["kdf"] = kdf;
            }
            else
            {
                if (string.IsNullOrEmpty(key.PublicXml)) throw new BundleException("sealing to a key needs the engagement public key");
                byte[] material = Random(64); aesKey = new byte[32]; macKey = new byte[32]; Buffer.BlockCopy(material, 0, aesKey, 0, 32); Buffer.BlockCopy(material, 32, macKey, 0, 32);
                Dictionary<string, object> k = new Dictionary<string, object>(); k["id"] = KeyId(key.PublicXml); k["wrap"] = "RSA-OAEP-SHA256";
                using (RSA rsa = Rsa(key.PublicXml)) k["wrapped"] = Convert.ToBase64String(rsa.Encrypt(material, RSAEncryptionPadding.OaepSHA256));
                h["key"] = k;
            }
            byte[] header = Encoding.UTF8.GetBytes(JsonWrite.Text(h, false)); byte[] body = key.Plain ? plain : Aes(plain, aesKey, iv, true);
            byte[] all = new byte[4 + 4 + header.Length + body.Length + 32]; int o = 0;
            Buffer.BlockCopy(Magic, 0, all, o, 4); o += 4; Buffer.BlockCopy(BitConverter.GetBytes(header.Length), 0, all, o, 4); o += 4;
            Buffer.BlockCopy(header, 0, all, o, header.Length); o += header.Length; Buffer.BlockCopy(body, 0, all, o, body.Length); o += body.Length;
            byte[] tag = Tag(macKey, all, o); Buffer.BlockCopy(tag, 0, all, o, 32);
            return all;
        }

        public static byte[] Open(byte[] file, BundleKey key)
        {
            if (key == null) key = BundleKey.None();
            if (file == null || file.Length < 4 + 4 + 2 + 32 || !HasMagic(file)) throw new BundleException("not a PowerTower bundle (bad magic or too short)");
            int hlen = BitConverter.ToInt32(file, 4); if (hlen < 2 || 8 + hlen + 32 > file.Length) throw new BundleException("truncated or corrupt bundle (header length " + hlen + ")");
            object h; try { h = Json.Parse(Encoding.UTF8.GetString(file, 8, hlen)); } catch (Exception ex) { throw new BundleException("corrupt bundle header: " + ex.Message); }
            string mode = Json.GetS(h, "mode") ?? ""; int bodyAt = 8 + hlen, bodyLen = file.Length - bodyAt - 32; int tagAt = file.Length - 32;
            byte[] aesKey = null, macKey = null;
            if (mode == "plain")
            {
                // a plain file is unauthenticated: whoever holds a passphrase or an engagement key is expecting a sealed bundle and must not be handed a forgery instead (PT-20)
                if (!key.Plain) throw new BundleException("this file is not sealed (plain mode) but a " + (key.Passphrase != null ? "passphrase" : "private key") + " was given - refusing an unauthenticated bundle; plain files open only with an explicit --plain");
            }
            else if (mode == "passphrase")
            {
                if (key.Passphrase == null) throw new BundleException("this bundle is sealed with a passphrase - give it with --pass");
                object kdf = Json.Get(h, "kdf"); byte[] salt; int it = JsonWrite.Int(Json.Get(kdf, "iterations"), 0);
                try { salt = Convert.FromBase64String(Json.GetS(kdf, "salt") ?? ""); } catch { throw new BundleException("corrupt bundle header (salt)"); }
                if (salt.Length < 8) throw new BundleException("corrupt bundle header (salt)");
                // the iteration count comes from the file: bound it both ways before paying for it (PT-21)
                if (it > 4 * Iterations) throw new BundleException("unsupported kdf cost (" + it.ToString("N0") + " iterations; this build accepts at most " + (4 * Iterations).ToString("N0") + ")");
                if (it < Iterations && !key.AllowLegacyKdf) throw new BundleException("kdf cost " + it.ToString("N0") + " is below this build's minimum of " + Iterations.ToString("N0") + " - refusing a downgraded header (AllowLegacyKdf opens older bundles knowingly)");
                if (it < 1000) throw new BundleException("corrupt bundle header (kdf)");
                Derive(key.Passphrase, salt, it, out aesKey, out macKey);
            }
            else if (mode == "public-key")
            {
                if (string.IsNullOrEmpty(key.PrivateXml)) throw new BundleException("this bundle is sealed to an engagement key - the engagement's private key is needed to open it");
                object k = Json.Get(h, "key"); string id = Json.GetS(k, "id") ?? ""; string mine;
                try { mine = KeyId(PublicOf(key.PrivateXml)); } catch (BundleException) { throw; } catch (Exception ex) { throw new BundleException("not a usable private key: " + ex.Message); }
                if (id != mine) throw new BundleException("sealed to a different engagement key (bundle key " + id + ", this key " + mine + ")");
                byte[] material;
                try { using (RSA rsa = Rsa(key.PrivateXml)) material = rsa.Decrypt(Convert.FromBase64String(Json.GetS(k, "wrapped") ?? ""), RSAEncryptionPadding.OaepSHA256); }
                catch (BundleException) { throw; } catch (Exception ex) { throw new BundleException("could not unwrap the bundle key: " + ex.Message); }
                if (material.Length != 64) throw new BundleException("corrupt bundle key material");
                aesKey = new byte[32]; macKey = new byte[32]; Buffer.BlockCopy(material, 0, aesKey, 0, 32); Buffer.BlockCopy(material, 32, macKey, 0, 32);
            }
            else throw new BundleException("unknown sealing mode '" + mode + "'");
            byte[] tag = Tag(macKey, file, tagAt);
            if (!Same(file, tagAt, tag)) throw new BundleException(mode == "plain" ? "integrity check failed: the file was modified" : "integrity check failed: wrong key or passphrase, or the file was modified");
            byte[] body = new byte[bodyLen]; Buffer.BlockCopy(file, bodyAt, body, 0, bodyLen);
            if (mode == "plain") return body;
            byte[] iv; try { iv = Convert.FromBase64String(Json.GetS(h, "iv") ?? ""); } catch { throw new BundleException("corrupt bundle header (iv)"); }
            if (iv.Length != 16) throw new BundleException("corrupt bundle header (iv)");
            try { return Aes(body, aesKey, iv, false); } catch (CryptographicException ex) { throw new BundleException("decryption failed: " + ex.Message); }
        }

        // ── DPAPI, for the engagement private key at rest on the controller: bound to this Windows user, salted with the engagement id ──
        static byte[] Entropy(string s) { using (SHA256 h = SHA256.Create()) return h.ComputeHash(Encoding.UTF8.GetBytes("PowerTower:" + (s ?? ""))); }
        public static byte[] Protect(byte[] data, string entropy) { return ProtectedData.Protect(data, Entropy(entropy), DataProtectionScope.CurrentUser); }
        public static byte[] Unprotect(byte[] data, string entropy)
        {
            try { return ProtectedData.Unprotect(data, Entropy(entropy), DataProtectionScope.CurrentUser); }
            catch (CryptographicException ex) { throw new BundleException("could not unprotect the key (another Windows user or machine, or a different engagement id): " + ex.Message); }
        }
    }

    // ───────────────────────────── the engagement file ─────────────────────────────
    /// <summary>engagement.json: who, for whom, which hosts, when, which modules, how long to keep the data, and the public key bundles are sealed to. The controller and the collector refuse to run outside it.</summary>
    public class Engagement
    {
        public const string Schema = "engagement/1";
        public string Id = "", Client = "", Operator = "", Notes = "", PublicKeyXml = ""; public string File;
        public readonly List<string> Scope = new List<string>(); public readonly List<string> Modules = new List<string>();
        public DateTime? WindowStartUtc, WindowEndUtc; public int RetentionDays = 90;

        public object ToTree()
        {
            Dictionary<string, object> t = new Dictionary<string, object>(); t["schema"] = Schema; t["id"] = Id; t["client"] = Client; t["operator"] = Operator;
            t["scope"] = new List<string>(Scope); t["windowStartUtc"] = WindowStartUtc.HasValue ? JsonWrite.Stamp(WindowStartUtc.Value) : null; t["windowEndUtc"] = WindowEndUtc.HasValue ? JsonWrite.Stamp(WindowEndUtc.Value) : null;
            t["modules"] = new List<string>(Modules); t["retentionDays"] = RetentionDays; t["publicKeyXml"] = PublicKeyXml; t["notes"] = Notes; return t;
        }
        public void Save(string path) { System.IO.File.WriteAllText(path, JsonWrite.Text(ToTree(), true), new UTF8Encoding(false)); File = path; }
        public static Engagement Load(string path)
        {
            object t; try { t = Json.Parse(System.IO.File.ReadAllText(path, Encoding.UTF8)); } catch (Exception ex) { throw new BundleException("engagement file " + path + ": " + ex.Message); }
            if (Json.Obj(t) == null) throw new BundleException("engagement file " + path + ": not a JSON object");
            string schema = Json.GetS(t, "schema") ?? ""; if (schema != Schema) throw new BundleException("engagement file " + path + ": schema '" + schema + "' is not " + Schema);
            Engagement e = new Engagement(); e.File = path; e.Id = Json.GetS(t, "id") ?? ""; e.Client = Json.GetS(t, "client") ?? ""; e.Operator = Json.GetS(t, "operator") ?? ""; e.Notes = Json.GetS(t, "notes") ?? ""; e.PublicKeyXml = Json.GetS(t, "publicKeyXml") ?? "";
            e.Scope.AddRange(JsonWrite.Strings(Json.Get(t, "scope"))); e.Modules.AddRange(JsonWrite.Strings(Json.Get(t, "modules")));
            e.WindowStartUtc = JsonWrite.Date(Json.Get(t, "windowStartUtc")); e.WindowEndUtc = JsonWrite.Date(Json.Get(t, "windowEndUtc")); e.RetentionDays = JsonWrite.Int(Json.Get(t, "retentionDays"), 90);
            return e;
        }
        /// <summary>Problems that make the file unusable; empty means usable.</summary>
        public List<string> Validate()
        {
            List<string> l = new List<string>();
            if (Id.Trim().Length == 0) l.Add("id is empty");
            if (Scope.Count == 0) l.Add("scope is empty - nothing may be audited");
            foreach (string s in Scope) { IPAddress ip; int bits; if (s == "*") continue; if (s.IndexOf('/') >= 0 && !Cidr(s, out ip, out bits)) l.Add("scope entry '" + s + "' is not a valid CIDR"); }
            if (WindowStartUtc.HasValue && WindowEndUtc.HasValue && WindowEndUtc.Value < WindowStartUtc.Value) l.Add("window ends before it starts");
            if (RetentionDays < 1) l.Add("retentionDays must be at least 1");
            return l;
        }
        /// <summary>Is this target (host name or IP) inside the scope? Exact host name (case-insensitive), exact IP, CIDR, or "*". An empty scope allows nothing.</summary>
        public bool InScope(string target, out string why)
        {
            string t = (target ?? "").Trim(); why = "";
            if (t.Length == 0) { why = "no target"; return false; }
            if (Scope.Count == 0) { why = "the engagement scope is empty"; return false; }
            IPAddress ip; bool isIp = IPAddress.TryParse(t, out ip);
            foreach (string s in Scope)
            {
                if (s == "*") return true;
                if (string.Equals(s, t, StringComparison.OrdinalIgnoreCase)) return true;
                IPAddress net; int bits; if (isIp && Cidr(s, out net, out bits) && InCidr(ip, net, bits)) return true;
            }
            why = "'" + t + "' is not in the engagement scope (" + Scope.Count + " entr" + (Scope.Count == 1 ? "y" : "ies") + ")"; return false;
        }
        public bool InWindow(DateTime nowUtc, out string why)
        {
            why = "";
            if (WindowStartUtc.HasValue && nowUtc < WindowStartUtc.Value) { why = "the engagement window opens " + JsonWrite.Stamp(WindowStartUtc.Value); return false; }
            if (WindowEndUtc.HasValue && nowUtc > WindowEndUtc.Value) { why = "the engagement window closed " + JsonWrite.Stamp(WindowEndUtc.Value); return false; }
            return true;
        }
        /// <summary>Module allow-list; an empty list allows every read-only module.</summary>
        public bool ModuleAllowed(string module) { if (Modules.Count == 0) return true; foreach (string m in Modules) if (string.Equals(m, module, StringComparison.OrdinalIgnoreCase)) return true; return false; }
        public DateTime? PurgeAfter(DateTime collectedUtc) { return collectedUtc.AddDays(RetentionDays); }

        static bool Cidr(string spec, out IPAddress net, out int bits)
        {
            net = null; bits = -1; int i = spec.IndexOf('/'); if (i < 0) return false;
            if (!IPAddress.TryParse(spec.Substring(0, i), out net) || !int.TryParse(spec.Substring(i + 1), out bits)) return false;
            int max = net.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32; return bits >= 0 && bits <= max;
        }
        static bool InCidr(IPAddress ip, IPAddress net, int bits)
        {
            byte[] a = ip.GetAddressBytes(), n = net.GetAddressBytes(); if (a.Length != n.Length) return false;
            int full = bits / 8, rem = bits % 8; for (int i = 0; i < full; i++) if (a[i] != n[i]) return false;
            if (rem == 0) return true; int mask = (0xFF << (8 - rem)) & 0xFF; return (a[full] & mask) == (n[full] & mask);
        }
    }
}
