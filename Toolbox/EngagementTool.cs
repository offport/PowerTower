// EngagementTool.cs - `engagement new / inspect / check`: the file every remote run is gated by (who, for whom, which
// hosts, when, which modules, how long the data is kept) and the key pair bundles are sealed to. The private key is
// written DPAPI-protected for the Windows user who created it, salted with the engagement id; it is never printed.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PSTools
{
    public static class EngagementTool
    {
        /// <summary>Creates engagement.json and engagement.key in dir. Refuses to overwrite an existing engagement (its key would be lost).</summary>
        public static Engagement New(string dir, string id, string client, string op, IEnumerable<string> scope, DateTime? fromUtc, DateTime? toUtc, IEnumerable<string> modules, int retentionDays, string notes, int keyBits)
        {
            Engagement e = new Engagement(); e.Id = (id ?? "").Trim(); e.Client = client ?? ""; e.Operator = op ?? ""; e.Notes = notes ?? ""; e.WindowStartUtc = fromUtc; e.WindowEndUtc = toUtc; e.RetentionDays = retentionDays;
            if (scope != null) foreach (string s in scope) { string t = (s ?? "").Trim(); if (t.Length > 0 && !e.Scope.Contains(t)) e.Scope.Add(t); }
            if (modules != null) foreach (string m in modules) { string t = (m ?? "").Trim().ToLowerInvariant(); if (t.Length > 0 && !e.Modules.Contains(t)) e.Modules.Add(t); }
            foreach (string m in e.Modules) if (Array.IndexOf(Collector.AllModules, m) < 0) throw new BundleException("unknown module '" + m + "' (choose from " + string.Join(", ", Collector.AllModules) + ")");
            foreach (char ch in e.Id) if (!char.IsLetterOrDigit(ch) && ch != '-' && ch != '_' && ch != '.') throw new BundleException("id: letters, digits, - _ . only");
            List<string> bad = e.Validate(); if (bad.Count > 0) throw new BundleException(string.Join("; ", bad.ToArray()));
            if (keyBits != 2048 && keyBits != 3072 && keyBits != 4096) throw new BundleException("key size must be 2048, 3072 or 4096");
            Directory.CreateDirectory(dir); string jf = Path.Combine(dir, "engagement.json"), kf = Engagement.KeyFileFor(jf);
            if (File.Exists(jf) || File.Exists(kf)) throw new BundleException("an engagement already exists in " + dir + " - refusing to overwrite its key");
            string pub, priv; BundleCrypto.NewKeyPair(keyBits, out pub, out priv); e.PublicKeyXml = pub;
            File.WriteAllBytes(kf, BundleCrypto.Protect(Encoding.UTF8.GetBytes(priv), e.Id)); e.Save(jf); return e;
        }

        /// <summary>A readable summary. The private key never appears; the public key only as its id and size.</summary>
        public static List<string> Inspect(Engagement e)
        {
            List<string> l = new List<string>(); l.Add("engagement   " + e.Id); l.Add("client       " + e.Client); l.Add("operator     " + e.Operator);
            l.Add("scope        " + (e.Scope.Count == 0 ? "(empty - nothing may be audited)" : string.Join(", ", e.Scope.ToArray())));
            l.Add("window       " + (e.WindowStartUtc.HasValue ? JsonWrite.Stamp(e.WindowStartUtc.Value) : "(open)") + " → " + (e.WindowEndUtc.HasValue ? JsonWrite.Stamp(e.WindowEndUtc.Value) : "(open)"));
            l.Add("modules      " + (e.Modules.Count == 0 ? "every read-only module" : string.Join(", ", e.Modules.ToArray()))); l.Add("retention    " + e.RetentionDays + " day(s) after collection");
            l.Add("public key   " + (e.PublicKeyXml.Length > 0 ? "id " + BundleCrypto.KeyId(e.PublicKeyXml) + " (RSA " + ModulusBits(e.PublicKeyXml) + " bits)" : "(none - bundles cannot be sealed to this engagement)"));
            string kf = e.File != null ? Engagement.KeyFileFor(e.File) : null; string ks;
            if (kf == null || !File.Exists(kf)) ks = "(no key file beside the engagement)";
            else { try { string priv = Engagement.PrivateKey(e, kf); ks = BundleCrypto.KeyId(BundleCrypto.PublicOf(priv)) == BundleCrypto.KeyId(e.PublicKeyXml) ? "DPAPI-protected, opens for this Windows user, matches the public key" : "DPAPI-protected, opens for this user but does NOT match the public key"; } catch (BundleException ex) { ks = "DPAPI-protected, cannot be opened here (" + ex.Message + ")"; } }
            l.Add("private key  " + Path.GetFileName(kf ?? "engagement.key") + ": " + ks);
            if (e.Notes.Length > 0) l.Add("notes        " + e.Notes);
            List<string> bad = e.Validate(); l.Add("valid        " + (bad.Count == 0 ? "yes" : "NO - " + string.Join("; ", bad.ToArray())));
            return l;
        }
        static int ModulusBits(string pubXml) { try { int a = pubXml.IndexOf("<Modulus>") + 9, b = pubXml.IndexOf("</Modulus>"); return Convert.FromBase64String(pubXml.Substring(a, b - a)).Length * 8; } catch { return 0; } }
    }
}
