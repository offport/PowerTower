// FeedPack.cs - a feed pack: the vulnerability feed cache (MSRC releases, KEV, EPSS batches, NVD records) exported as a
// folder with a manifest, and imported again on a box that has no internet, so `enrich` can run there offline. Files
// keep their original times, so the cache's age rules and stale-fallback notes stay honest; the manifest carries a
// SHA-256 per file and import refuses anything that does not match or is not a plain .json name.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PSTools
{
    public static class FeedPack
    {
        public const string Schema = "feedpack/1", ManifestName = "feedpack.json";
        public class Result { public int Files, Skipped; public long Bytes; public readonly List<string> Problems = new List<string>(); public string Manifest; }

        public static Result Export(FeedCache cache, string dir)
        {
            Result r = new Result(); Directory.CreateDirectory(dir); List<object> files = new List<object>();
            if (Directory.Exists(cache.Dir)) foreach (string f in Directory.GetFiles(cache.Dir, "*.json"))
            {
                string name = Path.GetFileName(f); if (string.Equals(name, ManifestName, StringComparison.OrdinalIgnoreCase)) continue;
                string dest = Path.Combine(dir, name); File.Copy(f, dest, true); File.SetLastWriteTimeUtc(dest, File.GetLastWriteTimeUtc(f));
                Dictionary<string, object> e = new Dictionary<string, object>(); long len = new FileInfo(f).Length; e["name"] = name; e["bytes"] = len; e["sha256"] = BundleCrypto.FileSha256(f); e["modifiedUtc"] = File.GetLastWriteTimeUtc(f); files.Add(e); r.Files++; r.Bytes += len;
            }
            Dictionary<string, object> m = new Dictionary<string, object>(); m["schema"] = Schema; m["exportedUtc"] = DateTime.UtcNow; m["from"] = Environment.MachineName; m["files"] = files;
            r.Manifest = Path.Combine(dir, ManifestName); File.WriteAllText(r.Manifest, JsonWrite.Text(m, true), new UTF8Encoding(false)); return r;
        }

        /// <summary>Copies the pack's files into the cache. verify: refuse a file whose SHA-256 differs from the manifest. Names must be plain *.json file names - nothing with a path in it is ever written.</summary>
        public static Result Import(string dir, FeedCache cache, bool verify)
        {
            Result r = new Result(); string mp = Path.Combine(dir, ManifestName); if (!File.Exists(mp)) throw new BundleException("not a feed pack: no " + ManifestName + " in " + dir);
            object m; try { m = Json.Parse(File.ReadAllText(mp, Encoding.UTF8)); } catch (Exception ex) { throw new BundleException("feed pack manifest: " + ex.Message); }
            string schema = Json.GetS(m, "schema") ?? ""; if (schema != Schema) throw new BundleException("feed pack schema '" + schema + "' is not " + Schema);
            List<object> list = Json.Get(m, "files") as List<object>; if (list == null) throw new BundleException("feed pack manifest: 'files' is missing or not a list - not a valid pack (PT-37)");
            if (list.Count == 0) throw new BundleException("feed pack manifest lists no files - an empty pack is not imported");
            Directory.CreateDirectory(cache.Dir);
            foreach (object e in list)
            {
                string name = Json.GetS(e, "name") ?? "";
                if (name.Length == 0 || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name.Contains("..") || !name.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || string.Equals(name, ManifestName, StringComparison.OrdinalIgnoreCase)) { r.Problems.Add("manifest names a file that is not a plain .json name: " + name); r.Skipped++; continue; }
                string src = Path.Combine(dir, name); if (!File.Exists(src)) { r.Problems.Add(name + ": listed in the manifest but missing"); r.Skipped++; continue; }
                if (verify) { string want = Json.GetS(e, "sha256") ?? "", have = BundleCrypto.FileSha256(src); if (!string.Equals(want, have, StringComparison.OrdinalIgnoreCase)) { r.Problems.Add(name + ": sha256 mismatch - not imported"); r.Skipped++; continue; } }
                // the time is checked before anything is copied: outside the FileTime range (before 1601) or in the future it is refused, not clamped -
                // a future copy would never age out and would stamp every enriched bundle with a date that has not happened (PT-35, PT-36)
                object modRaw = Json.Get(e, "modifiedUtc"); DateTime mod = File.GetLastWriteTimeUtc(src);
                if (modRaw != null)
                {
                    DateTime? parsed = modRaw is string ? JsonWrite.Date(modRaw) : null;
                    if (!parsed.HasValue) { r.Problems.Add(name + ": modifiedUtc is not an ISO-8601 date - not imported"); r.Skipped++; continue; }
                    if (parsed.Value < new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc) || parsed.Value > DateTime.UtcNow.AddDays(1)) { r.Problems.Add(name + ": modifiedUtc " + JsonWrite.Stamp(parsed.Value) + " is before 1601 or in the future - not imported"); r.Skipped++; continue; }
                    mod = parsed.Value;
                }
                string dest = Path.Combine(cache.Dir, name); File.Copy(src, dest, true); File.SetLastWriteTimeUtc(dest, mod);
                r.Files++; r.Bytes += new FileInfo(dest).Length;
            }
            if (r.Files == 0) r.Problems.Add("no files were imported - every entry was refused");
            r.Manifest = mp; return r;
        }

        /// <summary>What the cache holds, by feed, with the oldest and newest copy.</summary>
        public static List<string> Status(FeedCache cache)
        {
            List<string> l = new List<string>(); int msrc = 0, nvd = 0, epss = 0, kev = 0, other = 0; long bytes = 0; DateTime? oldest = null, newest = null;
            if (Directory.Exists(cache.Dir)) foreach (string f in Directory.GetFiles(cache.Dir, "*.json"))
            {
                string n = Path.GetFileName(f).ToLowerInvariant(); FileInfo fi = new FileInfo(f); bytes += fi.Length; DateTime w = fi.LastWriteTimeUtc; if (!oldest.HasValue || w < oldest.Value) oldest = w; if (!newest.HasValue || w > newest.Value) newest = w;
                if (n.StartsWith("msrc-")) msrc++; else if (n.StartsWith("nvd-")) nvd++; else if (n.StartsWith("epss-")) epss++; else if (n == "kev.json") kev++; else other++;
            }
            l.Add("feed cache   " + cache.Dir + (cache.Offline ? " (offline)" : ""));
            l.Add("files        " + (msrc + nvd + epss + kev + other) + " · " + Size(bytes) + " · MSRC " + msrc + " (releases list + monthly documents) · NVD " + nvd + " · EPSS " + epss + " · KEV " + kev + (other > 0 ? " · other " + other : ""));
            l.Add("copies from  " + (oldest.HasValue ? JsonWrite.Stamp(oldest.Value) + " to " + JsonWrite.Stamp(newest.Value) : "(empty)"));
            return l;
        }
        public static string Size(long b) { return b >= 1L << 30 ? (b / (double)(1L << 30)).ToString("N1") + " GB" : b >= 1 << 20 ? (b / (double)(1 << 20)).ToString("N1") + " MB" : b >= 1 << 10 ? (b / 1024.0).ToString("N0") + " KB" : b + " B"; }
    }
}
