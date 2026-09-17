// Dupes: find identical files. Group by size first (cheap), then confirm equal groups by hashing only the
// files that share a size - a partial hash of the first 64 KB, then a full SHA-256 only where the partial
// still collides. Reuses FastWalk. Each group knows its wasted space (every copy after the first).
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace PSTools
{
    public class DupeFile
    {
        public string Path = "", Name = "", Dir = ""; public long Size; public DateTime Modified; public string Group = ""; public bool Keep;
        public string Where { get { return Trust.Location(Path); } }
    }
    public class DupeGroup
    {
        public string Hash = ""; public long Size; public readonly List<DupeFile> Files = new List<DupeFile>();
        public int Count { get { return Files.Count; } }
        public long Wasted { get { return Size * (Files.Count - 1); } }
    }

    public class DupeScan
    {
        public IList<string> Roots = new List<string>(); public volatile bool Cancel;
        public long MinBytes = 1024; public bool SkipHidden = true;
        public long FilesSeen, Hashed; public string Current = ""; public string Phase = "";
        readonly FastWalk walk = new FastWalk();

        /// <summary>Run to completion (background). progress() is called periodically; returns the confirmed duplicate groups, largest wasted first.</summary>
        public List<DupeGroup> Run(Action progress)
        {
            walk.Roots = Roots;
            Dictionary<long, List<DupeFile>> bySize = new Dictionary<long, List<DupeFile>>();
            Phase = "scanning";
            walk.Run(delegate (FileInfo fi)
            {
                if (Cancel) { walk.Stop(); return; }
                Current = fi.FullName; FilesSeen++;
                try { if (fi.Length < MinBytes) return; if (SkipHidden && (fi.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0) return; } catch { return; }
                DupeFile d = new DupeFile(); d.Path = fi.FullName; d.Name = fi.Name; d.Dir = fi.DirectoryName ?? ""; d.Size = fi.Length; try { d.Modified = fi.LastWriteTime; } catch { }
                List<DupeFile> list; if (!bySize.TryGetValue(fi.Length, out list)) { list = new List<DupeFile>(); bySize[fi.Length] = list; } list.Add(d);
                if (progress != null && (FilesSeen & 1023) == 0) progress();
            });
            if (Cancel) return new List<DupeGroup>();

            // partial hash the size-collision groups, then full-hash the partial-collision groups
            Phase = "hashing";
            List<DupeGroup> groups = new List<DupeGroup>();
            foreach (KeyValuePair<long, List<DupeFile>> kv in bySize)
            {
                if (Cancel) break; if (kv.Value.Count < 2) continue;
                Dictionary<string, List<DupeFile>> byPartial = new Dictionary<string, List<DupeFile>>();
                foreach (DupeFile d in kv.Value) { if (Cancel) break; Current = d.Path; string ph = Hash(d.Path, 65536); if (ph == null) continue; List<DupeFile> pl; if (!byPartial.TryGetValue(ph, out pl)) { pl = new List<DupeFile>(); byPartial[ph] = pl; } pl.Add(d); if (progress != null && (Hashed & 255) == 0) progress(); }
                foreach (KeyValuePair<string, List<DupeFile>> pk in byPartial)
                {
                    if (Cancel) break; if (pk.Value.Count < 2) continue;
                    Dictionary<string, List<DupeFile>> byFull = new Dictionary<string, List<DupeFile>>();
                    foreach (DupeFile d in pk.Value) { if (Cancel) break; Current = d.Path; string fh = kv.Key <= 65536 ? pk.Key : Hash(d.Path, -1); if (fh == null) continue; List<DupeFile> fl; if (!byFull.TryGetValue(fh, out fl)) { fl = new List<DupeFile>(); byFull[fh] = fl; } fl.Add(d); if (progress != null) progress(); }
                    foreach (KeyValuePair<string, List<DupeFile>> fk in byFull)
                    {
                        if (fk.Value.Count < 2) continue;
                        DupeGroup g = new DupeGroup(); g.Hash = fk.Key; g.Size = kv.Key; g.Files.AddRange(fk.Value);
                        g.Files.Sort(delegate (DupeFile a, DupeFile b) { return a.Modified.CompareTo(b.Modified); });
                        for (int i = 0; i < g.Files.Count; i++) { g.Files[i].Group = fk.Key.Substring(0, 8); g.Files[i].Keep = i == 0; }
                        groups.Add(g);
                    }
                }
            }
            groups.Sort(delegate (DupeGroup a, DupeGroup b) { return b.Wasted.CompareTo(a.Wasted); });
            Phase = "done";
            return groups;
        }
        public void Stop() { Cancel = true; walk.Stop(); }
        public long DirsScanned { get { return walk.DirsScanned; } }

        string Hash(string path, int limit)
        {
            try
            {
                Hashed++;
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 65536))
                using (SHA256 sha = SHA256.Create())
                {
                    if (limit < 0) { byte[] full = sha.ComputeHash(fs); return Hex(full); }
                    byte[] buf = new byte[limit]; int read = fs.Read(buf, 0, limit); byte[] h = sha.ComputeHash(buf, 0, read); return Hex(h);
                }
            }
            catch { return null; }
        }
        static string Hex(byte[] b) { System.Text.StringBuilder sb = new System.Text.StringBuilder(b.Length * 2); foreach (byte x in b) sb.Append(x.ToString("x2")); return sb.ToString(); }
    }
}
