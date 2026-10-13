// HostsWrite.cs - the mutating half of Hosts (Net.cs): backup, write, add, remove, restore. Kept in its own file so
// PowerTowerCollect.exe, which is built without it, cannot touch the hosts file by construction (QA finding PT-22).
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace PSTools
{
    public partial class Hosts
    {
        public void Write(IList<string> lines) { File.WriteAllLines(Path, lines, Encoding.ASCII); }
        public string Backup()
        {
            Directory.CreateDirectory(BackupDir);
            string dest = System.IO.Path.Combine(BackupDir, "hosts-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".bak");
            if (File.Exists(Path)) File.Copy(Path, dest, true); else File.WriteAllText(dest, "");
            return dest;
        }

        public class AddResult { public int Added, Skipped; public string Backup; public List<string> AddedHosts = new List<string>(); }
        public AddResult Add(IEnumerable<string> domains, string sink)
        {
            AddResult r = new AddResult(); r.Backup = Backup();
            List<string> lines = new List<string>(Read());
            HashSet<string> present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string l in lines) foreach (string tok in Regex.Split(l, @"\s+")) if (tok.Length > 0 && !tok.StartsWith("#") && !char.IsDigit(tok[0])) present.Add(tok);
            List<string> append = new List<string>();
            foreach (string d in domains)
            {
                if (present.Contains(d)) { r.Skipped++; continue; }
                append.Add(sink + "\t" + d + "\t" + Marker); r.AddedHosts.Add(d); present.Add(d); r.Added++;
            }
            if (append.Count > 0)
            {
                if (lines.Count > 0 && lines[lines.Count - 1].Trim().Length > 0) lines.Add("");
                lines.Add("# added by Block-Hosts " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
                lines.AddRange(append);
                Write(lines);
            }
            return r;
        }
        public class RemoveResult { public int Removed; public string Backup; }
        /// <summary>Drops only lines carrying the marker whose host is in the set. Hand-written lines are never touched.</summary>
        public RemoveResult Remove(IEnumerable<string> hosts)
        {
            RemoveResult r = new RemoveResult(); HashSet<string> set = new HashSet<string>(hosts, StringComparer.OrdinalIgnoreCase);
            r.Backup = Backup();
            List<string> kept = new List<string>();
            foreach (string l in Read())
            {
                if (Regex.IsMatch(l, Regex.Escape(Marker) + @"\s*$"))
                {
                    string[] parts = Regex.Split(Regex.Replace(l, Regex.Escape(Marker), "").Trim(), @"\s+");
                    if (parts.Length >= 2 && set.Contains(parts[1])) { r.Removed++; continue; }
                }
                kept.Add(l);
            }
            Write(kept);
            return r;
        }
        public string Restore(string backupFile) { string safety = Backup(); File.Copy(backupFile, Path, true); return safety; }
    }
}
