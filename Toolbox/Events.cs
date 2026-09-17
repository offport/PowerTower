// Events: the Windows event-log records that matter for an incident - logons and failures, new services and
// tasks, PowerShell script blocks, Defender detections, process creation, log clears, user changes - pulled
// with EventLogReader over a time range, with the useful fields parsed out of each event.
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;

namespace PSTools
{
    public class EventRow
    {
        public DateTime Time; public int Id; public string Log = "", Source = "", Level = "", Category = "", Who = "", Detail = "", Computer = ""; public string Risk = "";
        public string When { get { return Time == DateTime.MinValue ? "" : Time.ToString("yyyy-MM-dd HH:mm:ss"); } }
    }

    /// <summary>One kind of event to hunt for: which log, which IDs, a friendly category, a risk tint, and a parser for the fields.</summary>
    public class EventSpec
    {
        public string Category, Log; public int[] Ids; public string Risk; public Func<EventRecord, string[], string[]> Parse; // returns {who, detail}
        public EventSpec(string cat, string log, int[] ids, string risk, Func<EventRecord, string[], string[]> parse) { Category = cat; Log = log; Ids = ids; Risk = risk; Parse = parse; }
    }

    public static class EventHunt
    {
        static string P(string[] props, int i) { return props != null && i >= 0 && i < props.Length && props[i] != null ? props[i].ToString() : ""; }
        static readonly Regex Ws = new Regex(@"\s+");
        static string Clean(string s) { return Ws.Replace((s ?? "").Replace("\r", " ").Replace("\n", " "), " ").Trim(); }

        public static readonly List<EventSpec> Specs = new List<EventSpec>(new EventSpec[] {
            new EventSpec("Failed logon", "Security", new int[]{4625}, "high", delegate(EventRecord e, string[] p){ return new string[]{ P(p,5)+(P(p,6).Length>0?"\\"+P(p,6):""), "from "+P(p,19)+(P(p,11).Length>0?" ("+P(p,11)+")":"")+" · logon type "+P(p,10)+" · status "+P(p,7) }; }),
            new EventSpec("Successful logon", "Security", new int[]{4624}, "", delegate(EventRecord e, string[] p){ string who=P(p,5)+(P(p,6).Length>0?"\\"+P(p,6):""); return new string[]{ who, "logon type "+P(p,8)+" from "+P(p,18)+(P(p,11).Length>0?" ("+P(p,11)+")":"") }; }),
            new EventSpec("Explicit-credential logon", "Security", new int[]{4648}, "", delegate(EventRecord e, string[] p){ return new string[]{ P(p,1)+"\\"+P(p,2), "ran as "+P(p,5)+"\\"+P(p,6)+" · target "+P(p,8)+" · "+P(p,11) }; }),
            new EventSpec("Account lockout", "Security", new int[]{4740}, "high", delegate(EventRecord e, string[] p){ return new string[]{ P(p,0), "locked out from "+P(p,1) }; }),
            new EventSpec("Special-privilege logon", "Security", new int[]{4672}, "", delegate(EventRecord e, string[] p){ return new string[]{ P(p,1)+"\\"+P(p,2), "admin-equivalent privileges assigned" }; }),
            new EventSpec("User account created", "Security", new int[]{4720}, "high", delegate(EventRecord e, string[] p){ return new string[]{ P(p,0), "created by "+P(p,4)+"\\"+P(p,5) }; }),
            new EventSpec("Added to group", "Security", new int[]{4728,4732,4756}, "high", delegate(EventRecord e, string[] p){ return new string[]{ P(p,0), "added to group "+P(p,2)+" by "+P(p,6)+"\\"+P(p,7) }; }),
            new EventSpec("User account enabled", "Security", new int[]{4722}, "medium", delegate(EventRecord e, string[] p){ return new string[]{ P(p,0), "enabled by "+P(p,4)+"\\"+P(p,5) }; }),
            new EventSpec("Password reset", "Security", new int[]{4724}, "medium", delegate(EventRecord e, string[] p){ return new string[]{ P(p,0), "password reset by "+P(p,4)+"\\"+P(p,5) }; }),
            new EventSpec("Audit log cleared", "Security", new int[]{1102}, "high", delegate(EventRecord e, string[] p){ return new string[]{ P(p,1)+"\\"+P(p,2), "the security audit log was cleared" }; }),
            new EventSpec("Process created", "Security", new int[]{4688}, "", delegate(EventRecord e, string[] p){ return new string[]{ P(p,1)+"\\"+P(p,2), Clean(P(p,8))+(P(p,13).Length>0?"  ← "+P(p,13):"") }; }),
            new EventSpec("New service (Security)", "Security", new int[]{4697}, "medium", delegate(EventRecord e, string[] p){ return new string[]{ P(p,1)+"\\"+P(p,2), "service "+P(p,4)+" → "+Clean(P(p,5)) }; }),
            new EventSpec("Scheduled task created", "Security", new int[]{4698}, "medium", delegate(EventRecord e, string[] p){ return new string[]{ P(p,1)+"\\"+P(p,2), "task "+P(p,4) }; }),
            new EventSpec("New service (System)", "System", new int[]{7045}, "medium", delegate(EventRecord e, string[] p){ return new string[]{ "", "service "+P(p,0)+" → "+Clean(P(p,1))+" · start "+P(p,3) }; }),
            new EventSpec("Service start failed", "System", new int[]{7000,7009,7023,7034}, "", delegate(EventRecord e, string[] p){ return new string[]{ "", Clean(desc(e)) }; }),
            new EventSpec("Unexpected shutdown", "System", new int[]{6008}, "", delegate(EventRecord e, string[] p){ return new string[]{ "", Clean(desc(e)) }; }),
            new EventSpec("PowerShell script block", "Microsoft-Windows-PowerShell/Operational", new int[]{4104}, "medium", delegate(EventRecord e, string[] p){ string t=Clean(P(p,2)); return new string[]{ "", t.Length>0?t:Clean(desc(e)) }; }),
            new EventSpec("WMI activity", "Microsoft-Windows-WMI-Activity/Operational", new int[]{5857,5860,5861}, "medium", delegate(EventRecord e, string[] p){ return new string[]{ "", Clean(desc(e)) }; }),
            new EventSpec("Defender detection", "Microsoft-Windows-Windows Defender/Operational", new int[]{1006,1007,1015,1116,1117}, "high", delegate(EventRecord e, string[] p){ return new string[]{ "", Clean(desc(e)) }; }),
            new EventSpec("Defender action", "Microsoft-Windows-Windows Defender/Operational", new int[]{1008,1009,1118,1119}, "medium", delegate(EventRecord e, string[] p){ return new string[]{ "", Clean(desc(e)) }; }),
            new EventSpec("RDP session", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", new int[]{21,22,25}, "", delegate(EventRecord e, string[] p){ return new string[]{ "", Clean(desc(e)) }; }),
        });
        static string desc(EventRecord e) { try { return e.FormatDescription() ?? ""; } catch { return ""; } }

        public static List<string> Categories() { List<string> l = new List<string>(); foreach (EventSpec s in Specs) if (!l.Contains(s.Category)) l.Add(s.Category); return l; }

        /// <summary>Read the chosen categories over [since, now], newest first, at most maxPer per category. progress(category). Unreadable logs (need admin) are reported through note.</summary>
        public static List<EventRow> Collect(IEnumerable<EventSpec> specs, DateTime since, int maxPer, Action<string> progress, Func<bool> cancelled, Action<string> note)
        {
            List<EventRow> rows = new List<EventRow>();
            string sinceIso = since.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.000Z");
            foreach (EventSpec spec in specs)
            {
                if (cancelled != null && cancelled()) break;
                if (progress != null) progress(spec.Category);
                string ids = ""; foreach (int id in spec.Ids) ids += (ids.Length > 0 ? " or " : "") + "EventID=" + id;
                string xpath = "*[System[(" + ids + ") and TimeCreated[@SystemTime>='" + sinceIso + "']]]";
                try
                {
                    EventLogQuery q = new EventLogQuery(spec.Log, PathType.LogName, xpath); q.ReverseDirection = true;
                    using (EventLogReader r = new EventLogReader(q))
                    {
                        int n = 0; EventRecord e;
                        while (n < maxPer && (e = SafeRead(r)) != null)
                        {
                            using (e)
                            {
                                n++; EventRow row = new EventRow(); row.Time = e.TimeCreated.HasValue ? e.TimeCreated.Value : DateTime.MinValue; row.Id = e.Id; row.Log = spec.Log; row.Category = spec.Category; row.Risk = spec.Risk;
                                try { row.Source = e.ProviderName ?? ""; } catch { } try { row.Computer = e.MachineName ?? ""; } catch { }
                                try { row.Level = LevelName(e.Level); } catch { }
                                string[] props = null; try { List<string> pv = new List<string>(); if (e.Properties != null) foreach (EventProperty pp in e.Properties) pv.Add(pp.Value == null ? "" : pp.Value.ToString()); props = pv.ToArray(); } catch { }
                                try { string[] wd = spec.Parse(e, props); row.Who = Clean(wd[0]); row.Detail = wd[1]; } catch { row.Detail = Clean(desc(e)); }
                                if (row.Detail.Length == 0) row.Detail = Clean(desc(e)); if (row.Detail.Length > 400) row.Detail = row.Detail.Substring(0, 400) + "…";
                                rows.Add(row);
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { if (note != null) note(spec.Category + ": needs administrator rights (" + spec.Log + ")"); }
                catch (EventLogNotFoundException) { }
                catch (EventLogException ex) { if (note != null) note(spec.Category + ": " + Clean(ex.Message)); }
                catch (Exception ex) { if (note != null) note(spec.Category + ": " + Clean(ex.Message)); }
            }
            rows.Sort(delegate (EventRow a, EventRow b) { return b.Time.CompareTo(a.Time); });
            return rows;
        }
        static EventRecord SafeRead(EventLogReader r) { try { return r.ReadEvent(); } catch { return null; } }
        static string LevelName(byte? lvl) { if (!lvl.HasValue) return ""; switch (lvl.Value) { case 1: return "critical"; case 2: return "error"; case 3: return "warning"; case 4: return "information"; case 5: return "verbose"; case 0: return "information"; default: return lvl.Value.ToString(); } }
    }
}
