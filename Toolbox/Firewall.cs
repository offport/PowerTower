// Firewall: read every Windows Firewall rule through the INetFwPolicy2 COM object, flag the risky ones
// (inbound Allow from Any remote address, all-ports or program-less rules on the public profile), and read
// each profile's on/off + default inbound action. Reuses the Com late-binding helper from Vuln.cs.
using System;
using System.Collections.Generic;

namespace PSTools
{
    public class FwRule
    {
        public string Name = "", Group = "", Direction = "", Action = "", Program = "", Service = "", Protocol = "", LocalPorts = "", RemotePorts = "", RemoteAddresses = "", Profiles = ""; public bool Enabled;
        public string Risk = ""; public string RiskWhy = "";
        public bool Inbound { get { return Direction == "in"; } }
        public bool Allow { get { return Action == "allow"; } }
    }
    public class FwProfile { public string Name = ""; public bool On; public string DefaultInbound = "", DefaultOutbound = ""; public bool NotifyOnBlock; }

    public static class WinFirewall
    {
        const int IN = 1, OUT = 2, ALLOW = 1, BLOCK = 0;
        static string Dir(object v) { try { return Convert.ToInt32(v) == OUT ? "out" : "in"; } catch { return "in"; } }
        static string Act(object v) { try { return Convert.ToInt32(v) == ALLOW ? "allow" : "block"; } catch { return "block"; } }
        static string Proto(object v)
        {
            try { int p = Convert.ToInt32(v); switch (p) { case 6: return "TCP"; case 17: return "UDP"; case 1: return "ICMPv4"; case 58: return "ICMPv6"; case 256: return "any"; default: return p.ToString(); } } catch { return "any"; }
        }
        static string Profiles(object v)
        {
            try { int p = Convert.ToInt32(v); if (p == 0x7fffffff) return "all"; List<string> l = new List<string>(); if ((p & 1) != 0) l.Add("domain"); if ((p & 2) != 0) l.Add("private"); if ((p & 4) != 0) l.Add("public"); return l.Count == 0 ? "all" : string.Join(", ", l.ToArray()); } catch { return "all"; }
        }

        public static List<FwProfile> ReadProfiles(out string note)
        {
            note = ""; List<FwProfile> l = new List<FwProfile>();
            try
            {
                object policy = Com.Create("HNetCfg.FwPolicy2");
                foreach (int t in new int[] { 1, 2, 4 })
                {
                    FwProfile p = new FwProfile(); p.Name = t == 1 ? "Domain" : t == 2 ? "Private" : "Public";
                    try { p.On = Convert.ToBoolean(Com.Prop(policy, "FirewallEnabled", t)); } catch { }
                    try { p.DefaultInbound = Act(Com.Prop(policy, "DefaultInboundAction", t)) == "allow" ? "allow" : "block"; } catch { }
                    try { p.DefaultOutbound = Act(Com.Prop(policy, "DefaultOutboundAction", t)) == "allow" ? "allow" : "block"; } catch { }
                    try { p.NotifyOnBlock = Convert.ToBoolean(Com.Prop(policy, "NotificationsDisabled", t)) == false; } catch { }
                    l.Add(p);
                }
            }
            catch (Exception ex) { note = ex.Message; }
            return l;
        }

        public static List<FwRule> ReadRules(out string note)
        {
            note = ""; List<FwRule> outp = new List<FwRule>();
            object policy; try { policy = Com.Create("HNetCfg.FwPolicy2"); } catch (Exception ex) { note = ex.Message; return outp; }
            object rules; try { rules = Com.Prop(policy, "Rules"); } catch (Exception ex) { note = ex.Message; return outp; }
            System.Collections.IEnumerable en = rules as System.Collections.IEnumerable; if (en == null) { note = "the firewall rule collection could not be read"; return outp; }
            foreach (object r in en)
            {
                try
                {
                    FwRule f = new FwRule();
                    f.Name = Com.S(r, "Name"); f.Group = Com.S(r, "Grouping"); f.Direction = Dir(Com.Prop(r, "Direction")); f.Action = Act(Com.Prop(r, "Action"));
                    try { f.Enabled = Convert.ToBoolean(Com.Prop(r, "Enabled")); } catch { }
                    f.Program = Com.S(r, "ApplicationName"); f.Service = Com.S(r, "serviceName"); f.Protocol = Proto(Com.Prop(r, "Protocol"));
                    f.LocalPorts = Com.S(r, "LocalPorts"); f.RemotePorts = Com.S(r, "RemotePorts"); f.RemoteAddresses = Com.S(r, "RemoteAddresses"); f.Profiles = Profiles(Com.Prop(r, "Profiles"));
                    Assess(f); outp.Add(f);
                }
                catch { }
            }
            outp.Sort(delegate (FwRule a, FwRule b) { int ra = Rank(a.Risk), rb = Rank(b.Risk); if (ra != rb) return ra - rb; return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); });
            return outp;
        }
        static int Rank(string r) { return r == "high" ? 0 : r == "medium" ? 1 : r == "low" ? 2 : 3; }

        static bool AnyRemote(string addr) { string a = (addr ?? "").Trim(); return a.Length == 0 || a == "*" || a.Equals("Any", StringComparison.OrdinalIgnoreCase); }
        static void Assess(FwRule f)
        {
            if (!f.Enabled || !f.Inbound || !f.Allow) return;
            bool anyRemote = AnyRemote(f.RemoteAddresses); bool allPorts = (f.LocalPorts ?? "").Trim().Length == 0 || f.LocalPorts == "*" || f.LocalPorts.Equals("Any", StringComparison.OrdinalIgnoreCase);
            bool noProgram = (f.Program ?? "").Trim().Length == 0 && (f.Service ?? "").Trim().Length == 0;
            bool publicProfile = f.Profiles == "all" || f.Profiles.Contains("public");
            List<string> why = new List<string>();
            if (anyRemote && allPorts && noProgram) { f.Risk = "high"; why.Add("allows any inbound connection from any address to any port, not tied to a program"); }
            else if (anyRemote && allPorts) { f.Risk = publicProfile ? "high" : "medium"; why.Add("opens all ports to any remote address"); }
            else if (anyRemote && noProgram) { f.Risk = "medium"; why.Add("allows inbound from any address, not tied to a program"); }
            else if (anyRemote && publicProfile) { f.Risk = "low"; why.Add("inbound from any address on the public profile"); }
            if (publicProfile && f.Risk == "") { } // an allow rule on public but scoped - leave unflagged
            if (f.Risk != "") f.RiskWhy = string.Join("; ", why.ToArray()) + (publicProfile ? " (public profile)" : "");
        }
    }
}
