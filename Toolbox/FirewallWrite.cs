// FirewallWrite.cs - the mutating half of the blocker's Firewall class (Net.cs): creating, changing and removing the
// BLOCK-HOSTS rule. Left out of PowerTowerCollect.exe so the collector can read the rule but never change it (PT-22).
using System;
using System.Collections.Generic;

namespace PSTools
{
    public static partial class Firewall
    {
        /// <summary>Replaces the rule's address set; an empty set removes the rule. Needs administrator.</summary>
        public static void SetBlocked(IList<string> ips)
        {
            dynamic pol = Policy(); dynamic r = FindRule(pol);
            if (ips == null || ips.Count == 0) { if (r != null) pol.Rules.Remove(RuleName); return; }
            string joined = string.Join(",", ips);
            if (r != null) { r.RemoteAddresses = joined; return; }
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            rule.Name = RuleName; rule.Description = "Outbound block list managed by Block-Hosts / PowerTower";
            rule.Direction = 2;            // NET_FW_RULE_DIR_OUT
            rule.Action = 0;               // NET_FW_ACTION_BLOCK
            rule.Protocol = 256;           // any
            rule.Profiles = 0x7FFFFFFF;    // all
            rule.RemoteAddresses = joined; rule.Enabled = true;
            pol.Rules.Add(rule);
        }
    }
}
