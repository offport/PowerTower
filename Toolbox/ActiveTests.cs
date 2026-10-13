// ActiveTests.cs - the two active checklist tests (EICAR drop, application-control policy read), moved out of
// Checklist.cs so PowerTowerCollect.exe never carries the EICAR builder or any test that writes to the host (PT-22).
// The passive ChecklistScan stays in Checklist.cs and is what the collector runs.
using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Threading;
using Microsoft.Win32;

namespace PSTools
{
    /// <summary>The two active tests: they deliberately drop test artifacts that antivirus and application-control
    /// react to. EICAR checks real-time malware detection; the execution test checks which writable folders let an
    /// unsigned program run. Every step is wrapped so a failure can never crash the app.</summary>
    public static class ActiveTests
    {
        // The EICAR standard anti-malware test string, XOR-encoded so this exe never contains the signature itself
        // (which would make antivirus quarantine the app). It is decoded only in memory, at run time.
        static readonly byte[] Enc = { 13, 96, 26, 116, 5, 112, 21, 20, 5, 14, 97, 9, 5, 15, 13, 96, 97, 125, 5, 11, 124, 98, 22, 22, 124, 98, 40, 113, 16, 28, 22, 20, 7, 120, 6, 1, 20, 27, 17, 20, 7, 17, 120, 20, 27, 1, 28, 3, 28, 7, 0, 6, 120, 1, 16, 6, 1, 120, 19, 28, 25, 16, 116, 113, 29, 126, 29, 127 };
        public static byte[] EicarBytes() { byte[] d = new byte[Enc.Length]; for (int i = 0; i < Enc.Length; i++) d[i] = (byte)(Enc[i] ^ 0x55); return d; }

        public static CheckItem Eicar()
        {
            const string C = "Active Tests"; byte[] data = EicarBytes();
            string dir = Path.Combine(Path.GetTempPath(), "pstools-avtest");
            string file = Path.Combine(dir, "avtest_" + Guid.NewGuid().ToString("N") + ".com");
            bool blockedWrite = false, present = false, readable = false; string ev = "";
            try
            {
                Directory.CreateDirectory(dir);
                try { File.WriteAllBytes(file, data); }
                catch (Exception wx) { blockedWrite = true; ev = "write blocked (" + wx.GetType().Name + ")"; }
                if (!blockedWrite)
                {
                    for (int i = 0; i < 25 && File.Exists(file); i++) Thread.Sleep(100); // give real-time protection a moment
                    present = File.Exists(file);
                    if (present) { try { byte[] b = File.ReadAllBytes(file); readable = b.Length == data.Length; } catch { readable = false; } }
                }
            }
            catch (Exception ex) { ev = ex.Message; }
            finally { try { if (File.Exists(file)) File.Delete(file); } catch { } try { Directory.Delete(dir, true); } catch { } }
            bool detected = blockedWrite || !present || !readable;
            string detail = blockedWrite ? "antivirus blocked writing the test file" : !present ? "antivirus removed the test file within a couple of seconds" : !readable ? "antivirus locked or quarantined the test file" : "the test file was written and stayed readable - real-time scanning did NOT detect it";
            return new CheckItem(C, "EICAR anti-malware detection", "Does real-time antivirus detect a standard test virus dropped on disk?", detected ? "pass" : "fail", detail, ev.Length > 0 ? ev : "harmless EICAR standard test file (MD5 44d88612...), written to %TEMP% then checked");
        }

        /// <summary>Which application-control policy governs execution — read entirely from policy (AppLocker / SRP / WDAC / SmartScreen).
        /// It NEVER drops or runs any program: an earlier version that did was flagged by Defender as malware-staging behaviour.</summary>
        public static List<CheckItem> AppControl(Action<string> progress)
        {
            const string C = "Active Tests"; List<CheckItem> outp = new List<CheckItem>(); bool control = false;
            if (progress != null) progress("reading application-control policy…");
            try
            {
                List<string> parts = new List<string>(); int rulesTotal = 0;
                using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                    foreach (string coll in new string[] { "Exe", "Msi", "Script", "Dll", "Appx" })
                        using (RegistryKey k = b.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\SrpV2\" + coll))
                            if (k != null) { int rules = 0; try { rules = k.GetSubKeyNames().Length; } catch { } object em = k.GetValue("EnforcementMode"); int mode = em == null ? -1 : Convert.ToInt32(em); if (rules > 0) { parts.Add(coll + "=" + (mode == 1 ? "enforce" : mode == 0 ? "audit" : "?") + " (" + rules + " rules)"); rulesTotal += rules; } }
                bool applocker = rulesTotal > 0; if (applocker) control = true;
                outp.Add(new CheckItem(C, "AppLocker", "Is AppLocker configured to control which programs run?", applocker ? "pass" : "warn", applocker ? "configured: " + string.Join(", ", parts.ToArray()) : "no AppLocker rules configured", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2"));
            }
            catch (Exception ex) { outp.Add(new CheckItem(C, "AppLocker", "", "na", "could not read", Short(ex.Message))); }
            try { int def = RegInt(@"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers", "DefaultLevel", -1); bool srp = def == 0; if (srp) control = true; outp.Add(new CheckItem(C, "Software Restriction Policies", "Is SRP enforcing a default-deny?", srp ? "pass" : "info", def == 0 ? "default level: disallowed (default-deny)" : def == 0x40000 ? "default level: unrestricted (allow all)" : "not configured", def < 0 ? "DefaultLevel absent" : "DefaultLevel=0x" + def.ToString("x"))); }
            catch (Exception ex) { outp.Add(new CheckItem(C, "Software Restriction Policies", "", "na", "could not read", Short(ex.Message))); }
            try { using (ManagementObjectSearcher q = new ManagementObjectSearcher(new ManagementScope(@"\\.\root\Microsoft\Windows\DeviceGuard"), new ObjectQuery("SELECT UsermodeCodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard"))) foreach (ManagementObject o in q.Get()) { int st = 0; try { st = Convert.ToInt32(o["UsermodeCodeIntegrityPolicyEnforcementStatus"]); } catch { } bool wdac = st >= 2; if (wdac) control = true; outp.Add(new CheckItem(C, "WDAC (code integrity)", "Is a Windows Defender Application Control policy enforced?", wdac ? "pass" : "info", st == 2 ? "user-mode code integrity: enforced" : st == 1 ? "audit only" : "not enforced", "Win32_DeviceGuard")); } } catch { }
            try { string ss = RegStr(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"); string pol = RegStr(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen"); bool off = ss == "Off" || pol == "0"; outp.Add(new CheckItem(C, "SmartScreen", "Does SmartScreen vet unknown/downloaded apps?", off ? "warn" : "info", off ? "SmartScreen is off" : "SmartScreen: " + (ss ?? (pol != null ? "policy " + pol : "on / default")), "")); } catch { }
            outp.Insert(0, new CheckItem(C, "Application control on writable folders", "Can an unsigned program run from any writable folder?", control ? "pass" : "warn", control ? "application control (AppLocker / SRP / WDAC) is enforced" : "no application control is enforced — an unsigned program can run from any writable folder (Temp, Downloads, ProgramData, the user profile…)", "read from policy only; nothing was executed or dropped"));
            return outp;
        }
        static int RegInt(string path, string name, int def) { try { using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) using (RegistryKey k = b.OpenSubKey(path)) { object v = k == null ? null : k.GetValue(name); return v == null ? def : Convert.ToInt32(v); } } catch { return def; } }
        static string RegStr(string path, string name) { try { using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) using (RegistryKey k = b.OpenSubKey(path)) { object v = k == null ? null : k.GetValue(name); return v == null ? null : Convert.ToString(v); } } catch { return null; } }
        static string Short(string s) { s = (s ?? "").Replace("\r", " ").Replace("\n", " "); return s.Length > 80 ? s.Substring(0, 80) + "…" : s; }
    }
}
