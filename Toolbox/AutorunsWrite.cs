// AutorunsWrite.cs - the actions of Autoruns (Autoruns.cs): disable/enable and delete an autostart entry. Left out of
// PowerTowerCollect.exe so the collector can list persistence but never change it (PT-22).
using System;
using System.IO;
using System.Management;
using Microsoft.Win32;

namespace PSTools
{
    public static partial class Autoruns
    {
        // ── actions: return null on success, else the reason ──
        public static string SetEnabled(AutorunEntry e, bool on)
        {
            try
            {
                if (e.Handle is RegHandle)
                {
                    RegHandle h = (RegHandle)e.Handle; if (!e.Toggleable) return "this kind of entry can only be deleted";
                    using (RegistryKey b = RegistryKey.OpenBaseKey(h.Hive, h.View))
                    {
                        string from = on ? h.Key + "\\" + Disabled : h.Key, to = on ? h.Key : h.Key + "\\" + Disabled;
                        using (RegistryKey src = b.OpenSubKey(from, true)) using (RegistryKey dst = b.CreateSubKey(to))
                        {
                            if (src == null) return "entry not found"; object v = src.GetValue(h.Value); if (v == null) return "entry not found";
                            dst.SetValue(h.Value, v, src.GetValueKind(h.Value)); src.DeleteValue(h.Value);
                        }
                    }
                    h.InDisabled = !on; e.Enabled = on; e.Location = on ? e.Location.Replace("\\" + Disabled, "") : e.Location + "\\" + Disabled; return null;
                }
                if (e.Handle is FileHandle)
                {
                    FileHandle h = (FileHandle)e.Handle; string dir = Path.GetDirectoryName(h.Path); string target;
                    if (on) { if (!dir.EndsWith(Disabled, StringComparison.OrdinalIgnoreCase)) return "already enabled"; target = Path.Combine(Path.GetDirectoryName(dir), Path.GetFileName(h.Path)); }
                    else { string dd = Path.Combine(dir, Disabled); Directory.CreateDirectory(dd); target = Path.Combine(dd, Path.GetFileName(h.Path)); }
                    File.Move(h.Path, target); h.Path = target; e.Enabled = on; e.Location = Path.GetDirectoryName(target); if (!e.Command.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) || e.Command == h.Path) { } return null;
                }
                if (e.Handle is TaskHandle)
                {
                    TaskHandle h = (TaskHandle)e.Handle; object svc = Com.Create("Schedule.Service"); Com.Call(svc, "Connect", Type.Missing, Type.Missing, Type.Missing, Type.Missing);
                    string folder = h.Path.Substring(0, Math.Max(1, h.Path.LastIndexOf('\\'))); string name = h.Path.Substring(h.Path.LastIndexOf('\\') + 1);
                    object f = Com.Call(svc, "GetFolder", folder); object t = Com.Call(f, "GetTask", name); Com.Set(t, "Enabled", on); e.Enabled = on; return null;
                }
                if (e.Handle is ServiceHandle)
                {
                    ServiceHandle h = (ServiceHandle)e.Handle; string key = @"SYSTEM\CurrentControlSet\Services\" + h.Name;
                    using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) using (RegistryKey k = b.OpenSubKey(key, true))
                    {
                        if (k == null) return "service key not found";
                        if (on) { object prev = k.GetValue("PSToolsPrevStart"); k.SetValue("Start", prev == null ? 3 : Convert.ToInt32(prev), RegistryValueKind.DWord); try { k.DeleteValue("PSToolsPrevStart"); } catch { } }
                        else { object cur = k.GetValue("Start"); if (cur != null) k.SetValue("PSToolsPrevStart", Convert.ToInt32(cur), RegistryValueKind.DWord); k.SetValue("Start", 4, RegistryValueKind.DWord); }
                    }
                    e.Enabled = on; return null;
                }
                return "this kind of entry cannot be toggled";
            }
            catch (Exception ex) { return ex.Message; }
        }
        public static string Delete(AutorunEntry e)
        {
            try
            {
                if (!e.Removable) return "this entry is protected";
                if (e.Handle is RegHandle)
                {
                    RegHandle h = (RegHandle)e.Handle;
                    using (RegistryKey b = RegistryKey.OpenBaseKey(h.Hive, h.View)) using (RegistryKey k = b.OpenSubKey(h.InDisabled ? h.Key + "\\" + Disabled : h.Key, true)) { if (k == null) return "entry not found"; k.DeleteValue(h.Value, false); }
                    return null;
                }
                if (e.Handle is FileHandle) { File.Delete(((FileHandle)e.Handle).Path); return null; }
                if (e.Handle is TaskHandle)
                {
                    TaskHandle h = (TaskHandle)e.Handle; object svc = Com.Create("Schedule.Service"); Com.Call(svc, "Connect", Type.Missing, Type.Missing, Type.Missing, Type.Missing);
                    string folder = h.Path.Substring(0, Math.Max(1, h.Path.LastIndexOf('\\'))); string name = h.Path.Substring(h.Path.LastIndexOf('\\') + 1);
                    object f = Com.Call(svc, "GetFolder", folder); Com.Call(f, "DeleteTask", name, 0); return null;
                }
                if (e.Handle is ServiceHandle)
                {
                    ServiceHandle h = (ServiceHandle)e.Handle;
                    using (ManagementObject o = new ManagementObject("Win32_Service.Name='" + h.Name.Replace("'", "\\'") + "'")) { object r = o.InvokeMethod("Delete", null); int rc = Convert.ToInt32(r); if (rc != 0) return "service delete returned " + rc + (rc == 2 ? " (access denied)" : rc == 1 ? " (not supported)" : ""); }
                    return null;
                }
                if (e.Handle is WmiHandle)
                {
                    WmiHandle h = (WmiHandle)e.Handle; ManagementScope scope = new ManagementScope(@"\\.\root\subscription"); scope.Connect();
                    if (h.Binding != null) { using (ManagementObject o = new ManagementObject(scope, new ManagementPath(h.Binding), null)) o.Delete(); }
                    foreach (string cls in new string[] { "CommandLineEventConsumer", "ActiveScriptEventConsumer" }) { try { using (ManagementObjectSearcher q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM " + cls + " WHERE Name='" + h.Consumer.Replace("'", "\\'") + "'"))) foreach (ManagementObject o in q.Get()) o.Delete(); } catch { } }
                    if (h.Filter != null) { try { using (ManagementObjectSearcher q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __EventFilter WHERE Name='" + h.Filter.Replace("'", "\\'") + "'"))) foreach (ManagementObject o in q.Get()) o.Delete(); } catch { } }
                    return null;
                }
                return "this kind of entry cannot be deleted here";
            }
            catch (Exception ex) { return ex.Message; }
        }
    }
}
