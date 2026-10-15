// RemoteTransport.cs - Transport A (SMB + WMI), the real agentless transport. Compiled into PowerTowerCli.exe
// ONLY (not Tests.exe, not PowerTowerCollect.exe, not SHARED): it touches the network, so the tests use
// FakeTransport instead. In-box only - WNetAddConnection2 (mpr.dll) for an authenticated ADMIN$ session, file
// copy over \\host\ADMIN$\Temp\pt-<id>\, and Win32_Process.Create/Terminate via System.Management over DCOM for
// remote execution. Transport B (WinRM/CIM) is a stub in this pass.
using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace PSTools
{
    /// <summary>SMB + WMI. The controller only ever calls through ITransport; this class owns the P/Invoke and WMI.</summary>
    public class SmbWmiTransport : ITransport
    {
        string host, stageUnc, stageLocal, connectedUnc; readonly int connectTimeoutMs;
        public SmbWmiTransport(int connectTimeoutMs) { this.connectTimeoutMs = connectTimeoutMs > 0 ? connectTimeoutMs : 4000; }

        public Preflight Preflight()
        {
            Preflight p = new Preflight();
            p.Smb445 = TcpOpen(445); p.Rpc135 = TcpOpen(135); p.WinRm5985 = TcpOpen(5985);
            return p;
        }
        public void SetHost(string h) { host = h; }   // the factory sets this before Preflight
        bool TcpOpen(int port)
        {
            try { using (TcpClient c = new TcpClient()) { IAsyncResult ar = c.BeginConnect(host, port, null, null); if (!ar.AsyncWaitHandle.WaitOne(connectTimeoutMs)) return false; c.EndConnect(ar); return true; } }
            catch { return false; }
        }

        public void Connect(string host, NetworkCred cred, string stageDirName)
        {
            this.host = host;
            connectedUnc = "\\\\" + host + "\\ADMIN$";
            NETRESOURCE nr = new NETRESOURCE(); nr.dwType = RESOURCETYPE_DISK; nr.lpRemoteName = connectedUnc;
            // one attempt, no retry - a wrong password must not loop and lock the account
            int rc = WNetAddConnection2(ref nr, cred.SecretUtf8(), cred.User, 0);
            if (rc == ERROR_LOGON_FAILURE || rc == ERROR_ACCESS_DENIED_LOGON || rc == ERROR_SESSION_CREDENTIAL_CONFLICT)
                throw new TransportException(PtStage.Connect, "LOGON_FAILURE", "WNetAddConnection2 rc=" + rc);
            if (rc == ERROR_BAD_NETPATH || rc == ERROR_BAD_NET_NAME)
                throw new TransportException(PtStage.Connect, "ADMIN_SHARE", "ADMIN$ not found (rc=" + rc + ")");
            if (rc == ERROR_ACCESS_DENIED)
                throw new TransportException(PtStage.Connect, "TOKEN_FILTER", "ADMIN$ access denied after logon (rc=5)");
            if (rc != 0) throw new TransportException(PtStage.Connect, "CONNECT", "WNetAddConnection2 rc=" + rc);
            stageUnc = connectedUnc + "\\Temp\\" + stageDirName;
            stageLocal = "%SystemRoot%\\Temp\\" + stageDirName;   // the path as the remote process sees it
            try { Directory.CreateDirectory(stageUnc); }
            catch (UnauthorizedAccessException) { throw new TransportException(PtStage.Connect, "TOKEN_FILTER", "cannot create the staging dir under ADMIN$ - filtered token (UAC remote restriction)"); }
            catch (Exception ex) { throw new TransportException(PtStage.Stage, "STAGE", ex.Message); }
        }

        public void Copy(byte[] data, string remoteName)
        {
            try { File.WriteAllBytes(Path.Combine(stageUnc, remoteName), data); }
            catch (Exception ex) { throw new TransportException(PtStage.Stage, "STAGE", ex.Message); }
        }

        public int Exec(string remoteExeName, string args)
        {
            // run the staged exe in its own dir; redirect streams to files we can fetch, so nothing goes to a console
            string cmd = "cmd.exe /c \"cd /d \"" + stageLocal + "\" && \"" + stageLocal + "\\" + remoteExeName + "\" " + args + " --out \"" + stageLocal + "\\bundle.ptb\" > \"" + stageLocal + "\\stdout.txt\" 2> \"" + stageLocal + "\\stderr.txt\"\"";
            try
            {
                ManagementScope scope = WmiScope();
                using (ManagementClass pc = new ManagementClass(scope, new ManagementPath("Win32_Process"), null))
                {
                    ManagementBaseObject inParams = pc.GetMethodParameters("Create");
                    inParams["CommandLine"] = cmd; inParams["CurrentDirectory"] = null;
                    ManagementBaseObject outParams = pc.InvokeMethod("Create", inParams, null);
                    uint rc = (uint)outParams["ReturnValue"];
                    if (rc != 0) throw new TransportException(PtStage.Exec, rc == 2 ? "EXE_GONE" : "EXEC", "Win32_Process.Create returned " + rc);
                    return Convert.ToInt32(outParams["ProcessId"]);
                }
            }
            catch (TransportException) { throw; }
            catch (ManagementException ex) { throw new TransportException(PtStage.Exec, "EXEC", ex.Message); }
            catch (UnauthorizedAccessException) { throw new TransportException(PtStage.Exec, "TOKEN_FILTER", "DCOM access denied - filtered token or WMI-In firewall rule"); }
        }

        public ExecResult Wait(int handle, int timeoutMs)
        {
            ExecResult r = new ExecResult(); DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            ManagementScope scope;
            try { scope = WmiScope(); } catch (Exception ex) { throw new TransportException(PtStage.Exec, "EXEC", ex.Message); }
            while (DateTime.UtcNow < deadline)
            {
                bool alive;
                try { alive = ProcessAlive(scope, handle); }
                catch (COMException) { r.SessionLost = true; return r; }
                catch (UnauthorizedAccessException) { r.SessionLost = true; return r; }
                if (!alive) { r.Exited = true; return r; }
                Thread.Sleep(2000);
            }
            try { Terminate(scope, handle); } catch { }
            r.TimedOut = true; return r;
        }
        bool ProcessAlive(ManagementScope scope, int pid)
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT ProcessId FROM Win32_Process WHERE ProcessId=" + pid)))
            using (ManagementObjectCollection c = s.Get()) { foreach (ManagementBaseObject o in c) { o.Dispose(); return true; } return false; }
        }
        void Terminate(ManagementScope scope, int pid)
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM Win32_Process WHERE ProcessId=" + pid)))
            using (ManagementObjectCollection c = s.Get()) foreach (ManagementObject o in c) { o.InvokeMethod("Terminate", new object[] { (uint)1 }); o.Dispose(); }
        }

        public byte[] Fetch(string remoteName)
        {
            try { string p = Path.Combine(stageUnc, remoteName); return File.Exists(p) ? File.ReadAllBytes(p) : null; }
            catch { return null; }
        }
        public void Delete()
        {
            try { if (Directory.Exists(stageUnc)) Directory.Delete(stageUnc, true); }
            catch (Exception ex) { throw new TransportException(PtStage.Clean, "CLEAN", ex.Message); }
        }
        public bool Exists() { try { return Directory.Exists(stageUnc); } catch { return true; } }
        public List<StagedDir> Sweep(string prefix, int maxAgeMs)
        {
            List<StagedDir> l = new List<StagedDir>();
            try
            {
                string tempUnc = connectedUnc + "\\Temp"; if (!Directory.Exists(tempUnc)) return l;
                foreach (string d in Directory.GetDirectories(tempUnc, prefix + "*"))
                {
                    DateTime w = Directory.GetLastWriteTimeUtc(d);
                    if ((DateTime.UtcNow - w).TotalMilliseconds > maxAgeMs && d != stageUnc) { try { Directory.Delete(d, true); l.Add(new StagedDir { Name = Path.GetFileName(d), WhenUtc = w }); } catch { } }
                }
            }
            catch { }
            return l;
        }
        public void Close()
        {
            try { if (connectedUnc != null) WNetCancelConnection2(connectedUnc, 0, true); } catch { }
            connectedUnc = null;
        }
        ManagementScope WmiScope()
        {
            // the ADMIN$ session already authenticated us to the host; WMI uses the same logon (no creds on the scope)
            ConnectionOptions co = new ConnectionOptions(); co.Impersonation = ImpersonationLevel.Impersonate; co.EnablePrivileges = true; co.Timeout = TimeSpan.FromSeconds(30);
            ManagementScope scope = new ManagementScope("\\\\" + host + "\\root\\cimv2", co); scope.Connect(); return scope;
        }

        // ── mpr.dll ──
        [StructLayout(LayoutKind.Sequential)]
        struct NETRESOURCE { public int dwScope, dwType, dwDisplayType, dwUsage; public string lpLocalName, lpRemoteName, lpComment, lpProvider; }
        const int RESOURCETYPE_DISK = 1;
        const int ERROR_ACCESS_DENIED = 5, ERROR_LOGON_FAILURE = 1326, ERROR_ACCESS_DENIED_LOGON = 1327, ERROR_SESSION_CREDENTIAL_CONFLICT = 1219, ERROR_BAD_NETPATH = 53, ERROR_BAD_NET_NAME = 67;
        [DllImport("mpr.dll")] static extern int WNetAddConnection2(ref NETRESOURCE nr, string password, string username, int flags);
        [DllImport("mpr.dll")] static extern int WNetCancelConnection2(string name, int flags, bool force);
    }

    /// <summary>Transport B (WinRM/CIM over WS-Man). Out of this pass - a stub so the shape exists and the CLI can
    /// name it. Needs a Phase-0 spike on Microsoft.Management.Infrastructure availability before it is built.</summary>
    public class WinRmTransport : ITransport
    {
        public Preflight Preflight() { throw new NotSupportedException("Transport B (WinRM/CIM) is not built in this release - use the default SMB+WMI transport."); }
        public void Connect(string host, NetworkCred cred, string stageDirName) { throw new NotSupportedException("Transport B (WinRM/CIM) is not built in this release."); }
        public void Copy(byte[] data, string remoteName) { throw new NotSupportedException(); }
        public int Exec(string remoteExeName, string args) { throw new NotSupportedException(); }
        public ExecResult Wait(int handle, int timeoutMs) { throw new NotSupportedException(); }
        public byte[] Fetch(string remoteName) { throw new NotSupportedException(); }
        public void Delete() { throw new NotSupportedException(); }
        public bool Exists() { return false; }
        public List<StagedDir> Sweep(string prefix, int maxAgeMs) { return new List<StagedDir>(); }
        public void Close() { }
    }

    public static class Transports
    {
        /// <summary>Make the transport named in the target spec. Only SMB+WMI is built; WinRM is a stub.</summary>
        public static ITransport Make(TargetSpec t, int connectTimeoutMs)
        {
            if (string.Equals(t.Transport, "winrm", StringComparison.OrdinalIgnoreCase)) return new WinRmTransport();
            SmbWmiTransport s = new SmbWmiTransport(connectTimeoutMs); s.SetHost(t.Host); return s;
        }
    }
}
