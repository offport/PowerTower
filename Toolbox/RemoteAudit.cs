// RemoteAudit.cs - the agentless authenticated remote-audit controller (scope-plan section 2).
// Compiled into PowerTowerCli.exe and Tests.exe ONLY - never PowerTowerCollect.exe (it would put a
// "Delete"/"Exec" method in the collector and break CollectorAssembly_), and never the SHARED set.
// This file holds the transport interface, a fully scriptable FakeTransport for the tests, the controller
// flow, the credential store, the append-only journal and the target list. It deliberately uses no CLI or
// GUI type (no Out, View, Cli) so the test assembly, which has no WinForms and no CLI framework, compiles it.
// The real SMB+WMI transport is in RemoteTransport.cs (CLI only).
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PSTools
{
    // ───────────────────────────── the transport ─────────────────────────────
    /// <summary>Which step a transport failure happened in, so the controller can turn it into one clear message.</summary>
    public enum PtStage { Preflight, Connect, Stage, Exec, Fetch, Clean }

    /// <summary>A transport failure with a stable code the controller maps to an explanation. Never carries a secret.</summary>
    public class TransportException : Exception
    {
        public readonly PtStage Stage; public readonly string Code;
        public TransportException(PtStage stage, string code, string message) : base(message) { Stage = stage; Code = code; }
    }

    /// <summary>What a preflight TCP check found. No credential is used to get this.</summary>
    public class Preflight { public bool Smb445, Rpc135, WinRm5985; public string Note = ""; public bool CanStageSmb { get { return Smb445; } } public bool CanExec { get { return Rpc135 || WinRm5985; } } }

    /// <summary>The result of starting the collector remotely and waiting for it.</summary>
    public class ExecResult { public bool Exited, TimedOut, SessionLost; public int ExitCode; }

    /// <summary>A staged file seen on the target (name + last-write), for the stale-dir sweep.</summary>
    public class StagedDir { public string Name = ""; public DateTime WhenUtc; }

    /// <summary>The controller-to-target transport. The six core verbs are Connect, Copy, Exec, Wait, Fetch and
    /// Delete; Preflight (no credential), Exists (verify-gone) and Sweep (stale cleanup) support the flow. A
    /// transport opens one staging directory per run and all paths below are relative to it.</summary>
    public interface ITransport
    {
        /// <summary>TCP reachability only - 445 / 135 / 5985. No credential is sent.</summary>
        Preflight Preflight();
        /// <summary>Authenticate (exactly one attempt - the controller never retries a logon) and open the ADMIN$
        /// session and the staging dir. Throws TransportException: PORT_DOWN, LOGON_FAILURE, TOKEN_FILTER (logon
        /// succeeded but ADMIN$ is denied - UAC remote restriction / LocalAccountTokenFilterPolicy), ADMIN_SHARE.</summary>
        void Connect(string host, NetworkCred cred, string stageDirName);
        /// <summary>Copy bytes into the staging dir under this name.</summary>
        void Copy(byte[] data, string remoteName);
        /// <summary>Start the staged program with these arguments; returns a handle (a PID for the real transport).</summary>
        int Exec(string remoteExeName, string args);
        /// <summary>Wait up to timeoutMs for the started program; kill it on expiry (TimedOut) and report a lost
        /// session (SessionLost, e.g. a reboot). Never throws for an ordinary non-zero exit.</summary>
        ExecResult Wait(int handle, int timeoutMs);
        /// <summary>Pull a staged file; null if it is not there (quarantined, never written).</summary>
        byte[] Fetch(string remoteName);
        /// <summary>Delete the whole staging dir.</summary>
        void Delete();
        /// <summary>True if the staging dir still exists (used to verify the delete).</summary>
        bool Exists();
        /// <summary>Staging dirs from earlier runs (names beginning pt-) older than maxAgeMs, to sweep; best-effort.</summary>
        List<StagedDir> Sweep(string prefix, int maxAgeMs);
        /// <summary>Close the session; never throws.</summary>
        void Close();
    }

    // ───────────────────────────── a credential that is zeroed after use ─────────────────────────────
    /// <summary>domain\user plus the secret as bytes, so it is never a string that lingers on the managed heap.
    /// Zero() wipes the bytes; the controller calls it in a finally. ToString() never shows the secret.</summary>
    public sealed class NetworkCred : IDisposable
    {
        public readonly string User; readonly byte[] secret;
        public NetworkCred(string user, byte[] secret) { User = user ?? ""; this.secret = secret ?? new byte[0]; }
        public byte[] SecretBytes { get { return secret; } }
        public string SecretUtf8() { return Encoding.UTF8.GetString(secret); }   // only the transport, at the moment of WNetAddConnection2, calls this
        public void Zero() { if (secret != null) Array.Clear(secret, 0, secret.Length); }
        public void Dispose() { Zero(); }
        public override string ToString() { return User + " (secret hidden)"; }
    }

    // ───────────────────────────── what one target run produced ─────────────────────────────
    public class RunResult
    {
        public string Host = "", User = "", RunId = "", Status = "", Detail = "", Transport = "smb-wmi";
        public long Bytes; public string Sha = ""; public bool Verified, Partial, LeftClean = true; public double Seconds;
        public DateTime WhenUtc = DateTime.UtcNow;
        /// <summary>The fetched bundle bytes, carried back to the CLI to write out. Never journaled, never a string.</summary>
        public object Tag;
        /// <summary>True for the statuses that mean the target failed, so the controller can exit 1.</summary>
        public bool Failed { get { return Status != "ok" && Status != "ok-partial" && Status != "preflight-ok"; } }
        public string DetailPorts(Preflight pf) { return "445=" + (pf.Smb445 ? "yes" : "no") + " 135=" + (pf.Rpc135 ? "yes" : "no") + " 5985=" + (pf.WinRm5985 ? "yes" : "no"); }
    }

    public class TargetSpec { public string Host = "", CredLabel = "", Transport = "smb-wmi"; public int TimeoutSec; public List<string> Modules = new List<string>(); public string SourceLine = ""; }

    public class RunOptions
    {
        public byte[] CollectorExe; public string CollectorArgs = "collect";
        public byte[] IocList; public byte[] EngagementPublicKey;
        public int DefaultTimeoutSec = 1800; public int StaleSweepSec = 1800; public bool PreflightOnly;
        public Action<string> Progress = delegate { };
    }

    // ───────────────────────────── the controller ─────────────────────────────
    public class RemoteAudit
    {
        readonly Engagement eng; readonly RunJournal journal; readonly Func<TargetSpec, ITransport> makeTransport;
        readonly Func<string, NetworkCred> resolveCred; readonly DateTime nowUtc;

        /// <summary>resolveCred is called only after the scope/window gate and preflight pass, so an out-of-scope or
        /// unreachable host never causes a credential to be read.</summary>
        public RemoteAudit(Engagement eng, RunJournal journal, Func<TargetSpec, ITransport> makeTransport, Func<string, NetworkCred> resolveCred, DateTime nowUtc)
        { this.eng = eng; this.journal = journal; this.makeTransport = makeTransport; this.resolveCred = resolveCred; this.nowUtc = nowUtc; }

        public RunResult RunOne(TargetSpec t, RunOptions opt)
        {
            RunResult r = new RunResult(); r.Host = t.Host; r.Transport = t.Transport; r.RunId = NewRunId();
            DateTime started = DateTime.UtcNow;
            // 1. the engagement gate - BEFORE any transport call and BEFORE any credential is read
            string why;
            if (!eng.InScope(t.Host, out why)) { return Done(r, "refused-scope", why, started); }
            if (!eng.InWindow(nowUtc, out why)) { return Done(r, "refused-window", why, started); }

            ITransport tr = null;
            NetworkCred cred = null;
            try
            {
                tr = makeTransport(t);
                // 2. preflight - TCP only, no credential
                Preflight pf;
                try { pf = tr.Preflight(); }
                catch (Exception ex) { return Done(r, "unreachable", "preflight failed: " + Scrub(ex.Message), started); }
                if (opt.PreflightOnly)
                {
                    bool ok = pf.CanStageSmb && pf.CanExec;
                    r.Detail = "445=" + YN(pf.Smb445) + " 135=" + YN(pf.Rpc135) + " 5985=" + YN(pf.WinRm5985) + (pf.Note.Length > 0 ? " · " + pf.Note : "");
                    return Done(r, ok ? "preflight-ok" : "unreachable-preflight", r.Detail, started);
                }
                if (!pf.CanStageSmb) return Done(r, "unreachable", "SMB 445 is not reachable; no credential was sent. " + r.DetailPorts(pf), started);
                if (!pf.CanExec) return Done(r, "unreachable", "no execution path reachable (RPC 135 nor WinRM 5985); no credential was sent. " + r.DetailPorts(pf), started);

                // 3. authenticate - read the credential now, one attempt, no retry on a logon failure (lockout safety)
                cred = resolveCred(t.CredLabel);
                if (cred == null) return Done(r, "no-credential", "no credential labelled '" + t.CredLabel + "' in the store", started);
                r.User = cred.User;
                try { tr.Connect(t.Host, cred, "pt-" + r.RunId); }
                catch (TransportException ex)
                {
                    switch (ex.Code)
                    {
                        case "LOGON_FAILURE": return Done(r, "logon-failed", "the credential was rejected. Stopped after ONE attempt so the account cannot be locked out. Check the password and that the account may log on from here.", started);
                        case "TOKEN_FILTER": return Done(r, "token-filter", "logon succeeded but ADMIN$ was denied - the account gets a filtered token over the network (UAC remote restriction / LocalAccountTokenFilterPolicy). Use a domain admin or the built-in Administrator, or the client sets LocalAccountTokenFilterPolicy=1 (a target-side change PowerTower never makes and which should be reverted after the engagement).", started);
                        case "ADMIN_SHARE": return Done(r, "admin-share", "ADMIN$ is not available (AutoShareServer=0, SMB1-only, or a signing mismatch). Stage path cannot be reached.", started);
                        case "PORT_DOWN": return Done(r, "unreachable", "the execution port closed between preflight and connect.", started);
                        default: return Done(r, "connect-failed", Scrub(ex.Message), started);
                    }
                }

                // best-effort: sweep this target's stale pt-* dirs from earlier crashed runs
                try { foreach (StagedDir sd in tr.Sweep("pt-", opt.StaleSweepSec * 1000)) opt.Progress("swept stale " + sd.Name); } catch { }

                // 4. stage the collector, the engagement public key and the IOC list
                try
                {
                    tr.Copy(opt.CollectorExe ?? new byte[0], "PowerTowerCollect.exe");
                    if (opt.EngagementPublicKey != null) tr.Copy(opt.EngagementPublicKey, "engagement.pub");
                    if (opt.IocList != null) tr.Copy(opt.IocList, "ioc.txt");
                }
                catch (TransportException ex) { tr.Close(); return Done(r, "staging-failed", Scrub(ex.Message), started); }

                // 5. execute with a hard timeout; kill on expiry and still try to fetch a partial bundle
                int timeoutMs = Math.Max(1, (t.TimeoutSec > 0 ? t.TimeoutSec : opt.DefaultTimeoutSec)) * 1000;
                ExecResult ex2;
                try { int h = tr.Exec("PowerTowerCollect.exe", opt.CollectorArgs); ex2 = tr.Wait(h, timeoutMs); }
                catch (TransportException ex)
                {
                    if (ex.Code == "EXE_GONE") { TryClean(tr, r); return Done(r, "exe-blocked", "the staged collector vanished before or during execution - antivirus/EDR quarantined it, or remote process creation was blocked. Allow-list PowerTowerCollect.exe by hash and publisher for this engagement and tell the client SOC the run id " + r.RunId + ".", started); }
                    TryClean(tr, r); return Done(r, "exec-failed", Scrub(ex.Message), started);
                }
                if (ex2.SessionLost) { return Done(r, "reboot-failed", "the session was lost mid-run (likely a reboot). Marked failed; the controller does not auto-retry. Staged dir pt-" + r.RunId + " may remain - run cleanup --run " + r.RunId + ".", started); }

                // 6. fetch done.json and the bundle
                byte[] doneBytes = tr.Fetch("done.json");
                byte[] bundle = tr.Fetch("bundle.ptb");
                if (ex2.TimedOut)
                {
                    r.Partial = true;
                    if (bundle == null) { TryClean(tr, r); return Done(r, "timeout-nobundle", "the collector exceeded the " + (timeoutMs / 1000) + "s timeout and was killed; no bundle was produced.", started); }
                    r.Bytes = bundle.Length; r.Sha = Sha256Hex(bundle); r.Verified = false;
                    bool cleaned = TryClean(tr, r);
                    return Done(r, "timeout-partial", "the collector exceeded the " + (timeoutMs / 1000) + "s timeout and was killed; a partial bundle (" + bundle.Length.ToString("N0") + " bytes) was fetched. It is unverified (the collector never wrote done.json).", started, bundle);
                }
                if (bundle == null) { TryClean(tr, r); return Done(r, "no-bundle", "the collector exited (code " + ex2.ExitCode + ") but no bundle.ptb was found - a module may have aborted, or EDR removed the output.", started); }

                // 7. verify SHA-256 against done.json
                r.Bytes = bundle.Length; r.Sha = Sha256Hex(bundle);
                string wantSha = null; bool partialRun = false;
                if (doneBytes != null)
                {
                    try { object d = Json.Parse(Encoding.UTF8.GetString(doneBytes)); wantSha = Json.GetS(d, "sha256"); foreach (object m in Json.Arr(Json.Get(d, "modules"))) { string s = Json.GetS(m, "status"); if (s == "failed" || s == "partial") partialRun = true; } }
                    catch { wantSha = null; }
                }
                if (wantSha == null) { TryClean(tr, r); return Done(r, "no-done", "bundle.ptb was fetched but done.json was missing or unreadable, so the transfer cannot be verified. Treating as failed.", started, bundle); }
                if (!string.Equals(wantSha, r.Sha, StringComparison.OrdinalIgnoreCase)) { TryClean(tr, r); return Done(r, "hash-mismatch", "the fetched bundle's SHA-256 does not match done.json (" + Short(r.Sha) + " vs " + Short(wantSha) + ") - truncated transfer or tampering. The bundle is rejected.", started); }
                r.Verified = true; r.Partial = partialRun;

                // 8. clean and verify gone
                bool gone = TryClean(tr, r);
                string st = partialRun ? "ok-partial" : "ok";
                r.LeftClean = gone;
                return Done(r, st, partialRun ? "bundle verified; one or more modules were partial (see the manifest)." : "bundle verified; nothing left on the target." + (gone ? "" : " WARNING: the staged dir could not be removed - run cleanup --run " + r.RunId + "."), started, bundle);
            }
            catch (Exception ex) { return Done(r, "error", Scrub(ex.GetType().Name + ": " + ex.Message), started); }
            finally { if (cred != null) cred.Zero(); if (tr != null) try { tr.Close(); } catch { } }
        }

        bool TryClean(ITransport tr, RunResult r)
        {
            try { tr.Delete(); bool gone = !tr.Exists(); r.LeftClean = gone; return gone; }
            catch { r.LeftClean = false; return false; }
        }

        RunResult Done(RunResult r, string status, string detail, DateTime started) { return Done(r, status, detail, started, null); }
        RunResult Done(RunResult r, string status, string detail, DateTime started, byte[] bundle)
        {
            r.Status = status; r.Detail = detail; r.Seconds = (DateTime.UtcNow - started).TotalSeconds;
            if (journal != null) journal.Append(r);
            if (bundle != null) r.Tag = bundle;   // the CLI writes it out; the journal never holds bytes
            return r;
        }

        /// <summary>Remove a run's staged dir after a controller crash (cleanup --run id), and sweep older ones.</summary>
        public RunResult Cleanup(TargetSpec t, string runId, RunOptions opt)
        {
            RunResult r = new RunResult(); r.Host = t.Host; r.RunId = runId; DateTime started = DateTime.UtcNow;
            string why; if (!eng.InScope(t.Host, out why)) return Done(r, "refused-scope", why, started);
            ITransport tr = null; NetworkCred cred = null;
            try
            {
                tr = makeTransport(t); Preflight pf = tr.Preflight(); if (!pf.CanStageSmb) return Done(r, "unreachable", "SMB 445 not reachable", started);
                cred = resolveCred(t.CredLabel); if (cred == null) return Done(r, "no-credential", "no credential labelled '" + t.CredLabel + "'", started);
                tr.Connect(t.Host, cred, "pt-" + runId);
                int swept = 0; try { foreach (StagedDir sd in tr.Sweep("pt-", opt.StaleSweepSec * 1000)) swept++; } catch { }
                tr.Delete(); bool gone = !tr.Exists(); r.LeftClean = gone;
                return Done(r, gone ? "cleaned" : "cleanup-incomplete", "removed pt-" + runId + (swept > 0 ? " and swept " + swept + " stale dir(s)" : "") + (gone ? "" : " - still present"), started);
            }
            catch (TransportException ex) { return Done(r, "cleanup-failed", Scrub(ex.Message), started); }
            catch (Exception ex) { return Done(r, "error", Scrub(ex.Message), started); }
            finally { if (cred != null) cred.Zero(); if (tr != null) try { tr.Close(); } catch { } }
        }

        static string NewRunId() { return DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 6); }
        static string YN(bool b) { return b ? "yes" : "no"; }
        static string Short(string sha) { return sha == null ? "?" : (sha.Length > 12 ? sha.Substring(0, 12) : sha); }
        public static string Sha256Hex(byte[] b) { using (SHA256 h = SHA256.Create()) { byte[] d = h.ComputeHash(b); StringBuilder sb = new StringBuilder(d.Length * 2); foreach (byte x in d) sb.Append(x.ToString("x2")); return sb.ToString(); } }
        /// <summary>Strip anything that looks like a credential out of a message before it is shown or journaled.</summary>
        public static string Scrub(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            // remove user:pass@ and /user:... /pass:... fragments defensively, even though we never put them there
            s = System.Text.RegularExpressions.Regex.Replace(s, @"(?i)(/user:|/pass(word)?:|password=)\S+", "$1***");
            s = System.Text.RegularExpressions.Regex.Replace(s, @"\\\\[^\s\\]+\\[^\s\\]*\$", "\\\\<host>\\<share>");
            return s;
        }
    }

}
