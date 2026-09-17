// Trust: Authenticode signature verification (embedded and catalog-signed, so Windows' own files verify), the
// modules loaded in a process, the executable behind a command line, and where on the disk a path lives.
// Shared by File Explorer, Find Files, Resource Usage, Software Inventory, Autoruns and Event Log Triage.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PSTools
{
    public class SigInfo
    {
        /// <summary>signed · catalog · unsigned · invalid · "" (not a signable file or not checked)</summary>
        public string Status = ""; public string Signer = "", Detail = "";
        public bool Ok { get { return Status == "signed" || Status == "catalog"; } }
        public bool Microsoft { get { return Ok && Signer.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase); } }
        public string Text { get { return Status.Length == 0 ? "" : Ok ? Status + (Signer.Length > 0 ? " · " + Signer : "") : Status + (Detail.Length > 0 ? " · " + Detail : ""); } }
        public string Short { get { return Status.Length == 0 ? "" : Ok ? (Signer.Length > 0 ? Signer : Status) : Status; } }
    }

    public class ModuleInfo { public string Name = "", Path = ""; public long Base, Size; public SigInfo Sig = new SigInfo(); public string Company = ""; public string Location = ""; }

    public static class Trust
    {
        static readonly Dictionary<string, SigInfo> cache = new Dictionary<string, SigInfo>(StringComparer.OrdinalIgnoreCase);
        static readonly Dictionary<string, string[]> vcache = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        static readonly HashSet<string> signable = new HashSet<string>(new string[] { ".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".efi", ".msi", ".msp", ".msu", ".cab", ".cat", ".appx", ".msix", ".ps1", ".psm1", ".psd1", ".vbs", ".js", ".wsf", ".mui", ".ax", ".tsp", ".node" }, StringComparer.OrdinalIgnoreCase);
        public static bool IsSignable(string path) { try { return signable.Contains(Path.GetExtension(path ?? "")); } catch { return false; } }

        // ── WinVerifyTrust ──
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct WINTRUST_FILE_INFO { public uint cbStruct; public string pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct WINTRUST_CATALOG_INFO { public uint cbStruct; public uint dwCatalogVersion; public string pcwszCatalogFilePath; public string pcwszMemberTag; public string pcwszMemberFilePath; public IntPtr hMemberFile; public IntPtr pbCalculatedFileHash; public uint cbCalculatedFileHash; public IntPtr pcCatalogContext; public IntPtr hCatAdmin; }
        [StructLayout(LayoutKind.Sequential)] struct WINTRUST_DATA { public uint cbStruct; public IntPtr pPolicyCallbackData; public IntPtr pSIPClientData; public uint dwUIChoice; public uint fdwRevocationChecks; public uint dwUnionChoice; public IntPtr pUnion; public uint dwStateAction; public IntPtr hWVTStateData; public IntPtr pwszURLReference; public uint dwProvFlags; public uint dwUIContext; public IntPtr pSignatureSettings; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct CATALOG_INFO { public uint cbStruct; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile; }
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)] static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WINTRUST_DATA data);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, IntPtr pgSubsystem, string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);
        [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint pcbHash, byte[] pbHash, uint dwFlags);
        [DllImport("wintrust.dll", SetLastError = true)] static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);
        [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);
        [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);
        static readonly Guid GenericVerify = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1, WTD_CHOICE_CATALOG = 2, WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2, WTD_REVOCATION_CHECK_NONE = 0x10, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

        /// <summary>Verify a file's Authenticode signature: embedded first, then the Windows security catalogs. Cached per path + size + mtime.</summary>
        public static SigInfo Verify(string path)
        {
            SigInfo r = new SigInfo(); if (string.IsNullOrEmpty(path)) return r;
            string key; try { FileInfo fi = new FileInfo(path); if (!fi.Exists) { r.Detail = "file not found"; return r; } key = fi.FullName + "|" + fi.Length + "|" + fi.LastWriteTimeUtc.Ticks; } catch { return r; }
            lock (cache) { SigInfo c; if (cache.TryGetValue(key, out c)) return c; }
            if (!IsSignable(path)) { lock (cache) cache[key] = r; return r; }
            try
            {
                int hr = VerifyFile(path);
                if (hr == 0) { r.Status = "signed"; r.Signer = SignerOf(path); }
                else if ((uint)hr == 0x800B0100) // TRUST_E_NOSIGNATURE: try the catalogs
                {
                    string cat = FindCatalog(path, out hr);
                    if (cat != null && hr == 0) { r.Status = "catalog"; r.Signer = SignerOf(cat); r.Detail = Path.GetFileName(cat); }
                    else if (cat != null) { r.Status = "invalid"; r.Detail = Describe(hr) + " (catalog)"; }
                    else r.Status = "unsigned";
                }
                else { r.Status = "invalid"; r.Detail = Describe(hr); try { r.Signer = SignerOf(path); } catch { } }
            }
            catch (Exception ex) { r.Status = ""; r.Detail = ex.Message; }
            lock (cache) cache[key] = r;
            return r;
        }
        static int VerifyFile(string path)
        {
            WINTRUST_FILE_INFO fi = new WINTRUST_FILE_INFO(); fi.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)); fi.pcwszFilePath = path;
            IntPtr pfi = Marshal.AllocHGlobal((int)fi.cbStruct); Marshal.StructureToPtr(fi, pfi, false);
            try { return Run(WTD_CHOICE_FILE, pfi); } finally { Marshal.DestroyStructure(pfi, typeof(WINTRUST_FILE_INFO)); Marshal.FreeHGlobal(pfi); }
        }
        static int Run(uint choice, IntPtr pUnion)
        {
            WINTRUST_DATA d = new WINTRUST_DATA(); d.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)); d.dwUIChoice = WTD_UI_NONE; d.fdwRevocationChecks = WTD_REVOKE_NONE; d.dwUnionChoice = choice; d.pUnion = pUnion; d.dwStateAction = WTD_STATEACTION_VERIFY; d.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
            int hr = WinVerifyTrust(IntPtr.Zero, GenericVerify, ref d);
            d.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust(IntPtr.Zero, GenericVerify, ref d);
            return hr;
        }
        static string FindCatalog(string path, out int hr)
        {
            hr = unchecked((int)0x800B0100);
            foreach (string algo in new string[] { "SHA256", "SHA1" })
            {
                IntPtr admin = IntPtr.Zero;
                if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, algo, IntPtr.Zero, 0)) continue;
                try
                {
                    using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    {
                        IntPtr h = fs.SafeFileHandle.DangerousGetHandle(); uint cb = 0;
                        CryptCATAdminCalcHashFromFileHandle2(admin, h, ref cb, null, 0); if (cb == 0) continue;
                        byte[] hash = new byte[cb]; if (!CryptCATAdminCalcHashFromFileHandle2(admin, h, ref cb, hash, 0)) continue;
                        IntPtr prev = IntPtr.Zero; IntPtr catInfo = CryptCATAdminEnumCatalogFromHash(admin, hash, cb, 0, ref prev);
                        if (catInfo == IntPtr.Zero) continue;
                        try
                        {
                            CATALOG_INFO ci = new CATALOG_INFO(); ci.cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO));
                            if (!CryptCATCatalogInfoFromContext(catInfo, ref ci, 0)) continue;
                            StringBuilder tag = new StringBuilder(); foreach (byte b in hash) tag.Append(b.ToString("X2"));
                            WINTRUST_CATALOG_INFO wci = new WINTRUST_CATALOG_INFO(); wci.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)); wci.pcwszCatalogFilePath = ci.wszCatalogFile; wci.pcwszMemberFilePath = path; wci.pcwszMemberTag = tag.ToString(); wci.hMemberFile = h; wci.hCatAdmin = admin;
                            IntPtr ph = Marshal.AllocHGlobal(hash.Length); Marshal.Copy(hash, 0, ph, hash.Length); wci.pbCalculatedFileHash = ph; wci.cbCalculatedFileHash = cb;
                            IntPtr p = Marshal.AllocHGlobal((int)wci.cbStruct); Marshal.StructureToPtr(wci, p, false);
                            try { hr = Run(WTD_CHOICE_CATALOG, p); } finally { Marshal.DestroyStructure(p, typeof(WINTRUST_CATALOG_INFO)); Marshal.FreeHGlobal(p); Marshal.FreeHGlobal(ph); }
                            return ci.wszCatalogFile;
                        }
                        finally { CryptCATAdminReleaseCatalogContext(admin, catInfo, 0); }
                    }
                }
                catch { }
                finally { CryptCATAdminReleaseContext(admin, 0); }
            }
            return null;
        }
        static string SignerOf(string path)
        {
            try { X509Certificate c = X509Certificate.CreateFromSignedFile(path); X509Certificate2 c2 = new X509Certificate2(c); string n = c2.GetNameInfo(X509NameType.SimpleName, false); return string.IsNullOrEmpty(n) ? c2.Subject : n; } catch { return ""; }
        }
        public static string Describe(int hr)
        {
            switch (unchecked((uint)hr))
            {
                case 0x800B0100: return "no signature";
                case 0x80096010: return "hash mismatch (file modified after signing)";
                case 0x800B0004: return "subject not trusted";
                case 0x800B0109: return "untrusted root";
                case 0x800B0101: return "certificate expired";
                case 0x800B010A: return "broken chain";
                case 0x800B0111: return "explicitly distrusted";
                case 0x80092026: return "blocked by security settings";
                case 0x800B010C: return "certificate revoked";
                case 0x80096005: return "signature not valid for this file";
                default: return "error 0x" + hr.ToString("X8");
            }
        }

        // ── file version info ──
        /// <summary>[company, description, version] of a file, cached.</summary>
        public static string[] VersionInfo(string path)
        {
            if (string.IsNullOrEmpty(path)) return new string[] { "", "", "" };
            lock (vcache) { string[] v; if (vcache.TryGetValue(path, out v)) return v; }
            string[] r;
            try { FileVersionInfo f = FileVersionInfo.GetVersionInfo(path); r = new string[] { (f.CompanyName ?? "").Trim(), (f.FileDescription ?? "").Trim(), (f.FileVersion ?? "").Trim() }; }
            catch { r = new string[] { "", "", "" }; }
            lock (vcache) vcache[path] = r;
            return r;
        }

        // ── where a path lives ──
        static string windir, pf, pf86, profile, programdata, users;
        static void Roots() { if (windir != null) return; windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows); pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles); pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86); profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); programdata = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData); try { users = Path.GetDirectoryName(profile.TrimEnd('\\')); } catch { users = "C:\\Users"; } }
        static bool Under(string p, string root) { return !string.IsNullOrEmpty(root) && p.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase); }
        /// <summary>"windows" · "program files" · "user-writable" (profiles, ProgramData, Temp, Public) · "other" (any other drive/folder) · "" for no path.</summary>
        public static string Location(string path)
        {
            if (string.IsNullOrEmpty(path)) return ""; Roots(); string p = path;
            if (Under(p, Path.Combine(windir, "Temp"))) return "user-writable";
            if (Under(p, windir)) return "windows";
            if (Under(p, pf) || Under(p, pf86)) return "program files";
            if (Under(p, users) || Under(p, programdata)) return "user-writable";
            return "other";
        }
        public static bool UserWritable(string path) { return Location(path) == "user-writable"; }

        // ── the executable behind a command line ──
        static readonly string[] exts = { ".exe", ".com", ".bat", ".cmd", ".dll", ".sys", ".scr", ".vbs", ".js", ".ps1", ".msi", ".ocx", ".cpl" };
        /// <summary>Find the program a command line runs: handles quotes, %ENV%, rundll32 targets, missing .exe and bare names on the PATH. Empty when nothing plausible.</summary>
        public static string ImagePath(string command)
        {
            if (string.IsNullOrEmpty(command)) return ""; string c = command.Trim();
            try { c = Environment.ExpandEnvironmentVariables(c); } catch { }
            if (c.StartsWith("\\??\\")) c = c.Substring(4);
            if (c.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase)) { Roots(); c = Path.Combine(windir, c.Substring(12)); }
            if (c.StartsWith("system32\\", StringComparison.OrdinalIgnoreCase)) { Roots(); c = Path.Combine(windir, c); }
            string first;
            if (c.StartsWith("\"")) { int q = c.IndexOf('"', 1); first = q > 0 ? c.Substring(1, q - 1) : c.Substring(1); }
            else
            {
                // rundll32 x.dll,Entry → the dll; else the longest space-separated prefix that is an existing file
                string[] parts = c.Split(' '); first = parts[0]; string acc = "";
                for (int i = 0; i < parts.Length; i++) { acc = i == 0 ? parts[0] : acc + " " + parts[i]; if (Exists(acc)) first = acc; else if (!Path.HasExtension(acc) && Exists(acc + ".exe")) first = acc + ".exe"; }
                if (parts[0].EndsWith("rundll32.exe", StringComparison.OrdinalIgnoreCase) && parts.Length > 1)
                {
                    string rest = c.Substring(parts[0].Length).Trim(); string dll = rest.StartsWith("\"") ? rest.Substring(1, Math.Max(0, rest.IndexOf('"', 1) - 1)) : rest.Split(',', ' ')[0];
                    string rp = Resolve(dll); if (rp.Length > 0) return rp;
                }
            }
            return Resolve(first.Trim());
        }
        static bool Exists(string p) { try { return p.Length > 0 && p.IndexOfAny(Path.GetInvalidPathChars()) < 0 && File.Exists(p); } catch { return false; } }
        static string Resolve(string p)
        {
            if (p.Length == 0) return "";
            try
            {
                if (Exists(p)) return Path.GetFullPath(p);
                if (!Path.HasExtension(p) && Exists(p + ".exe")) return Path.GetFullPath(p + ".exe");
                if (p.IndexOf('\\') < 0)
                {
                    Roots(); List<string> dirs = new List<string>(); dirs.Add(Path.Combine(windir, "System32")); dirs.Add(windir); dirs.Add(Path.Combine(windir, "SysWOW64")); string pathVar = Environment.GetEnvironmentVariable("PATH") ?? ""; dirs.AddRange(pathVar.Split(';'));
                    foreach (string d in dirs) { if (d.Trim().Length == 0) continue; string cand = Path.Combine(d.Trim(), p); if (Exists(cand)) return cand; if (!Path.HasExtension(p)) foreach (string e in exts) if (Exists(cand + e)) return cand + e; }
                }
            }
            catch { }
            return p.IndexOf('\\') >= 0 ? p : "";
        }

        // ── process image and modules ──
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder name, ref uint size);
        [DllImport("psapi.dll", SetLastError = true)] static extern bool EnumProcessModulesEx(IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb, out uint lpcbNeeded, uint dwFilterFlag);
        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, uint nSize);
        [StructLayout(LayoutKind.Sequential)] struct MODULEINFO { public IntPtr lpBaseOfDll; public uint SizeOfImage; public IntPtr EntryPoint; }
        [DllImport("psapi.dll", SetLastError = true)] static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO info, uint cb);
        const uint PROCESS_QUERY_INFORMATION = 0x400, PROCESS_VM_READ = 0x10, PROCESS_QUERY_LIMITED_INFORMATION = 0x1000, LIST_MODULES_ALL = 3;

        public static string ProcessPath(int pid)
        {
            if (pid <= 4) return ""; IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid); if (h == IntPtr.Zero) return "";
            try { StringBuilder sb = new StringBuilder(1024); uint n = 1024; return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : ""; } catch { return ""; } finally { CloseHandle(h); }
        }
        static string Win32Err() { try { return new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message.TrimEnd('.'); } catch { return "error"; } }
        /// <summary>Every module loaded in a process (32- and 64-bit), with its path; throws when the process cannot be opened.</summary>
        public static List<ModuleInfo> Modules(int pid)
        {
            List<ModuleInfo> l = new List<ModuleInfo>(); IntPtr h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
            if (h == IntPtr.Zero) throw new UnauthorizedAccessException("cannot open the process (" + Win32Err() + ")");
            try
            {
                IntPtr[] mods = new IntPtr[4096]; uint needed;
                if (!EnumProcessModulesEx(h, mods, (uint)(mods.Length * IntPtr.Size), out needed, LIST_MODULES_ALL)) throw new UnauthorizedAccessException("cannot list the modules (" + Win32Err() + ")");
                int n = Math.Min(mods.Length, (int)(needed / IntPtr.Size));
                for (int i = 0; i < n; i++)
                {
                    StringBuilder sb = new StringBuilder(1024); if (GetModuleFileNameEx(h, mods[i], sb, 1024) == 0) continue;
                    ModuleInfo m = new ModuleInfo(); m.Path = sb.ToString(); if (m.Path.StartsWith("\\??\\")) m.Path = m.Path.Substring(4); m.Name = Path.GetFileName(m.Path); m.Location = Location(m.Path);
                    MODULEINFO mi; if (GetModuleInformation(h, mods[i], out mi, (uint)Marshal.SizeOf(typeof(MODULEINFO)))) { m.Base = mi.lpBaseOfDll.ToInt64(); m.Size = mi.SizeOfImage; }
                    l.Add(m);
                }
            }
            finally { CloseHandle(h); }
            return l;
        }
    }
}
