// BrowserCreds: the passwords a browser has saved. Like the Wi-Fi reveal, these are masked until you opt in.
// Chromium (Chrome/Edge/Brave/…): the "Login Data" SQLite DB; the password is DPAPI-encrypted (old) or
// AES-256-GCM with a key kept in "Local State" and itself DPAPI-wrapped (Chrome v80+). Firefox: logins.json,
// decrypted through the NSS library shipped with Firefox when it can be found. No external dependencies -
// DPAPI via crypt32, AES-GCM via bcrypt.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PSTools
{
    public class LoginRow
    {
        public string Browser = "", Profile = "", Url = "", Domain = "", User = "", Password = "", Note = ""; public DateTime When; public bool HasPassword;
        public string WhenText { get { return When == DateTime.MinValue ? "" : When.ToString("yyyy-MM-dd HH:mm"); } }
        public bool Weak { get { return HasPassword && Password.Length > 0 && Password.Length < 8; } }
    }

    public static class BrowserCreds
    {
        // ── DPAPI (crypt32) ──
        [StructLayout(LayoutKind.Sequential)] struct DATA_BLOB { public int cbData; public IntPtr pbData; }
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)] static extern bool CryptUnprotectData(ref DATA_BLOB inData, StringBuilder desc, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref DATA_BLOB outData);
        [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
        static byte[] Dpapi(byte[] data)
        {
            if (data == null || data.Length == 0) return null;
            IntPtr pIn = Marshal.AllocHGlobal(data.Length); Marshal.Copy(data, 0, pIn, data.Length);
            DATA_BLOB inB = new DATA_BLOB(); inB.cbData = data.Length; inB.pbData = pIn; DATA_BLOB outB = new DATA_BLOB();
            try { if (!CryptUnprotectData(ref inB, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref outB)) return null; byte[] r = new byte[outB.cbData]; Marshal.Copy(outB.pbData, r, 0, outB.cbData); return r; }
            finally { Marshal.FreeHGlobal(pIn); if (outB.pbData != IntPtr.Zero) LocalFree(outB.pbData); }
        }

        // ── AES-256-GCM (bcrypt) ──
        [DllImport("bcrypt.dll")] static extern int BCryptOpenAlgorithmProvider(out IntPtr h, string algId, string impl, int flags);
        [DllImport("bcrypt.dll")] static extern int BCryptCloseAlgorithmProvider(IntPtr h, int flags);
        [DllImport("bcrypt.dll")] static extern int BCryptSetProperty(IntPtr h, string prop, byte[] input, int cbInput, int flags);
        [DllImport("bcrypt.dll")] static extern int BCryptGenerateSymmetricKey(IntPtr hAlg, out IntPtr hKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int flags);
        [DllImport("bcrypt.dll")] static extern int BCryptDestroyKey(IntPtr hKey);
        [DllImport("bcrypt.dll")] static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int flags);
        [StructLayout(LayoutKind.Sequential)] struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO { public int cbSize; public int dwInfoVersion; public IntPtr pbNonce; public int cbNonce; public IntPtr pbAuthData; public int cbAuthData; public IntPtr pbTag; public int cbTag; public IntPtr pbMacContext; public int cbMacContext; public int cbAAD; public long cbData; public int dwFlags; }

        static byte[] AesGcm(byte[] key, byte[] nonce, byte[] cipher, byte[] tag)
        {
            IntPtr hAlg = IntPtr.Zero, hKey = IntPtr.Zero; IntPtr pNonce = IntPtr.Zero, pTag = IntPtr.Zero;
            try
            {
                if (BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0) != 0) return null;
                byte[] gcm = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
                if (BCryptSetProperty(hAlg, "ChainingMode", gcm, gcm.Length, 0) != 0) return null;
                if (BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0) != 0) return null;
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                info.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)); info.dwInfoVersion = 1;
                pNonce = Marshal.AllocHGlobal(nonce.Length); Marshal.Copy(nonce, 0, pNonce, nonce.Length); info.pbNonce = pNonce; info.cbNonce = nonce.Length;
                pTag = Marshal.AllocHGlobal(tag.Length); Marshal.Copy(tag, 0, pTag, tag.Length); info.pbTag = pTag; info.cbTag = tag.Length;
                byte[] outBuf = new byte[cipher.Length]; int outLen;
                int rc = BCryptDecrypt(hKey, cipher, cipher.Length, ref info, null, 0, outBuf, outBuf.Length, out outLen, 0);
                if (rc != 0) return null; if (outLen != outBuf.Length) { byte[] t = new byte[outLen]; Array.Copy(outBuf, t, outLen); return t; } return outBuf;
            }
            catch { return null; }
            finally { if (pNonce != IntPtr.Zero) Marshal.FreeHGlobal(pNonce); if (pTag != IntPtr.Zero) Marshal.FreeHGlobal(pTag); if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey); if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0); }
        }

        // ── Chromium ──
        static byte[] ChromiumKey(string userDataDir)
        {
            try
            {
                string ls = Path.Combine(userDataDir, "Local State"); if (!File.Exists(ls)) return null;
                object doc = Json.Parse(File.ReadAllText(ls)); string b64 = Json.GetS(Json.Get(doc, "os_crypt"), "encrypted_key"); if (string.IsNullOrEmpty(b64)) return null;
                byte[] blob = Convert.FromBase64String(b64);
                if (blob.Length > 5 && Encoding.ASCII.GetString(blob, 0, 5) == "DPAPI") { byte[] stripped = new byte[blob.Length - 5]; Array.Copy(blob, 5, stripped, 0, stripped.Length); return Dpapi(stripped); }
                return Dpapi(blob);
            }
            catch { return null; }
        }
        static string DecryptChromium(byte[] blob, byte[] aesKey)
        {
            if (blob == null || blob.Length == 0) return "";
            try
            {
                if (blob.Length > 3 && (blob[0] == 'v') && (blob[1] == '1') && (blob[2] == '0' || blob[2] == '1'))
                {
                    if (aesKey == null) return "";
                    byte[] nonce = new byte[12]; Array.Copy(blob, 3, nonce, 0, 12);
                    int ctLen = blob.Length - 3 - 12 - 16; if (ctLen < 0) return "";
                    byte[] cipher = new byte[ctLen]; Array.Copy(blob, 15, cipher, 0, ctLen);
                    byte[] tag = new byte[16]; Array.Copy(blob, 15 + ctLen, tag, 0, 16);
                    byte[] plain = AesGcm(aesKey, nonce, cipher, tag); return plain == null ? "" : Encoding.UTF8.GetString(plain);
                }
                byte[] d = Dpapi(blob); return d == null ? "" : Encoding.UTF8.GetString(d);
            }
            catch { return ""; }
        }

        public static List<LoginRow> Chromium(BrowserProfile p, string userDataDir, bool reveal)
        {
            List<LoginRow> rows = new List<LoginRow>();
            string db = Path.Combine(p.Dir, "Login Data"); if (!File.Exists(db)) return rows;
            byte[] key = reveal ? ChromiumKey(userDataDir) : null;
            SqliteTable t; try { t = Sqlite.Read(db, "logins", int.MaxValue); } catch { return rows; }
            int iPw = t.Index("password_value");
            foreach (object[] r in t.Rows)
            {
                LoginRow lr = new LoginRow(); lr.Browser = p.Browser; lr.Profile = p.Name; lr.Url = t.Str(r, "origin_url"); lr.Domain = Browser.DomainOf(lr.Url); lr.User = t.Str(r, "username_value");
                lr.When = Sqlite.ChromeTime(t.Long(r, "date_created"));
                object pw = iPw >= 0 && iPw < r.Length ? r[iPw] : null; byte[] blob = pw as byte[]; lr.HasPassword = blob != null && blob.Length > 0;
                if (reveal && lr.HasPassword) { lr.Password = DecryptChromium(blob, key); if (lr.Password.Length == 0) lr.Note = NoteFor(blob, key); }
                rows.Add(lr);
            }
            return rows;
        }

        static string NoteFor(byte[] blob, byte[] key)
        {
            if (key == null) return "could not read the master key (Local State)";
            if (blob != null && blob.Length >= 3 && blob[0] == 'v' && blob[1] == '2' && blob[2] == '0') return "app-bound encryption — only the browser itself can decrypt this";
            return "unsupported encryption format on this entry";
        }

        // ── Firefox (NSS) ──
        public static List<LoginRow> Firefox(BrowserProfile p, bool reveal)
        {
            List<LoginRow> rows = new List<LoginRow>();
            string lj = Path.Combine(p.Dir, "logins.json"); if (!File.Exists(lj)) return rows;
            List<string[]> raw = new List<string[]>(); // {host, encUser, encPass, created}
            try
            {
                object doc = Json.Parse(File.ReadAllText(lj));
                foreach (object login in Json.Arr(Json.Get(doc, "logins")))
                { string host = Json.GetS(login, "hostname") ?? ""; string eu = Json.GetS(login, "encryptedUsername") ?? ""; string ep = Json.GetS(login, "encryptedPassword") ?? ""; string ct = ""; double? c = Json.N(Json.Get(login, "timeCreated")); if (c.HasValue) ct = ((long)c.Value).ToString(); raw.Add(new string[] { host, eu, ep, ct }); }
            }
            catch { return rows; }
            Nss nss = null; if (reveal) { try { nss = Nss.Open(p.Dir); } catch { nss = null; } }
            foreach (string[] e in raw)
            {
                LoginRow lr = new LoginRow(); lr.Browser = p.Browser; lr.Profile = p.Name; lr.Url = e[0]; lr.Domain = Browser.DomainOf(e[0]); lr.HasPassword = e[2].Length > 0;
                long ms; if (long.TryParse(e[3], out ms) && ms > 0) lr.When = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMilliseconds(ms).ToLocalTime();
                if (reveal)
                {
                    if (nss != null && nss.Ok) { lr.User = nss.Decrypt(e[1]); lr.Password = nss.Decrypt(e[2]); if (lr.Password.Length == 0 && lr.HasPassword) lr.Note = "NSS could not decrypt (master password set?)"; }
                    else lr.Note = "install Firefox / NSS not found to decrypt";
                }
                rows.Add(lr);
            }
            if (nss != null) nss.Close();
            return rows;
        }
    }

    /// <summary>Thin loader for Firefox's NSS library (nss3.dll) to decrypt logins. Best-effort: needs Firefox installed.</summary>
    class Nss
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr LoadLibrary(string path);
        [DllImport("kernel32.dll")] static extern bool SetDllDirectory(string path);
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] static extern IntPtr GetProcAddress(IntPtr h, string name);
        [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr h);
        [StructLayout(LayoutKind.Sequential)] struct SECItem { public int type; public IntPtr data; public int len; }
        delegate int NSS_InitD(string configdir);
        delegate int NSS_ShutdownD();
        delegate int PK11SDR_DecryptD(ref SECItem data, ref SECItem result, IntPtr cx);

        IntPtr lib; NSS_InitD nssInit; NSS_ShutdownD nssShutdown; PK11SDR_DecryptD decrypt;
        public bool Ok { get { return decrypt != null; } }

        public static Nss Open(string profileDir)
        {
            string dir = FirefoxDir(); if (dir == null) return null;
            Nss n = new Nss(); SetDllDirectory(dir);
            n.lib = LoadLibrary(Path.Combine(dir, "nss3.dll")); if (n.lib == IntPtr.Zero) return null;
            n.nssInit = (NSS_InitD)Marshal.GetDelegateForFunctionPointer(GetProcAddress(n.lib, "NSS_Init"), typeof(NSS_InitD));
            IntPtr pShut = GetProcAddress(n.lib, "NSS_Shutdown"); if (pShut != IntPtr.Zero) n.nssShutdown = (NSS_ShutdownD)Marshal.GetDelegateForFunctionPointer(pShut, typeof(NSS_ShutdownD));
            IntPtr pDec = GetProcAddress(n.lib, "PK11SDR_Decrypt"); if (pDec != IntPtr.Zero) n.decrypt = (PK11SDR_DecryptD)Marshal.GetDelegateForFunctionPointer(pDec, typeof(PK11SDR_DecryptD));
            if (n.nssInit == null || n.decrypt == null) { n.Close(); return null; }
            if (n.nssInit("sql:" + profileDir) != 0 && n.nssInit(profileDir) != 0) { n.Close(); return null; }
            return n;
        }
        public string Decrypt(string b64)
        {
            if (string.IsNullOrEmpty(b64) || decrypt == null) return "";
            IntPtr pIn = IntPtr.Zero;
            try
            {
                byte[] enc = Convert.FromBase64String(b64); pIn = Marshal.AllocHGlobal(enc.Length); Marshal.Copy(enc, 0, pIn, enc.Length);
                SECItem input = new SECItem(); input.data = pIn; input.len = enc.Length; SECItem output = new SECItem();
                if (decrypt(ref input, ref output, IntPtr.Zero) != 0) return ""; if (output.data == IntPtr.Zero || output.len <= 0) return "";
                byte[] outb = new byte[output.len]; Marshal.Copy(output.data, outb, 0, output.len); return Encoding.UTF8.GetString(outb);
            }
            catch { return ""; }
            finally { if (pIn != IntPtr.Zero) Marshal.FreeHGlobal(pIn); }
        }
        public void Close() { try { if (nssShutdown != null) nssShutdown(); } catch { } try { if (lib != IntPtr.Zero) FreeLibrary(lib); } catch { } lib = IntPtr.Zero; decrypt = null; }
        static string FirefoxDir()
        {
            foreach (string b in new string[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
            { if (string.IsNullOrEmpty(b)) continue; string d = Path.Combine(b, "Mozilla Firefox"); if (File.Exists(Path.Combine(d, "nss3.dll"))) return d; }
            return null;
        }
    }
}
