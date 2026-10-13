// FileCrypto.cs - the half of FileCrypto (Files.cs) that produces or destroys files: Encrypt, Decrypt, Verify, SecureWipe
// and their helpers. Left out of PowerTowerCollect.exe so the collector can only recognise encrypted files (PT-22).
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PSTools
{
    public static partial class FileCrypto
    {
        static void Derive(string password, byte[] salt, out byte[] aesKey, out byte[] macKey, out byte[] check)
        {
            using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password ?? "", salt, Iterations))
            { aesKey = kdf.GetBytes(32); macKey = kdf.GetBytes(32); check = kdf.GetBytes(CheckLen); }
        }

        /// <summary>Encrypts inPath to outPath. progress(0..1) is optional. Throws on I/O errors.</summary>
        public static void Encrypt(string inPath, string outPath, string password, Action<double> progress)
        {
            byte[] salt = new byte[SaltLen], iv = new byte[IvLen];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) { rng.GetBytes(salt); rng.GetBytes(iv); }
            byte[] aesKey, macKey, check; Derive(password, salt, out aesKey, out macKey, out check);
            long total = 0; try { total = new FileInfo(inPath).Length; } catch { }
            using (FileStream outFs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                outFs.Write(Magic, 0, 8); outFs.Write(salt, 0, SaltLen); outFs.Write(iv, 0, IvLen);
                outFs.Write(BitConverter.GetBytes(Iterations), 0, 4); outFs.Write(check, 0, CheckLen);
                using (Aes aes = Aes.Create()) { aes.KeySize = 256; aes.Key = aesKey; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                    using (ICryptoTransform enc = aes.CreateEncryptor())
                    using (CryptoStream cs = new CryptoStream(outFs, enc, CryptoStreamMode.Write))
                    using (FileStream inFs = new FileStream(inPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan))
                    {
                        byte[] buf = new byte[1 << 20]; int n; long done = 0;
                        while ((n = inFs.Read(buf, 0, buf.Length)) > 0) { cs.Write(buf, 0, n); done += n; if (progress != null && total > 0) progress((double)done / total * 0.9); }
                        cs.FlushFinalBlock();
                    }
                }
            }
            // append HMAC over the whole file so a torn write is caught on decrypt
            byte[] tag = MacOfFile(outPath, macKey);
            using (FileStream outFs = new FileStream(outPath, FileMode.Append, FileAccess.Write, FileShare.None)) outFs.Write(tag, 0, tag.Length);
            if (progress != null) progress(1);
        }

        static byte[] MacOfFile(string path, byte[] macKey)
        {
            using (HMACSHA256 mac = new HMACSHA256(macKey))
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan))
            { byte[] buf = new byte[1 << 20]; int n; while ((n = fs.Read(buf, 0, buf.Length)) > 0) mac.TransformBlock(buf, 0, n, null, 0); mac.TransformFinalBlock(buf, 0, 0); return mac.Hash; }
        }
        static byte[] MacOfRange(string path, byte[] macKey, long length)
        {
            using (HMACSHA256 mac = new HMACSHA256(macKey))
            using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan))
            { byte[] buf = new byte[1 << 20]; long left = length; int n; while (left > 0 && (n = fs.Read(buf, 0, (int)Math.Min(buf.Length, left))) > 0) { mac.TransformBlock(buf, 0, n, null, 0); left -= n; } mac.TransformFinalBlock(buf, 0, 0); return mac.Hash; }
        }

        public class CryptoException : Exception { public CryptoException(string m) : base(m) { } }

        /// <summary>Header + password + integrity check without producing output. True if this file will decrypt with this password.</summary>
        public static bool Verify(string path, string password)
        {
            try { ReadAndCheck(path, password); return true; } catch { return false; }
        }
        static void ReadAndCheck(string path, string password)
        {
            using (FileStream fs = File.OpenRead(path))
            {
                if (fs.Length < HeaderLen + MacLen + 16) throw new CryptoException("not a valid encrypted file");
                byte[] head = new byte[HeaderLen]; ReadFull(fs, head, HeaderLen);
                for (int i = 0; i < 8; i++) if (head[i] != Magic[i]) throw new CryptoException("not a PowerTower encrypted file");
                byte[] salt = new byte[SaltLen]; Array.Copy(head, 8, salt, 0, SaltLen);
                byte[] check = new byte[CheckLen]; Array.Copy(head, 8 + SaltLen + IvLen + 4, check, 0, CheckLen);
                byte[] aesKey, macKey, check2; Derive(password, salt, out aesKey, out macKey, out check2);
                bool ok = true; for (int i = 0; i < CheckLen; i++) if (check[i] != check2[i]) ok = false;
                if (!ok) throw new CryptoException("wrong password");
                long macAt = fs.Length - MacLen; fs.Position = macAt; byte[] stored = new byte[MacLen]; ReadFull(fs, stored, MacLen);
                byte[] actual = MacOfRange(path, macKey, macAt);
                for (int i = 0; i < MacLen; i++) if (stored[i] != actual[i]) throw new CryptoException("wrong password or the file is corrupted");
            }
        }

        /// <summary>Decrypts inPath to outPath. Throws CryptoException on a wrong password or a corrupted file (before touching outPath's content beyond truncation).</summary>
        public static void Decrypt(string inPath, string outPath, string password, Action<double> progress)
        {
            ReadAndCheck(inPath, password); // fail fast, no partial output on bad password
            byte[] head = new byte[HeaderLen];
            using (FileStream fs = File.OpenRead(inPath)) ReadFull(fs, head, HeaderLen);
            byte[] salt = new byte[SaltLen]; Array.Copy(head, 8, salt, 0, SaltLen);
            byte[] iv = new byte[IvLen]; Array.Copy(head, 8 + SaltLen, iv, 0, IvLen);
            byte[] aesKey, macKey, check; Derive(password, salt, out aesKey, out macKey, out check);
            long fileLen = new FileInfo(inPath).Length; long cipherLen = fileLen - HeaderLen - MacLen;
            using (FileStream inFs = new FileStream(inPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20, FileOptions.SequentialScan))
            {
                inFs.Position = HeaderLen;
                using (Aes aes = Aes.Create()) { aes.KeySize = 256; aes.Key = aesKey; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                    using (ICryptoTransform dec = aes.CreateDecryptor())
                    using (FileStream outFs = new FileStream(outPath, FileMode.Create, FileAccess.Write, FileShare.None))
                    using (CryptoStream cs = new CryptoStream(outFs, dec, CryptoStreamMode.Write))
                    {
                        byte[] buf = new byte[1 << 20]; long left = cipherLen, done = 0; int n;
                        while (left > 0 && (n = inFs.Read(buf, 0, (int)Math.Min(buf.Length, left))) > 0) { cs.Write(buf, 0, n); left -= n; done += n; if (progress != null && cipherLen > 0) progress((double)done / cipherLen); }
                        cs.FlushFinalBlock();
                    }
                }
            }
            if (progress != null) progress(1);
        }
        static void ReadFull(Stream s, byte[] buf, int len) { int off = 0; while (off < len) { int n = s.Read(buf, off, len - off); if (n <= 0) throw new EndOfStreamException(); off += n; } }

        /// <summary>Overwrites a file's bytes with random data (passes times), truncates, renames, then deletes it.
        /// Note: on SSDs, wear-levelling means the original blocks may still exist physically; this defeats casual recovery, not forensics.</summary>
        public static void SecureWipe(string path, int passes, Action<double> progress)
        {
            long len = 0; try { len = new FileInfo(path).Length; } catch { }
            if (len > 0)
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.None))
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    byte[] buf = new byte[Math.Min(1 << 20, Math.Max(4096, len))];
                    for (int p = 0; p < Math.Max(1, passes); p++)
                    {
                        fs.Position = 0; long left = len;
                        while (left > 0) { int n = (int)Math.Min(buf.Length, left); if (p == passes - 1) Array.Clear(buf, 0, n); else rng.GetBytes(buf); fs.Write(buf, 0, n); left -= n; }
                        fs.Flush(true); if (progress != null) progress((double)(p + 1) / Math.Max(1, passes));
                    }
                    fs.SetLength(0);
                }
            }
            string dir = System.IO.Path.GetDirectoryName(path); string tmp = System.IO.Path.Combine(dir, Guid.NewGuid().ToString("N"));
            try { File.Move(path, tmp); File.Delete(tmp); } catch { File.Delete(path); }
        }
    }
}
