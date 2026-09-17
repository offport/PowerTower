// Sqlite: a tiny read-only reader for the SQLite file format, enough to pull tables out of browser history
// databases without any external library (the app ships as one exe built with the in-box compiler). It reads
// the file format directly - schema from sqlite_master, then the table B-tree, with overflow pages and every
// serial type. Not a general engine: no SQL, no writes, no indexes, no WAL merge.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PSTools
{
    public class SqliteException : Exception { public SqliteException(string m) : base(m) { } }

    public class SqliteTable
    {
        public readonly List<string> Columns = new List<string>();
        public readonly List<object[]> Rows = new List<object[]>();
        public int Index(string col) { for (int i = 0; i < Columns.Count; i++) if (string.Equals(Columns[i], col, StringComparison.OrdinalIgnoreCase)) return i; return -1; }
        /// <summary>Value in the named column, or null. rowid is exposed as the pseudo-column "rowid".</summary>
        public object Get(object[] row, string col) { int i = Index(col); return i >= 0 && i < row.Length ? row[i] : null; }
        public string Str(object[] row, string col) { object v = Get(row, col); return v == null ? "" : Convert.ToString(v); }
        public long Long(object[] row, string col) { object v = Get(row, col); try { return v == null ? 0 : Convert.ToInt64(v); } catch { return 0; } }
    }

    public static class Sqlite
    {
        /// <summary>Read a whole table by name. Column order matches the CREATE TABLE statement; a trailing "rowid" column is appended.</summary>
        public static SqliteTable Read(string path, string table) { return Read(path, table, int.MaxValue); }
        public static SqliteTable Read(string path, string table, int maxRows)
        {
            byte[] data = Snapshot(path);
            return new Reader(data).ReadTable(table, maxRows);
        }
        /// <summary>The table names present in the database.</summary>
        public static List<string> Tables(string path)
        {
            byte[] data = Snapshot(path); Reader r = new Reader(data); List<string> l = new List<string>();
            foreach (object[] row in r.Master()) { if (string.Equals((string)row[0], "table", StringComparison.OrdinalIgnoreCase)) l.Add((string)row[1]); }
            return l;
        }

        /// <summary>Copy the DB to a temp file so a running browser's lock/writes don't interfere; falls back to a shared read.</summary>
        static byte[] Snapshot(string path)
        {
            if (!File.Exists(path)) throw new SqliteException("no such file: " + path);
            try { using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) { using (MemoryStream ms = new MemoryStream()) { fs.CopyTo(ms); return ms.ToArray(); } } }
            catch (IOException)
            {
                string tmp = Path.Combine(Path.GetTempPath(), "pstools-db-" + Guid.NewGuid().ToString("N"));
                try { File.Copy(path, tmp, true); byte[] b = File.ReadAllBytes(tmp); return b; } finally { try { File.Delete(tmp); } catch { } }
            }
        }

        class Reader
        {
            readonly byte[] d; readonly int pageSize, usable;
            public Reader(byte[] data)
            {
                d = data;
                if (d.Length < 100 || d[0] != 'S' || d[1] != 'Q' || d[2] != 'L' || d[3] != 'i') throw new SqliteException("not a SQLite database");
                int ps = (d[16] << 8) | d[17]; pageSize = ps == 1 ? 65536 : ps;
                if (pageSize < 512 || (pageSize & (pageSize - 1)) != 0) throw new SqliteException("bad page size " + pageSize);
                int reserved = d[20]; usable = pageSize - reserved;
            }

            public SqliteTable ReadTable(string table, int maxRows)
            {
                int root = -1; string sql = null;
                foreach (object[] row in Master()) { if (string.Equals((string)row[0], "table", StringComparison.OrdinalIgnoreCase) && string.Equals((string)row[1], table, StringComparison.OrdinalIgnoreCase)) { root = Convert.ToInt32(row[3]); sql = row[4] as string; break; } }
                if (root < 0) throw new SqliteException("no such table: " + table);
                SqliteTable t = new SqliteTable(); t.Columns.AddRange(ParseColumns(sql)); t.Columns.Add("rowid");
                List<Cell> cells = new List<Cell>(); WalkTable(root, cells, maxRows, new HashSet<int>());
                foreach (Cell c in cells)
                {
                    object[] rec = ParseRecord(c.Payload); object[] full = new object[t.Columns.Count];
                    for (int i = 0; i < t.Columns.Count - 1; i++) full[i] = i < rec.Length ? rec[i] : null;
                    // SQLite stores an INTEGER PRIMARY KEY as NULL in the record and uses the rowid; expose rowid always
                    full[t.Columns.Count - 1] = c.RowId;
                    t.Rows.Add(full);
                    if (t.Rows.Count >= maxRows) break;
                }
                return t;
            }

            // sqlite_master is a table rooted at page 1 with columns type,name,tbl_name,rootpage,sql
            public List<object[]> Master()
            {
                List<object[]> outp = new List<object[]>(); List<Cell> cells = new List<Cell>(); WalkTable(1, cells, int.MaxValue, new HashSet<int>());
                foreach (Cell c in cells) { object[] rec = ParseRecord(c.Payload); object[] row = new object[5]; for (int i = 0; i < 5; i++) row[i] = i < rec.Length ? rec[i] : null; if (row[0] is byte[]) row[0] = Encoding.UTF8.GetString((byte[])row[0]); outp.Add(row); }
                return outp;
            }

            struct Cell { public long RowId; public byte[] Payload; }

            void WalkTable(int page, List<Cell> cells, int maxRows, HashSet<int> seen)
            {
                if (page < 1 || cells.Count >= maxRows) return; if (!seen.Add(page)) return; // guard against cycles
                int baseOff = (page - 1) * pageSize; int hdr = page == 1 ? baseOff + 100 : baseOff;
                if (hdr + 12 > d.Length) return;
                int type = d[hdr]; int nCells = (d[hdr + 3] << 8) | d[hdr + 4];
                bool interior = type == 5; bool leaf = type == 13;
                if (!interior && !leaf) return; // not a table b-tree page
                int cellPtrBase = hdr + (interior ? 12 : 8);
                for (int i = 0; i < nCells && cells.Count < maxRows; i++)
                {
                    int p = cellPtrBase + i * 2; if (p + 1 >= d.Length) break; int cellOff = baseOff + ((d[p] << 8) | d[p + 1]);
                    if (cellOff < 0 || cellOff >= d.Length) continue;
                    if (interior)
                    {
                        if (cellOff + 4 > d.Length) continue; int child = (int)ReadUint32(cellOff);
                        WalkTable(child, cells, maxRows, seen);
                    }
                    else
                    {
                        int o = cellOff; long payloadLen; o += Varint(o, out payloadLen); long rowid; o += Varint(o, out rowid);
                        byte[] payload = ReadPayload(o, payloadLen);
                        Cell c = new Cell(); c.RowId = rowid; c.Payload = payload; cells.Add(c);
                    }
                }
                if (interior && cells.Count < maxRows) { int right = (int)ReadUint32(hdr + 8); WalkTable(right, cells, maxRows, seen); }
            }

            // read a record payload that may spill onto overflow pages
            byte[] ReadPayload(int localOff, long payloadLen)
            {
                int P = (int)payloadLen; int U = usable; int maxLocal = U - 35; int minLocal = (U - 12) * 32 / 255 - 23;
                int local;
                if (P <= maxLocal) local = P;
                else { int k = minLocal + (P - minLocal) % (U - 4); local = k <= maxLocal ? k : minLocal; }
                byte[] buf = new byte[P]; int copied = Math.Min(local, Math.Max(0, d.Length - localOff)); if (copied > 0) Array.Copy(d, localOff, buf, 0, copied);
                int filled = copied;
                if (P > local)
                {
                    int overflowPtr = localOff + local; if (overflowPtr + 4 <= d.Length)
                    {
                        int nextPage = (int)ReadUint32(overflowPtr); int guard = 0;
                        while (nextPage != 0 && filled < P && guard++ < 100000)
                        {
                            int pgOff = (nextPage - 1) * pageSize; if (pgOff < 0 || pgOff + 4 > d.Length) break;
                            int next = (int)ReadUint32(pgOff); int avail = Math.Min(U - 4, P - filled); int src = pgOff + 4;
                            int can = Math.Min(avail, Math.Max(0, d.Length - src)); if (can > 0) Array.Copy(d, src, buf, filled, can); filled += can; nextPage = next;
                        }
                    }
                }
                return buf;
            }

            object[] ParseRecord(byte[] rec)
            {
                if (rec == null || rec.Length == 0) return new object[0];
                int o = 0; long hdrLen; o += Varint(rec, o, out hdrLen); int headerEnd = (int)hdrLen; if (headerEnd > rec.Length) headerEnd = rec.Length;
                List<long> types = new List<long>(); while (o < headerEnd) { long st; o += Varint(rec, o, out st); types.Add(st); }
                object[] vals = new object[types.Count]; int body = headerEnd;
                for (int i = 0; i < types.Count; i++) { object v; body = ReadValue(rec, body, types[i], out v); vals[i] = v; }
                return vals;
            }

            int ReadValue(byte[] b, int off, long serial, out object val)
            {
                switch (serial)
                {
                    case 0: val = null; return off;
                    case 1: val = (long)(sbyte)At(b, off); return off + 1;
                    case 2: val = (long)(short)((At(b, off) << 8) | At(b, off + 1)); return off + 2;
                    case 3: { int u = (At(b, off) << 16) | (At(b, off + 1) << 8) | At(b, off + 2); if ((u & 0x800000) != 0) u |= unchecked((int)0xFF000000); val = (long)u; return off + 3; }
                    case 4: { long u = ReadUint32(b, off); if ((u & 0x80000000L) != 0) u -= 0x100000000L; val = u; return off + 4; }
                    case 5: { long u = 0; for (int i = 0; i < 6; i++) u = (u << 8) | (uint)At(b, off + i); if ((u & 0x800000000000L) != 0) u -= 0x1000000000000L; val = u; return off + 6; }
                    case 6: { long u = 0; for (int i = 0; i < 8; i++) u = (u << 8) | (uint)At(b, off + i); val = u; return off + 8; }
                    case 7: { long u = 0; for (int i = 0; i < 8; i++) u = (u << 8) | (uint)At(b, off + i); val = BitConverter.Int64BitsToDouble(u); return off + 8; }
                    case 8: val = 0L; return off;
                    case 9: val = 1L; return off;
                    default:
                        if (serial >= 12)
                        {
                            int len = (int)((serial - (serial % 2 == 0 ? 12 : 13)) / 2); if (len < 0) len = 0; int avail = Math.Min(len, Math.Max(0, b.Length - off)); byte[] slice = new byte[avail]; if (avail > 0) Array.Copy(b, off, slice, 0, avail);
                            if (serial % 2 == 0) val = slice; else { try { val = Encoding.UTF8.GetString(slice); } catch { val = slice; } }
                            return off + len;
                        }
                        val = null; return off;
                }
            }

            static int At(byte[] b, int i) { return i >= 0 && i < b.Length ? b[i] : 0; }
            uint ReadUint32(int off) { return ReadUint32(d, off); }
            static uint ReadUint32(byte[] b, int off) { return (uint)((At(b, off) << 24) | (At(b, off + 1) << 16) | (At(b, off + 2) << 8) | At(b, off + 3)); }

            int Varint(int off, out long value) { return Varint(d, off, out value); }
            static int Varint(byte[] b, int off, out long value)
            {
                value = 0; int i = 0;
                for (; i < 8; i++) { int by = At(b, off + i); value = (value << 7) | (long)(by & 0x7F); if ((by & 0x80) == 0) return i + 1; }
                value = (value << 8) | (long)(uint)At(b, off + 8); return 9;
            }
        }

        // ── column names from a CREATE TABLE statement (best-effort) ──
        static List<string> ParseColumns(string sql)
        {
            List<string> cols = new List<string>();
            if (string.IsNullOrEmpty(sql)) return cols;
            int lp = sql.IndexOf('('); int rp = sql.LastIndexOf(')'); if (lp < 0 || rp <= lp) return cols;
            string body = sql.Substring(lp + 1, rp - lp - 1);
            foreach (string part in SplitTopLevel(body))
            {
                string s = part.Trim(); if (s.Length == 0) continue;
                string up = s.ToUpperInvariant();
                if (up.StartsWith("PRIMARY KEY") || up.StartsWith("UNIQUE") || up.StartsWith("CHECK") || up.StartsWith("FOREIGN KEY") || up.StartsWith("CONSTRAINT")) continue;
                string name; int q = 0;
                if (s[0] == '"' || s[0] == '`' || s[0] == '[') { char close = s[0] == '[' ? ']' : s[0]; int e = s.IndexOf(close, 1); name = e > 0 ? s.Substring(1, e - 1) : s.Substring(1); }
                else { while (q < s.Length && !char.IsWhiteSpace(s[q])) q++; name = s.Substring(0, q); }
                if (name.Length > 0) cols.Add(name);
            }
            return cols;
        }
        static IEnumerable<string> SplitTopLevel(string body)
        {
            int depth = 0, start = 0; bool inStr = false; char strCh = '"';
            for (int i = 0; i < body.Length; i++)
            {
                char c = body[i];
                if (inStr) { if (c == strCh) inStr = false; continue; }
                if (c == '"' || c == '\'' || c == '`') { inStr = true; strCh = c; }
                else if (c == '(') depth++;
                else if (c == ')') depth--;
                else if (c == ',' && depth == 0) { yield return body.Substring(start, i - start); start = i + 1; }
            }
            if (start < body.Length) yield return body.Substring(start);
        }

        // ── browser timestamp helpers ──
        static readonly DateTime ChromeEpoch = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        public static DateTime ChromeTime(long micros) { if (micros <= 0) return DateTime.MinValue; try { return ChromeEpoch.AddTicks(micros * 10).ToLocalTime(); } catch { return DateTime.MinValue; } }
        public static DateTime UnixMicros(long micros) { if (micros <= 0) return DateTime.MinValue; try { return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddTicks(micros * 10).ToLocalTime(); } catch { return DateTime.MinValue; } }
        public static DateTime UnixSeconds(long secs) { if (secs <= 0) return DateTime.MinValue; try { return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(secs).ToLocalTime(); } catch { return DateTime.MinValue; } }
    }
}
