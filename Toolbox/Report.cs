// Report.cs - Phase 2 reporting. The ptreport/1 contract: one JSON document per deliverable, every row with a stable id,
// severity, status, evidence, framework refs and an as-of stamp; a small JSON-Schema validator so the contract is
// checked against schemas\ptreport-1.schema.json; the Vulnerability report built from an enriched bundle; and the
// renderers - JSON (the source of truth), CSV (formula-safe), Markdown, a self-contained HTML page, and a Helvetica PDF
// with severity chips and page numbers. Reports are reproducible: nothing here reads the clock, every stamp comes from
// the bundle. Every client-controlled string is escaped by the renderer that emits it.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace PSTools
{
    // ───────────────────────────── JSON Schema, draft-07 subset ─────────────────────────────
    /// <summary>type (name or list), properties, required, additionalProperties (false or a schema), items, enum, const, minimum/maximum, minItems, maxLength, pattern, $ref "#/definitions/x". Enough to keep the report contract honest without a dependency.</summary>
    public static class JsonSchema
    {
        public static List<string> Validate(object schema, object doc) { List<string> errs = new List<string>(); Check(schema, schema, doc, "$", errs, 0); return errs; }
        static void Check(object root, object s, object v, string path, List<string> errs, int depth)
        {
            if (depth > 64 || errs.Count > 200) return; Dictionary<string, object> sd = Json.Obj(s); if (sd == null) return;
            string r = Json.GetS(sd, "$ref"); if (r != null) { object t = Resolve(root, r); if (t == null) { errs.Add(path + ": unresolved $ref " + r); return; } Check(root, t, v, path, errs, depth + 1); return; }
            object type = Json.Get(sd, "type"); if (type != null && !TypeOk(type, v)) { errs.Add(path + ": expected " + TypeText(type) + ", got " + Kind(v)); return; }
            object en = Json.Get(sd, "enum"); if (en != null) { bool ok = false; foreach (object e in Json.Arr(en)) if (Same(e, v)) ok = true; if (!ok) errs.Add(path + ": '" + (Json.S(v) ?? "null") + "' is not one of the allowed values"); }
            if (sd.ContainsKey("const") && !Same(sd["const"], v)) errs.Add(path + ": must be " + JsonWrite.Text(sd["const"], false));
            if (v is double) { double d = (double)v; double? min = Json.N(Json.Get(sd, "minimum")), max = Json.N(Json.Get(sd, "maximum")); if (min.HasValue && d < min.Value) errs.Add(path + ": " + d + " is below the minimum " + min.Value); if (max.HasValue && d > max.Value) errs.Add(path + ": " + d + " is above the maximum " + max.Value); }
            string str = v as string;
            if (str != null) { double? ml = Json.N(Json.Get(sd, "maxLength")); if (ml.HasValue && str.Length > ml.Value) errs.Add(path + ": longer than " + ml.Value); string pat = Json.GetS(sd, "pattern"); if (pat != null && !Regex.IsMatch(str, pat)) errs.Add(path + ": '" + (str.Length > 40 ? str.Substring(0, 40) + "…" : str) + "' does not match " + pat); }
            Dictionary<string, object> obj = Json.Obj(v);
            if (obj != null)
            {
                foreach (object req in Json.Arr(Json.Get(sd, "required"))) { string k = Json.S(req); if (k != null && !obj.ContainsKey(k)) errs.Add(path + ": missing required '" + k + "'"); }
                Dictionary<string, object> props = Json.Obj(Json.Get(sd, "properties")); object addl = Json.Get(sd, "additionalProperties");
                foreach (KeyValuePair<string, object> p in obj)
                {
                    object ps = props != null && props.ContainsKey(p.Key) ? props[p.Key] : null;
                    if (ps != null) Check(root, ps, p.Value, path + "." + p.Key, errs, depth + 1);
                    else if (addl is bool && !(bool)addl) errs.Add(path + ": unexpected property '" + p.Key + "'");
                    else if (Json.Obj(addl) != null) Check(root, addl, p.Value, path + "." + p.Key, errs, depth + 1);
                }
            }
            List<object> arr = v as List<object>;
            if (arr != null) { double? mi = Json.N(Json.Get(sd, "minItems")); if (mi.HasValue && arr.Count < mi.Value) errs.Add(path + ": fewer than " + mi.Value + " items"); object items = Json.Get(sd, "items"); if (items != null) for (int i = 0; i < arr.Count; i++) Check(root, items, arr[i], path + "[" + i + "]", errs, depth + 1); }
        }
        static object Resolve(object root, string r) { if (!r.StartsWith("#/")) return null; object cur = root; foreach (string part in r.Substring(2).Split('/')) { cur = Json.Get(cur, part); if (cur == null) return null; } return cur; }
        static bool TypeOk(object type, object v)
        {
            List<object> types = type as List<object>; if (types != null) { foreach (object t in types) if (TypeOk(t, v)) return true; return false; }
            switch (Json.S(type)) { case "string": return v is string; case "number": return v is double; case "integer": return v is double && Math.Floor((double)v) == (double)v; case "boolean": return v is bool; case "object": return v is Dictionary<string, object>; case "array": return v is List<object>; case "null": return v == null; default: return true; }
        }
        static string Kind(object v) { return v == null ? "null" : v is string ? "string" : v is double ? "number" : v is bool ? "boolean" : v is List<object> ? "array" : v is Dictionary<string, object> ? "object" : v.GetType().Name; }
        static string TypeText(object t) { List<object> l = t as List<object>; if (l == null) return Json.S(t) ?? "?"; List<string> s = new List<string>(); foreach (object x in l) s.Add(Json.S(x)); return string.Join(" or ", s.ToArray()); }
        static bool Same(object a, object b) { return JsonWrite.Text(a, false) == JsonWrite.Text(b, false); }
    }

    // ───────────────────────────── brand ─────────────────────────────
    /// <summary>brand\brand.json + a logo SVG beside it; anything missing falls back to a neutral mark. The logo is embedded only if it is self-contained (no script, no image, no link, no URL beyond the SVG namespaces).</summary>
    public class Brand
    {
        public string Name = "PowerTower", Line = "Endpoint security report", Footer = "For authorised use only. Prepared for the named client under the stated engagement; not for onward distribution.";
        public string Accent = "#0B7304", Ink = "#0A0D0B", Paper = "#FFFFFF", Panel = "#EDEFEA", Muted = "#525B55", Rule = "#C9CEC9"; public string LogoSvg = "";
        public readonly Dictionary<string, string> Severity = new Dictionary<string, string>();
        public Brand() { Severity["Critical"] = "#C4231B"; Severity["High"] = "#B45309"; Severity["Medium"] = "#8A6D00"; Severity["Low"] = "#2E7D32"; Severity["Unrated"] = "#7C867F"; }
        public static string DefaultDir { get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "brand"); } }
        public static Brand Load(string dir)
        {
            Brand b = new Brand(); if (dir == null || !Directory.Exists(dir)) return b; string jf = Path.Combine(dir, "brand.json");
            if (File.Exists(jf))
            {
                try
                {
                    object t = Json.Parse(File.ReadAllText(jf, Encoding.UTF8));
                    b.Name = Json.GetS(t, "name") ?? b.Name; b.Line = Json.GetS(t, "line") ?? b.Line; b.Footer = Json.GetS(t, "footer") ?? b.Footer;
                    b.Accent = Hex(Json.GetS(t, "accent"), b.Accent); b.Ink = Hex(Json.GetS(t, "ink"), b.Ink); b.Paper = Hex(Json.GetS(t, "paper"), b.Paper); b.Panel = Hex(Json.GetS(t, "panel"), b.Panel); b.Muted = Hex(Json.GetS(t, "muted"), b.Muted); b.Rule = Hex(Json.GetS(t, "rule"), b.Rule);
                    Dictionary<string, object> sev = Json.Obj(Json.Get(t, "severity")); if (sev != null) foreach (KeyValuePair<string, object> p in sev) if (b.Severity.ContainsKey(p.Key)) b.Severity[p.Key] = Hex(Json.S(p.Value), b.Severity[p.Key]);
                    string logo = Json.GetS(t, "logo"); if (logo != null && logo.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 && File.Exists(Path.Combine(dir, logo))) b.LogoSvg = File.ReadAllText(Path.Combine(dir, logo), Encoding.UTF8);
                }
                catch { }
            }
            return b;
        }
        /// <summary>Colours are the one thing from brand.json that lands inside the HTML and PDF unescaped, so they must be exactly #rrggbb.</summary>
        static string Hex(string s, string def) { return s != null && Regex.IsMatch(s, "^#[0-9A-Fa-f]{6}$") ? s.ToUpperInvariant() : def; }
        public string SafeLogo(string fallbackText) { return Embeddable(LogoSvg) ? LogoSvg.Trim() : NeutralLogo(fallbackText, Accent, Ink); }
        public static bool Embeddable(string svg)
        {
            if (string.IsNullOrEmpty(svg) || svg.Length > 200000) return false; string t = svg.TrimStart(); if (!t.StartsWith("<svg")) return false; string low = svg.ToLowerInvariant();
            if (low.Contains("<script") || low.Contains("javascript:") || low.Contains("<image") || low.Contains("<foreignobject") || low.Contains("href=") || low.Contains("url(") || low.Contains("<use") || low.Contains("<a ") || Regex.IsMatch(low, @"\son[a-z]+\s*=")) return false;
            return Regex.Replace(svg, "xmlns(:[A-Za-z0-9]+)?=\"http[^\"]*\"", "").IndexOf("http", StringComparison.OrdinalIgnoreCase) < 0;
        }
        public static string NeutralLogo(string text, string accent, string ink)
        {
            string t = (text ?? "").Length > 24 ? text.Substring(0, 24) : (text ?? "");
            return "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 320 48\" width=\"320\" height=\"48\" role=\"img\" aria-label=\"" + Html.Esc(t) + "\"><rect x=\"2\" y=\"6\" width=\"36\" height=\"36\" rx=\"6\" fill=\"" + accent + "\"/><path d=\"M10 30 L20 14 L30 30\" fill=\"none\" stroke=\"#FFFFFF\" stroke-width=\"4\" stroke-linejoin=\"round\"/><text x=\"50\" y=\"33\" font-family=\"Arial, Helvetica, sans-serif\" font-size=\"26\" font-weight=\"700\" fill=\"" + ink + "\">" + Html.Esc(t) + "</text></svg>";
        }
    }

    public static class Html
    {
        /// <summary>Escapes everything that can start markup or leave an attribute: &amp; &lt; &gt; &quot; &#39;.</summary>
        public static string Esc(string s) { if (string.IsNullOrEmpty(s)) return ""; StringBuilder sb = new StringBuilder(s.Length + 16); foreach (char c in s) { switch (c) { case '&': sb.Append("&amp;"); break; case '<': sb.Append("&lt;"); break; case '>': sb.Append("&gt;"); break; case '"': sb.Append("&quot;"); break; case '\'': sb.Append("&#39;"); break; default: if (c < ' ' && c != '\t' && c != '\n' && c != '\r') sb.Append(' '); else sb.Append(c); break; } } return sb.ToString(); }
    }

    // ───────────────────────────── the contract ─────────────────────────────
    public static class Ptreport
    {
        public const string Schema = "ptreport/1";
        public static string SchemaDir { get { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "schemas"); } }
        public static object LoadSchema(string name) { string p = Path.Combine(SchemaDir, name); if (!File.Exists(p)) throw new BundleException("schema not found: " + p); return Json.Parse(File.ReadAllText(p, Encoding.UTF8)); }
        /// <summary>The document as it will be written (serialised then parsed) against schemas\ptreport-1.schema.json.</summary>
        public static List<string> Validate(Dictionary<string, object> report) { return JsonSchema.Validate(LoadSchema("ptreport-1.schema.json"), Json.Parse(JsonWrite.Text(report, false))); }
        /// <summary>Stable ids: PT-W-&lt;AREA&gt;-&lt;parts&gt;, parts reduced to [A-Za-z0-9.-].</summary>
        public static string RowId(string area, params string[] parts)
        {
            StringBuilder sb = new StringBuilder("PT-W-" + area);
            foreach (string p in parts) { StringBuilder c = new StringBuilder(); foreach (char ch in p ?? "") if (char.IsLetterOrDigit(ch) || ch == '.' || ch == '-') c.Append(ch); if (c.Length > 0) sb.Append('-').Append(c.ToString()); }
            return sb.ToString();
        }
        public static Dictionary<string, object> Ref(string framework, string reference, string note) { Dictionary<string, object> d = new Dictionary<string, object>(); d["framework"] = framework; d["ref"] = reference; d["note"] = note; return d; }
        public static string Short(string s) { return BundleCrypto.Sha256Hex(Encoding.UTF8.GetBytes(s ?? "")).Substring(0, 6); }
    }

    // ───────────────────────────── the Vulnerability report ─────────────────────────────
    public static class VulnReport
    {
        public const string Kind = "vulnerability", Title = "Endpoint Vulnerability Report";
        static readonly Regex KbRx = new Regex(@"KB(\d{5,8})", RegexOptions.IgnoreCase);
        public static readonly string MethodText = "Findings are version- and build-based: Microsoft CVEs come from the MSRC monthly releases compared with the host's build (major.minor.build.UBR) and installed KBs including supersedence; third-party CVEs come from the NVD matched on vendor, product and the installed version; CISA KEV marks known-exploited CVEs; EPSS gives the probability of exploitation in the next 30 days. The MSRC window follows the host's patch level, so a stale host is judged against every release it missed. Nothing was exploited or executed on the host; a finding is a missing fix, not a proven compromise.";

        public static Dictionary<string, object> Build(Bundle b, Brand brand)
        {
            object fd = b["findings"]; if (fd == null) throw new BundleException("the bundle has no findings section - run `enrich` on it first");
            // PT-45: a findings section of the wrong shape is refused, never read as an empty (clean) result
            if (Json.Obj(fd) == null) throw new BundleException("the bundle's findings section is not an object - run `enrich` on it again");
            if (!(Json.Get(fd, "items") is System.Collections.IList)) throw new BundleException("the bundle's findings.items is not a list - run `enrich` on it again");
            object inv = b["inventory"]; OsInfo os = Codec.OsFrom(Json.Get(inv, "os"));
            Dictionary<string, object> asOfRaw = Json.Obj(Json.Get(fd, "asOf")); bool haveAsOf = asOfRaw != null; Dictionary<string, object> asOf = asOfRaw ?? new Dictionary<string, object>();
            string enrichedUtc = Json.GetS(b.Manifest, "enriched", "utc") ?? Json.GetS(asOf, "enrichedUtc") ?? "", collectedUtc = Json.GetS(b.Manifest, "finishedUtc") ?? Json.GetS(b.Manifest, "startedUtc") ?? "";
            List<Finding> all = new List<Finding>(); foreach (object it in Json.Arr(Json.Get(fd, "items"))) all.Add(Codec.FindingFrom(it));
            all.Sort(delegate (Finding x, Finding y) { int c = y.SortScore.CompareTo(x.SortScore); return c != 0 ? c : string.CompareOrdinal(y.Cve, x.Cve); });
            Dictionary<string, string> relStamp = new Dictionary<string, string>(); foreach (object u in Json.Arr(Json.Get(asOf, "msrc", "releases"))) { string rel = Json.GetS(u, "release"), st = Json.GetS(u, "cached"); if (rel != null && st != null) relStamp[rel] = st; }
            string nvdStamp = Json.GetS(asOf, "nvd", "newestCache") ?? enrichedUtc;
            List<object> rows = new List<object>(), unconfirmed = new List<object>(); int rank = 0, crit = 0, high = 0, med = 0, low = 0, unrated = 0, kev = 0, open = 0, patched = 0;
            Dictionary<string, Dictionary<string, object>> byKb = new Dictionary<string, Dictionary<string, object>>(), byProd = new Dictionary<string, Dictionary<string, object>>(); List<string> kbOrder = new List<string>(), prodOrder = new List<string>();
            foreach (Finding f in all)
            {
                Dictionary<string, object> row = Row(f, relStamp, nvdStamp, enrichedUtc, collectedUtc);
                if (f.Status == "unconfirmed") { unconfirmed.Add(row); continue; }
                row["rank"] = ++rank; rows.Add(row);
                if (!f.Open) { patched++; continue; }
                open++; if (f.Kev || f.Exploited) kev++;
                switch (f.SeverityNorm) { case "Critical": crit++; break; case "High": high++; break; case "Medium": med++; break; case "Low": low++; break; default: unrated++; break; }   // PT-48: an unrated open finding is counted, not dropped from the headline
                if (f.Source == "NVD") Group(byProd, prodOrder, f.Product, "product", f, f.Installed, f.Fix);
                else { Match m = KbRx.Match(f.Fix ?? ""); string kb = m.Success ? "KB" + m.Groups[1].Value : (f.Fix.Length > 0 ? f.Fix : "(no fix named)"); Group(byKb, kbOrder, kb, "kb", f, "", f.Fix); }
            }
            Dictionary<string, object> r = new Dictionary<string, object>(); r["schema"] = Ptreport.Schema; r["report"] = Kind; r["title"] = Title;
            Dictionary<string, object> subject = new Dictionary<string, object>(); subject["host"] = b.Host; subject["domain"] = Json.GetS(b.Manifest, "domain") ?? ""; subject["platform"] = (Json.GetS(b.Manifest, "platform") ?? "windows"); subject["mode"] = (Json.GetS(b.Manifest, "mode") ?? "live");
            Dictionary<string, object> osd = new Dictionary<string, object>(); osd["productName"] = os.ProductName; osd["displayVersion"] = os.DisplayVersion; osd["fullBuild"] = os.FullBuild; osd["arch"] = os.Arch; subject["os"] = osd;
            subject["runId"] = b.RunId; subject["engagementId"] = Json.GetS(b.Manifest, "engagementId") ?? ""; subject["collectedUtc"] = collectedUtc; subject["enrichedUtc"] = enrichedUtc; subject["privilegeTier"] = Json.GetS(b.Manifest, "privilegeTier") ?? ""; subject["collector"] = Json.Obj(Json.Get(b.Manifest, "collector")) ?? new Dictionary<string, object>();
            r["subject"] = subject; r["asOf"] = asOf;
            Dictionary<string, object> s = new Dictionary<string, object>(); s["open"] = open; s["patched"] = patched; s["total"] = rows.Count; s["critical"] = crit; s["high"] = high; s["medium"] = med; s["low"] = low; s["unrated"] = unrated; s["knownExploited"] = kev; s["unconfirmed"] = unconfirmed.Count;
            int window = JsonWrite.Int(Json.Get(fd, "msrcWindow"), 0); List<string> releases = new List<string>(JsonWrite.Strings(Json.Get(fd, "releases"))); s["msrcWindow"] = window; s["releases"] = releases;
            // PT-45: the verdict fails closed. Nothing reads as clean unless every requested MSRC release was read, every feed answered and enrichment logged no problem;
            // the verdict goes into the headline of every format and into summary.status / summary.coverage, never only into method.coverage.
            Coverage cv = Coverage.Of(asOf, haveAsOf, window, releases.Count, new List<string>(JsonWrite.Strings(Json.Get(fd, "errors"))));
            s["status"] = cv.Status; s["assessable"] = cv.Status == "assessed"; s["coverage"] = cv.ToJson();
            string counts = open + " open finding" + (open == 1 ? "" : "s") + " (" + crit + " critical, " + high + " high, " + med + " medium, " + low + " low, " + unrated + " unrated), " + kev + " of them known to be exploited; " + patched + " already patched; " + unconfirmed.Count + " third-party match" + (unconfirmed.Count == 1 ? "" : "es") + " could not be confirmed against the installed version.";
            if (cv.Status == "not-assessable") s["headline"] = "NOT ASSESSABLE - the vulnerability feeds could not be checked (" + cv.Summary() + "). This is not a clean result: nothing in this report says the host is patched. Repair the feed cache or go online, then run `enrich` again.";
            else if (cv.Status == "incomplete-coverage") s["headline"] = "INCOMPLETE COVERAGE - " + cv.Summary() + ". The findings below are real but partial: a release or feed that was not read may hide more, so this is not a clean result. So far: " + counts;
            else s["headline"] = open == 0 ? "No open vulnerabilities were found against the feeds as of the stated dates: every Microsoft CVE in the checked releases is fixed on this build and no third-party product at its installed version has a known CVE." : counts;
            r["summary"] = s; r["rows"] = rows; r["unconfirmed"] = unconfirmed;
            Dictionary<string, object> rem = new Dictionary<string, object>(); List<object> bu = new List<object>(); foreach (string k in kbOrder) bu.Add(byKb[k]); List<object> bp = new List<object>(); foreach (string k in prodOrder) bp.Add(byProd[k]); rem["byUpdate"] = bu; rem["byProduct"] = bp; r["remediation"] = rem;
            Dictionary<string, object> method = new Dictionary<string, object>(); method["text"] = MethodText;
            List<string> lim = new List<string>(); lim.Add("Version/build-based, not exploit-validated: a finding means the fix is missing, not that the weakness was exploited or exploitable in this environment. The 'validated' column is filled in by a separate exploit-validation pass (confirmed / not exploitable / untested).");
            lim.Add("Only products the inventory could map to an NVD vendor:product with a comparable version were checked; software with no version or an unmapped name was not."); lim.Add("Feeds are judged as of the dates in the as-of block; a CVE published or added to KEV after those dates is not here."); lim.Add("Unconfirmed matches are NVD records without version bounds for a product that is installed; they need a manual check and are listed separately, not counted as open.");
            string missing = Json.GetS(inv, "missingStatus") ?? ""; if (missing.StartsWith("not searched")) lim.Add("Windows Update was not asked which updates it offers (offline collection); 'update available' therefore comes from MSRC build comparison only."); if (JsonWrite.Bool(Json.Get(asOf, "msrc", "newestUpdateInFuture"))) lim.Add("The bundle's newest-update date lies in the future and was not trusted; the widest MSRC window was checked instead.");
            lim.Add("Rows are ordered by a composite score - open before closed, known-exploited first, then severity, CVSS and EPSS - so among closed rows a higher severity can precede a higher CVSS; the per-row 'score' is in the JSON.");
            method["limitations"] = lim;
            Dictionary<string, object> cov = new Dictionary<string, object>(); cov["status"] = cv.Status; cov["releasesChecked"] = releases.Count; cov["feedsUnavailable"] = new List<string>(cv.FeedsDown); cov["msrcWindow"] = s["msrcWindow"]; cov["releases"] = s["releases"]; cov["minimumMonths"] = Json.Get(asOf, "msrc", "minimum"); cov["newestUpdate"] = Json.Get(asOf, "msrc", "newestUpdate"); cov["offline"] = Json.Get(asOf, "offline"); cov["missingUpdateSearch"] = missing; cov["problems"] = new List<string>(JsonWrite.Strings(Json.Get(fd, "errors"))); cov["privilegeTier"] = subject["privilegeTier"]; cov["softwareInventoried"] = Json.Arr(Json.Get(inv, "software")).Count; cov["nvdProductsLookedUp"] = Json.Get(asOf, "nvd", "products");
            method["coverage"] = cov; r["method"] = method;
            Dictionary<string, object> br = new Dictionary<string, object>(); br["name"] = brand.Name; br["line"] = brand.Line; br["footer"] = brand.Footer; r["brand"] = br;
            return r;
        }
        static void Group(Dictionary<string, Dictionary<string, object>> g, List<string> order, string key, string keyName, Finding f, string installed, string fix)
        {
            Dictionary<string, object> d; if (!g.TryGetValue(key, out d)) { d = new Dictionary<string, object>(); d[keyName] = key; if (keyName == "product") { d["installed"] = installed; d["fix"] = fix ?? ""; } else d["products"] = new List<string>(); d["cves"] = new List<string>(); d["openCount"] = 0; d["worstSeverity"] = "Unrated"; d["knownExploited"] = false; g[key] = d; order.Add(key); }
            ((List<string>)d["cves"]).Add(f.Cve); d["openCount"] = (int)d["openCount"] + 1; if (f.Kev || f.Exploited) d["knownExploited"] = true;
            string sev = f.SeverityNorm.Length > 0 ? f.SeverityNorm : "Unrated"; if (Resolve.SevRank(sev) > Resolve.SevRank((string)d["worstSeverity"])) d["worstSeverity"] = sev;
            if (keyName == "kb") { List<string> ps = (List<string>)d["products"]; if (!ps.Contains(f.Product)) ps.Add(f.Product); }
            else if (((string)d["fix"]).Length == 0 && !string.IsNullOrEmpty(fix)) d["fix"] = fix;
        }
        static Dictionary<string, object> Row(Finding f, Dictionary<string, string> relStamp, string nvdStamp, string enrichedUtc, string collectedUtc)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            d["id"] = Ptreport.RowId("VULN", f.Cve.Replace("CVE-", ""), Ptreport.Short(f.Product)); d["severity"] = f.SeverityNorm.Length > 0 ? f.SeverityNorm : "Unrated"; d["status"] = f.Status; d["evidence"] = f.Evidence; d["frameworkRefs"] = Refs(f.Source);
            string st; d["asOf"] = f.Source == "NVD" ? nvdStamp : f.Source == "Windows Update" ? (collectedUtc.Length > 0 ? collectedUtc : enrichedUtc) : (relStamp.TryGetValue(f.Release ?? "", out st) ? st : enrichedUtc);
            d["title"] = f.Title; d["cve"] = f.Cve; d["source"] = f.Source; d["product"] = f.Product; d["installed"] = f.Installed; d["fix"] = f.Fix; d["cvss"] = f.Cvss.HasValue ? (object)f.Cvss.Value : null; d["epss"] = f.Epss.HasValue ? (object)f.Epss.Value : null;
            d["kev"] = f.Kev; d["ransomware"] = f.Ransomware; d["kevDue"] = f.KevDue; d["exploited"] = f.Exploited; d["url"] = f.Url; d["release"] = f.Release; d["validated"] = f.Validated; d["open"] = f.Open; d["score"] = Math.Round(f.SortScore, 3);
            return d;
        }
        /// <summary>What a missing fix is evidence for. CIS Controls v8 safeguards are referenceable; Essential Eight is "evidence toward" a strategy, never an assessed maturity level; CSF 2.0 subcategory ids.</summary>
        static List<object> Refs(string source)
        {
            List<object> l = new List<object>(); bool os = source != "NVD";
            l.Add(Ptreport.Ref("CIS Controls v8", os ? "7.3" : "7.4", os ? "Perform automated operating system patch management" : "Perform automated application patch management"));
            l.Add(Ptreport.Ref("ACSC Essential Eight", os ? "Patch operating systems" : "Patch applications", "evidence toward the strategy, not an assessed maturity level"));
            l.Add(Ptreport.Ref("NIST CSF 2.0", "ID.RA-01", "Vulnerabilities in assets are identified, validated, and recorded"));
            return l;
        }
    }

    // ───────────────────────────── coverage verdict (PT-45) ─────────────────────────────
    /// <summary>How much of the assessment actually happened. assessed: every requested MSRC monthly release was read, every feed answered and enrichment logged no problem. incomplete-coverage: something was checked, but not everything. not-assessable: nothing usable was checked (no release read, or no as-of block). The report layer fails closed on this: the verdict leads the headline in every format.</summary>
    public class Coverage
    {
        public string Status = "assessed"; public int Checked, Expected; public List<string> FeedsDown = new List<string>(), Problems = new List<string>();
        static readonly string[] Feeds = { "MSRC", "NVD", "KEV", "EPSS" };
        public static Coverage Of(Dictionary<string, object> asOf, bool haveAsOf, int expected, int checkedCount, List<string> problems)
        {
            Coverage c = new Coverage(); c.Expected = expected; c.Checked = checkedCount; c.Problems = problems ?? new List<string>();
            foreach (string feed in Feeds)
            {
                bool present = haveAsOf && Json.Get(asOf, feed.ToLowerInvariant()) != null, failed = false;
                foreach (string p in c.Problems) if (p.StartsWith(feed, StringComparison.OrdinalIgnoreCase)) failed = true;   // enrich logs "MSRC 2026-Oct: …", "NVD cpe:…", "KEV: …", "EPSS: …"
                if (feed == "MSRC") failed = checkedCount == 0;   // a partly read MSRC window is already stated as "n of m releases checked"; "unavailable" means none was read
                if (!present || failed) c.FeedsDown.Add(feed);
            }
            if (!haveAsOf || checkedCount == 0 || Json.Get(asOf, "msrc") == null) c.Status = "not-assessable";
            else if (c.Problems.Count > 0 || checkedCount < expected || c.FeedsDown.Count > 0) c.Status = "incomplete-coverage";
            return c;
        }
        /// <summary>The facts for the headline: releases read of requested, feeds that did not answer, problems logged.</summary>
        public string Summary()
        {
            string s = Checked + " of " + Expected + " MSRC monthly release" + (Expected == 1 ? "" : "s") + " checked";
            if (FeedsDown.Count > 0) s += "; feed" + (FeedsDown.Count == 1 ? "" : "s") + " unavailable: " + string.Join(", ", FeedsDown.ToArray());
            if (Problems.Count > 0) s += "; " + Problems.Count + " problem" + (Problems.Count == 1 ? "" : "s") + " during enrichment";
            return s;
        }
        public Dictionary<string, object> ToJson()
        {
            Dictionary<string, object> d = new Dictionary<string, object>(); d["status"] = Status; d["releasesChecked"] = Checked; d["releasesExpected"] = Expected; d["feedsUnavailable"] = new List<string>(FeedsDown); d["problems"] = Problems.Count; d["text"] = Summary(); return d;
        }
    }

    // ───────────────────────────── renderers ─────────────────────────────
    public static class ReportRender
    {
        static string S(object o, string k) { return Json.GetS(o, k) ?? ""; }
        static string E(string s) { return Html.Esc(s); }
        static string Num(object o, string k, string fmt) { double? n = Json.N(Json.Get(o, k)); return n.HasValue ? n.Value.ToString(fmt, CultureInfo.InvariantCulture) : ""; }
        static bool B(object o, string k) { return JsonWrite.Bool(Json.Get(o, k)); }
        /// <summary>PT-46, prose the report composes itself (headline, method, brand): every Markdown-active ASCII punctuation is backslash-escaped, angle brackets become entities, and anything shaped like a URL or an e-mail address is emitted as inline code so no renderer autolinks it.</summary>
        static readonly Regex LinkRx = new Regex(@"(?i)\b(?:https?://|www\.)\S+|[^\s@`]+@[^\s@`]+\.[^\s@`]+");
        static string Md(string s)
        {
            if (string.IsNullOrEmpty(s)) return ""; StringBuilder sb = new StringBuilder(s.Length + 16); int at = 0;
            foreach (Match m in LinkRx.Matches(s)) { MdText(sb, s.Substring(at, m.Index - at)); sb.Append(Mc(m.Value)); at = m.Index + m.Length; }
            MdText(sb, s.Substring(at)); return sb.ToString();
        }
        static void MdText(StringBuilder sb, string s)
        {
            foreach (char c in s) { if (c == '<') sb.Append("&lt;"); else if (c == '>') sb.Append("&gt;"); else if (c == '\r' || c == '\n') sb.Append(' '); else { if ("\\`*_{}[]()#+-.!|~".IndexOf(c) >= 0) sb.Append('\\'); sb.Append(c); } }
        }
        /// <summary>PT-46, data from the audited host (names, titles, evidence, versions, ids, dates): one inline code span, fenced with one more backtick than the longest run inside, so links, images, emphasis, HTML and autolinks are all inert. Pipes stay escaped for the table; angle brackets become entities for a renderer that is careless with code spans.</summary>
        static string Mc(string s)
        {
            if (string.IsNullOrEmpty(s)) return ""; s = s.Replace("\r", " ").Replace("\n", " ").Replace("|", "\\|").Replace("<", "&lt;").Replace(">", "&gt;");
            int run = 0, longest = 0; foreach (char c in s) { run = c == '`' ? run + 1 : 0; if (run > longest) longest = run; }
            string fence = new string('`', longest + 1); bool pad = s[0] == '`' || s[s.Length - 1] == '`'; return fence + (pad ? " " : "") + s + (pad ? " " : "") + fence;
        }
        /// <summary>PT-45: the coverage verdict with its problems at the top of the Markdown when the report is not a clean assessment.</summary>
        static string MdBanner(Dictionary<string, object> r)
        {
            object sum = Json.Get(r, "summary"); string st = S(sum, "status"); if (st == "assessed") return "";
            StringBuilder sb = new StringBuilder(); sb.Append("> **").Append(st == "not-assessable" ? "NOT ASSESSABLE" : "INCOMPLETE COVERAGE").Append("** — ").Append(Md(S(sum, "headline"))).Append("\n");
            List<string> probs = JsonWrite.Strings(Json.Get(r, "method", "coverage", "problems")); int n = 0;
            foreach (string p in probs) { if (++n > 12) { sb.Append(">\n> - … and ").Append(probs.Count - 12).Append(" more (method.coverage.problems in the JSON)\n"); break; } sb.Append(">\n> - ").Append(Md(p)).Append("\n"); }
            return sb.Append("\n").ToString();
        }
        /// <summary>PT-45: the same verdict and problems, above the cards in the HTML.</summary>
        static string HtmlBanner(Dictionary<string, object> r)
        {
            object sum = Json.Get(r, "summary"); string st = S(sum, "status"); if (st == "assessed") return "";
            StringBuilder sb = new StringBuilder(); sb.Append("<div class=\"alert\"><b>").Append(st == "not-assessable" ? "NOT ASSESSABLE" : "INCOMPLETE COVERAGE").Append("</b> — ").Append(E(S(sum, "headline")));
            List<string> probs = JsonWrite.Strings(Json.Get(r, "method", "coverage", "problems")); int n = 0;
            if (probs.Count > 0) { sb.Append("<ul>"); foreach (string p in probs) { if (++n > 12) { sb.Append("<li>… and ").Append(probs.Count - 12).Append(" more (method.coverage.problems in the JSON)</li>"); break; } sb.Append("<li>").Append(E(p)).Append("</li>"); } sb.Append("</ul>"); }
            return sb.Append("</div>\n").ToString();
        }
        public static readonly string[] Columns = { "rank", "id", "severity", "status", "cve", "title", "source", "product", "installed", "fix", "cvss", "epss", "kev", "ransomware", "kevDue", "exploited", "release", "validated", "asOf", "evidence", "url" };
        /// <summary>host_runId_kind, reduced to safe characters: a deterministic name, no timestamp.</summary>
        public static string FileStem(Dictionary<string, object> r)
        {
            string raw = S(Json.Get(r, "subject"), "host") + "_" + S(Json.Get(r, "subject"), "runId") + "_" + S(r, "report"); StringBuilder sb = new StringBuilder();
            foreach (char c in raw) sb.Append(char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.' ? c : '-'); string s = sb.ToString().Trim('-', '.'); return s.Length == 0 ? "report" : (s.Length > 80 ? s.Substring(0, 80) : s);
        }
        public static List<string> WriteAll(Dictionary<string, object> r, Brand brand, string dir, IEnumerable<string> formats)
        {
            Directory.CreateDirectory(dir); string stem = Path.Combine(dir, FileStem(r)); List<string> written = new List<string>();
            foreach (string f in formats)
            {
                string fmt = (f ?? "").Trim().ToLowerInvariant(); if (fmt.Length == 0) continue; string p = stem + "." + fmt;
                if (fmt == "json") File.WriteAllText(p, JsonWrite.Text(r, true), new UTF8Encoding(false));
                else if (fmt == "csv") File.WriteAllText(p, Csv(r), new UTF8Encoding(true));
                else if (fmt == "md") File.WriteAllText(p, Markdown(r), new UTF8Encoding(false));
                else if (fmt == "html") File.WriteAllText(p, HtmlPage(r, brand), new UTF8Encoding(false));
                else if (fmt == "pdf") File.WriteAllBytes(p, Pdf(r, brand));
                else throw new BundleException("unknown report format '" + fmt + "' (json, csv, md, html, pdf)");
                written.Add(p);
            }
            return written;
        }

        // ── CSV: every cell through Fmt.CsvQ, which quotes and neutralises formula cells (= + - @ TAB CR) ──
        public static string Csv(Dictionary<string, object> r)
        {
            // PT-45: the first line carries the verdict and the headline, so a CSV on its own can never pass for clean; the column header follows it
            object sum = Json.Get(r, "summary"); StringBuilder sb = new StringBuilder(); sb.Append(Fmt.CsvQ("# " + S(sum, "status").ToUpperInvariant().Replace('-', ' ') + " · " + S(Json.Get(sum, "coverage"), "text") + " · " + S(sum, "headline"))).Append("\r\n");
            List<string> h = new List<string>(); foreach (string c in Columns) h.Add(Fmt.CsvQ(c)); sb.Append(string.Join(",", h.ToArray())).Append("\r\n");
            foreach (string sec in new string[] { "rows", "unconfirmed" }) foreach (object row in Json.Arr(Json.Get(r, sec)))
            {
                List<string> cells = new List<string>();
                foreach (string c in Columns) { object v = Json.Get(row, c); string text = v == null ? "" : v is bool ? ((bool)v ? "yes" : "no") : v is double ? ((double)v).ToString(c == "epss" ? "0.###" : "0.##", CultureInfo.InvariantCulture) : Json.S(v) ?? ""; cells.Add(Fmt.CsvQ(text)); }
                sb.Append(string.Join(",", cells.ToArray())).Append("\r\n");
            }
            return sb.ToString();
        }

        // ── Markdown ──
        public static string Markdown(Dictionary<string, object> r)
        {
            object sub = Json.Get(r, "subject"), sum = Json.Get(r, "summary"), os = Json.Get(sub, "os"); StringBuilder sb = new StringBuilder();
            sb.Append("# ").Append(Md(S(r, "title"))).Append(" — ").Append(Mc(S(sub, "host"))).Append("\n\n").Append(MdBanner(r));
            sb.Append("- **Host:** ").Append(Mc(S(sub, "host"))).Append(S(sub, "domain").Length > 0 ? " (" + Mc(S(sub, "domain")) + ")" : "").Append("\n- **OS:** ").Append(Mc(S(os, "productName"))).Append(" ").Append(Mc(S(os, "displayVersion"))).Append(" · build ").Append(Mc(S(os, "fullBuild"))).Append(" · ").Append(Mc(S(os, "arch"))).Append("\n- **Collected:** ").Append(Mc(S(sub, "collectedUtc"))).Append(" · **Enriched:** ").Append(Mc(S(sub, "enrichedUtc"))).Append(" · **Run:** ").Append(Mc(S(sub, "runId"))).Append(S(sub, "engagementId").Length > 0 ? " · **Engagement:** " + Mc(S(sub, "engagementId")) : "").Append("\n");
            sb.Append("- **Result:** ").Append(Md(S(sum, "headline"))).Append("\n- **Coverage:** ").Append(Md(S(Json.Get(sum, "coverage"), "text"))).Append(" · status `").Append(S(sum, "status")).Append("`\n\n");
            sb.Append("## Open findings, risk-ranked (open → known exploited → severity → CVSS → EPSS)\n\n| # | Severity | CVE | Title | Product | Installed | Fix | CVSS | EPSS | KEV | Status | Validated | As of |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
            int shown = 0; foreach (object row in Json.Arr(Json.Get(r, "rows"))) { if (!B(row, "open")) continue; shown++; sb.Append("| ").Append(Num(row, "rank", "0")).Append(" | ").Append(Mc(S(row, "severity"))).Append(" | ").Append(Mc(S(row, "cve"))).Append(" | ").Append(Mc(S(row, "title"))).Append(" | ").Append(Mc(S(row, "product"))).Append(" | ").Append(Mc(S(row, "installed"))).Append(" | ").Append(Mc(S(row, "fix"))).Append(" | ").Append(Num(row, "cvss", "0.#")).Append(" | ").Append(Num(row, "epss", "0.###")).Append(" | ").Append(B(row, "kev") ? (B(row, "ransomware") ? "KEV · ransomware" : "KEV") : (B(row, "exploited") ? "exploited" : "")).Append(" | ").Append(Mc(S(row, "status"))).Append(" | ").Append(Mc(S(row, "validated"))).Append(" | ").Append(Mc(S(row, "asOf"))).Append(" |\n"); }
            if (shown == 0) sb.Append("| – | – | – | no open findings | | | | | | | | | |\n");
            sb.Append("\n## Remediation by update\n\n| Update | Open CVEs | Worst | Known exploited | Products |\n|---|---|---|---|---|\n");
            foreach (object u in Json.Arr(Json.Get(r, "remediation", "byUpdate"))) sb.Append("| ").Append(Mc(S(u, "kb"))).Append(" | ").Append(Num(u, "openCount", "0")).Append(" | ").Append(Mc(S(u, "worstSeverity"))).Append(" | ").Append(B(u, "knownExploited") ? "yes" : "").Append(" | ").Append(Mc(string.Join(", ", JsonWrite.Strings(Json.Get(u, "products")).ToArray()))).Append(" |\n");
            sb.Append("\n## Remediation by product\n\n| Product | Installed | Fix | Open CVEs | Worst | Known exploited |\n|---|---|---|---|---|---|\n");
            foreach (object p in Json.Arr(Json.Get(r, "remediation", "byProduct"))) sb.Append("| ").Append(Mc(S(p, "product"))).Append(" | ").Append(Mc(S(p, "installed"))).Append(" | ").Append(Mc(S(p, "fix"))).Append(" | ").Append(Num(p, "openCount", "0")).Append(" | ").Append(Mc(S(p, "worstSeverity"))).Append(" | ").Append(B(p, "knownExploited") ? "yes" : "").Append(" |\n");
            sb.Append("\n## Unconfirmed third-party matches\n\n"); List<object> un = Json.Arr(Json.Get(r, "unconfirmed")); if (un.Count == 0) sb.Append("None.\n"); else { sb.Append("| CVE | Product | Installed | Evidence |\n|---|---|---|---|\n"); foreach (object row in un) sb.Append("| ").Append(Mc(S(row, "cve"))).Append(" | ").Append(Mc(S(row, "product"))).Append(" | ").Append(Mc(S(row, "installed"))).Append(" | ").Append(Mc(S(row, "evidence"))).Append(" |\n"); }
            sb.Append("\n## Patched / closed\n\n").Append(Num(sum, "patched", "0")).Append(" finding(s) are fixed on this build (listed in the JSON and CSV).\n\n## Feeds as of\n\n").Append("````\n").Append(JsonWrite.Text(Json.Get(r, "asOf"), true)).Append("````\n\n## Method and limitations\n\n").Append(Md(S(Json.Get(r, "method"), "text"))).Append("\n\n");
            foreach (string l in JsonWrite.Strings(Json.Get(r, "method", "limitations"))) sb.Append("- ").Append(Md(l)).Append("\n");
            sb.Append("\n_").Append(Md(S(Json.Get(r, "brand"), "name"))).Append(" · ").Append(Md(S(Json.Get(r, "brand"), "footer"))).Append(" · ").Append(Ptreport.Schema).Append("_\n");
            return sb.ToString();
        }

        // ── HTML: one self-contained file, inline CSS, inline SVG logo, print stylesheet, no external requests, everything escaped ──
        public static string HtmlPage(Dictionary<string, object> r, Brand brand)
        {
            object sub = Json.Get(r, "subject"), sum = Json.Get(r, "summary"), os = Json.Get(sub, "os"); StringBuilder sb = new StringBuilder();
            sb.Append("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<meta name=\"referrer\" content=\"no-referrer\">\n<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">\n<title>").Append(E(S(r, "title") + " - " + S(sub, "host"))).Append("</title>\n<style>\n");
            sb.Append(":root{--accent:").Append(brand.Accent).Append(";--ink:").Append(brand.Ink).Append(";--paper:").Append(brand.Paper).Append(";--panel:").Append(brand.Panel).Append(";--muted:").Append(brand.Muted).Append(";--rule:").Append(brand.Rule).Append("}\n");
            sb.Append("*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.5 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}main{max-width:1180px;margin:0 auto;padding:28px 32px 48px}header{display:flex;align-items:center;gap:24px;border-bottom:3px solid var(--accent);padding-bottom:18px;margin-bottom:22px}header .logo svg{height:44px;width:auto;display:block}.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);font-weight:700}h1{margin:2px 0 6px;font-size:26px;letter-spacing:-.01em}h2{font-size:17px;margin:30px 0 10px;padding-top:14px;border-top:1px solid var(--rule)}.meta{color:var(--muted);font-size:13px}.meta b{color:var(--ink);font-weight:600}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:18px 0}.card{background:var(--panel);border-radius:8px;padding:12px 14px}.card .n{font-size:26px;font-weight:700;line-height:1.1}.card .l{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}.card.bad .n{color:").Append(brand.Severity["Critical"]).Append("}.headline{font-size:15px;background:var(--panel);border-left:4px solid var(--accent);padding:12px 16px;border-radius:0 8px 8px 0}table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{text-align:left;vertical-align:top;padding:7px 8px;border-bottom:1px solid var(--rule)}th{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);background:var(--panel);position:sticky;top:0}td.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}.chip{display:inline-block;padding:1px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:700;letter-spacing:.04em;white-space:nowrap}.kev{display:inline-block;padding:1px 7px;border-radius:4px;background:").Append(brand.Severity["Critical"]).Append(";color:#fff;font-size:11px;font-weight:700}.mono{font-family:Consolas,'Courier New',monospace;font-size:12px}.ev{color:var(--muted);font-size:11.5px}details summary{cursor:pointer;color:var(--accent);font-weight:600}pre{background:var(--panel);padding:12px;border-radius:8px;overflow:auto;font-size:12px}footer{margin-top:40px;padding-top:14px;border-top:1px solid var(--rule);color:var(--muted);font-size:12px}.lim li{margin:4px 0}.alert{font-size:15px;border-left:4px solid ").Append(brand.Severity["Critical"]).Append(";background:var(--panel);padding:12px 16px;border-radius:0 8px 8px 0;margin:14px 0}.alert ul{margin:8px 0 0;padding-left:20px}.alert li{font-size:12.5px;color:var(--muted)}.coverage{color:var(--muted);font-size:13px;margin:6px 0 0}.coverage.bad{color:").Append(brand.Severity["Critical"]).Append(";font-weight:600}\n");
            foreach (KeyValuePair<string, string> sv in brand.Severity) sb.Append(".sev-").Append(sv.Key).Append("{background:").Append(sv.Value).Append("}\n");
            sb.Append("@media print{body{font-size:11px}main{max-width:none;padding:0}header{break-after:avoid}h2{break-after:avoid}tr{break-inside:avoid}th{position:static}details{display:block}details>*{display:block}.card{border:1px solid var(--rule)}a{text-decoration:none;color:inherit}@page{margin:16mm 14mm}}\n</style>\n</head>\n<body>\n<main>\n");
            sb.Append("<header><div class=\"logo\">").Append(brand.SafeLogo(brand.Name)).Append("</div><div><div class=\"eyebrow\">").Append(E(brand.Line)).Append("</div><h1>").Append(E(S(r, "title"))).Append("</h1><div class=\"meta\"><b>").Append(E(S(sub, "host"))).Append("</b>").Append(S(sub, "domain").Length > 0 ? " · " + E(S(sub, "domain")) : "").Append(" · ").Append(E(S(os, "productName") + " " + S(os, "displayVersion"))).Append(" · build <span class=\"mono\">").Append(E(S(os, "fullBuild"))).Append("</span> · ").Append(E(S(os, "arch"))).Append("<br>collected <b>").Append(E(S(sub, "collectedUtc"))).Append("</b> · enriched <b>").Append(E(S(sub, "enrichedUtc"))).Append("</b> · run <span class=\"mono\">").Append(E(S(sub, "runId"))).Append("</span>").Append(S(sub, "engagementId").Length > 0 ? " · engagement <span class=\"mono\">" + E(S(sub, "engagementId")) + "</span>" : "").Append(" · privilege tier ").Append(E(S(sub, "privilegeTier"))).Append("</div></div></header>\n");
            object cov = Json.Get(sum, "coverage"); bool assessed = S(sum, "status") == "assessed"; sb.Append(HtmlBanner(r));
            sb.Append("<section class=\"cards\">").Append(Card("open", Num(sum, "open", "0"), Json.N(Json.Get(sum, "open")) > 0)).Append(Card("critical", Num(sum, "critical", "0"), Json.N(Json.Get(sum, "critical")) > 0)).Append(Card("high", Num(sum, "high", "0"), Json.N(Json.Get(sum, "high")) > 0)).Append(Card("medium", Num(sum, "medium", "0"), false)).Append(Card("low", Num(sum, "low", "0"), false)).Append(Card("known exploited", Num(sum, "knownExploited", "0"), Json.N(Json.Get(sum, "knownExploited")) > 0)).Append(Card("patched", Num(sum, "patched", "0"), false)).Append(Card("unconfirmed", Num(sum, "unconfirmed", "0"), false)).Append(Card("MSRC releases checked", Num(cov, "releasesChecked", "0") + " of " + Num(cov, "releasesExpected", "0"), !assessed)).Append("</section>\n");
            sb.Append("<h2>Executive summary</h2><p class=\"headline\">").Append(E(S(sum, "headline"))).Append("</p><p class=\"coverage").Append(assessed ? "" : " bad").Append("\">Coverage: ").Append(E(S(cov, "text"))).Append(" · status ").Append(E(S(sum, "status"))).Append("</p>\n");
            sb.Append("<h2>Open findings, risk-ranked (open → known exploited → severity → CVSS → EPSS)</h2>\n<table><thead><tr><th>#</th><th>Severity</th><th>CVE</th><th>Title</th><th>Product</th><th>Installed</th><th>Fix</th><th>CVSS</th><th>EPSS</th><th>Exploited</th><th>Status</th><th>Validated</th><th>As of</th></tr></thead><tbody>\n");
            int shown = 0; foreach (object row in Json.Arr(Json.Get(r, "rows"))) { if (!B(row, "open")) continue; shown++; sb.Append(RowHtml(row, true)); }
            if (shown == 0) sb.Append("<tr><td colspan=\"13\">No open findings.</td></tr>\n"); sb.Append("</tbody></table>\n");
            sb.Append("<h2>Remediation by update</h2>\n<table><thead><tr><th>Update</th><th>Open CVEs</th><th>Worst</th><th>Known exploited</th><th>Products</th></tr></thead><tbody>\n");
            foreach (object u in Json.Arr(Json.Get(r, "remediation", "byUpdate"))) sb.Append("<tr><td class=\"mono\">").Append(E(S(u, "kb"))).Append("</td><td class=\"num\">").Append(Num(u, "openCount", "0")).Append("</td><td>").Append(Chip(S(u, "worstSeverity"))).Append("</td><td>").Append(B(u, "knownExploited") ? "<span class=\"kev\">KEV</span>" : "").Append("</td><td>").Append(E(string.Join(", ", JsonWrite.Strings(Json.Get(u, "products")).ToArray()))).Append("</td></tr>\n");
            if (Json.Arr(Json.Get(r, "remediation", "byUpdate")).Count == 0) sb.Append("<tr><td colspan=\"5\">No missing Microsoft update.</td></tr>\n"); sb.Append("</tbody></table>\n");
            sb.Append("<h2>Remediation by product</h2>\n<table><thead><tr><th>Product</th><th>Installed</th><th>Fix</th><th>Open CVEs</th><th>Worst</th><th>Known exploited</th></tr></thead><tbody>\n");
            foreach (object p in Json.Arr(Json.Get(r, "remediation", "byProduct"))) sb.Append("<tr><td>").Append(E(S(p, "product"))).Append("</td><td class=\"mono\">").Append(E(S(p, "installed"))).Append("</td><td>").Append(E(S(p, "fix"))).Append("</td><td class=\"num\">").Append(Num(p, "openCount", "0")).Append("</td><td>").Append(Chip(S(p, "worstSeverity"))).Append("</td><td>").Append(B(p, "knownExploited") ? "<span class=\"kev\">KEV</span>" : "").Append("</td></tr>\n");
            if (Json.Arr(Json.Get(r, "remediation", "byProduct")).Count == 0) sb.Append("<tr><td colspan=\"6\">No third-party product with an open CVE at its installed version.</td></tr>\n"); sb.Append("</tbody></table>\n");
            sb.Append("<h2>Unconfirmed third-party matches</h2>\n"); List<object> un = Json.Arr(Json.Get(r, "unconfirmed")); if (un.Count == 0) sb.Append("<p>None.</p>\n"); else { sb.Append("<p class=\"ev\">NVD records for an installed product without version bounds: not counted as open, to be checked by hand.</p><table><thead><tr><th>CVE</th><th>Title</th><th>Product</th><th>Installed</th><th>Evidence</th><th>Advisory</th></tr></thead><tbody>\n"); foreach (object row in un) sb.Append("<tr><td class=\"mono\">").Append(E(S(row, "cve"))).Append("</td><td>").Append(E(S(row, "title"))).Append("</td><td>").Append(E(S(row, "product"))).Append("</td><td class=\"mono\">").Append(E(S(row, "installed"))).Append("</td><td class=\"ev\">").Append(E(S(row, "evidence"))).Append("</td><td class=\"mono\">").Append(E(S(row, "url"))).Append("</td></tr>\n"); sb.Append("</tbody></table>\n"); }
            sb.Append("<h2>Patched / closed</h2>\n<details><summary>").Append(Num(sum, "patched", "0")).Append(" finding(s) are fixed on this build - show them</summary><table><thead><tr><th>#</th><th>Severity</th><th>CVE</th><th>Title</th><th>Product</th><th>Installed</th><th>Fix</th><th>CVSS</th><th>EPSS</th><th>Exploited</th><th>Status</th><th>Validated</th><th>As of</th></tr></thead><tbody>\n");
            foreach (object row in Json.Arr(Json.Get(r, "rows"))) { if (B(row, "open")) continue; sb.Append(RowHtml(row, false)); } sb.Append("</tbody></table></details>\n");
            sb.Append("<h2>Feeds as of</h2>\n<pre>").Append(E(JsonWrite.Text(Json.Get(r, "asOf"), true))).Append("</pre>\n");
            object method = Json.Get(r, "method"); sb.Append("<h2>Method and limitations</h2>\n<p>").Append(E(S(method, "text"))).Append("</p>\n<ul class=\"lim\">"); foreach (string l in JsonWrite.Strings(Json.Get(method, "limitations"))) sb.Append("<li>").Append(E(l)).Append("</li>"); sb.Append("</ul>\n");
            List<string> probs = JsonWrite.Strings(Json.Get(method, "coverage", "problems")); if (probs.Count > 0) { sb.Append("<p class=\"ev\"><b>Problems during enrichment:</b></p><ul class=\"lim ev\">"); foreach (string p in probs) sb.Append("<li>").Append(E(p)).Append("</li>"); sb.Append("</ul>\n"); }
            sb.Append("<footer>").Append(E(brand.Name)).Append(" · ").Append(E(brand.Footer)).Append(" · ").Append(Ptreport.Schema).Append(" · generated by PowerTower from bundle ").Append(E(S(sub, "runId"))).Append(" enriched ").Append(E(S(sub, "enrichedUtc"))).Append("</footer>\n</main>\n</body>\n</html>\n");
            return sb.ToString();
        }
        static string Card(string label, string n, bool bad) { return "<div class=\"card" + (bad ? " bad" : "") + "\"><div class=\"n\">" + Html.Esc(n) + "</div><div class=\"l\">" + Html.Esc(label) + "</div></div>"; }
        static string Chip(string sev) { string s = string.IsNullOrEmpty(sev) ? "Unrated" : sev; string cls = Regex.IsMatch(s, "^[A-Za-z]+$") ? s : "Unrated"; return "<span class=\"chip sev-" + cls + "\">" + Html.Esc(s) + "</span>"; }
        static string RowHtml(object row, bool open)
        {
           
            return "<tr><td class=\"num\">" + Num(row, "rank", "0") + "</td><td>" + Chip(S(row, "severity")) + "</td><td class=\"mono\">" + E(S(row, "cve")) + "</td><td>" + E(S(row, "title")) + "<div class=\"ev\">" + E(S(row, "evidence")) + (S(row, "url").Length > 0 ? " · " + E(S(row, "url")) : "") + "</div></td><td>" + E(S(row, "product")) + "</td><td class=\"mono\">" + E(S(row, "installed")) + "</td><td>" + E(S(row, "fix")) + "</td><td class=\"num\">" + Num(row, "cvss", "0.#") + "</td><td class=\"num\">" + Num(row, "epss", "0.###") + "</td><td>" + (B(row, "kev") ? "<span class=\"kev\">KEV" + (B(row, "ransomware") ? " · ransomware" : "") + "</span>" + (S(row, "kevDue").Length > 0 ? " <span class=\"ev\">due " + E(S(row, "kevDue")) + "</span>" : "") : (B(row, "exploited") ? "exploited" : "")) + "</td><td>" + E(S(row, "status")) + "</td><td>" + E(S(row, "validated")) + "</td><td class=\"mono\">" + E(S(row, "asOf")) + "</td></tr>\n";
        }

        // ── PDF ──
        public static byte[] Pdf(Dictionary<string, object> r, Brand brand)
        {
            object sub = Json.Get(r, "subject"), sum = Json.Get(r, "summary"), os = Json.Get(sub, "os");
            PdfDoc d = new PdfDoc(brand.Name + " · " + brand.Line, S(r, "title") + " · " + S(sub, "host"), brand);
            d.Line(20, true, brand.Ink, S(r, "title"), 0); d.Line(10.5f, false, brand.Muted, S(sub, "host") + (S(sub, "domain").Length > 0 ? " (" + S(sub, "domain") + ")" : "") + " · " + S(os, "productName") + " " + S(os, "displayVersion") + " · build " + S(os, "fullBuild") + " · " + S(os, "arch"), 0);
            d.Line(9.5f, false, brand.Muted, "collected " + S(sub, "collectedUtc") + " · enriched " + S(sub, "enrichedUtc") + " · run " + S(sub, "runId") + (S(sub, "engagementId").Length > 0 ? " · engagement " + S(sub, "engagementId") : "") + " · privilege tier " + S(sub, "privilegeTier"), 0); d.Gap(8);
            string[] labels = { "open", "critical", "high", "medium", "low", "known exploited", "patched", "unconfirmed" }; string[] keys = { "open", "critical", "high", "medium", "low", "knownExploited", "patched", "unconfirmed" }; string[] fills = { brand.Severity["Critical"], brand.Severity["Critical"], brand.Severity["High"], brand.Severity["Medium"], brand.Severity["Low"], brand.Severity["Critical"], brand.Severity["Low"], brand.Severity["Unrated"] };
            // PT-45: the verdict leads the PDF too, with the problems, before any count that could be read as clean
            string st = S(sum, "status"); object cov = Json.Get(sum, "coverage");
            if (st != "assessed")
            {
                d.Para(11.5f, brand.Severity["Critical"], (st == "not-assessable" ? "NOT ASSESSABLE" : "INCOMPLETE COVERAGE") + " - " + S(cov, "text"), 0); d.Para(9.5f, brand.Ink, S(sum, "headline"), 0);
                List<string> pr = JsonWrite.Strings(Json.Get(r, "method", "coverage", "problems")); int pn = 0; foreach (string p in pr) { if (++pn > 12) { d.Para(9, brand.Muted, "- … and " + (pr.Count - 12) + " more (method.coverage.problems in the JSON)", 10); break; } d.Para(9, brand.Muted, "- " + p, 10); }
                d.Gap(8);
            }
            d.Chips(labels, keys, sum, fills, brand.Muted); d.Gap(10);
            d.Heading("Executive summary", brand.Accent); d.Para(10.5f, brand.Ink, S(sum, "headline"), 0); d.Para(9.5f, st == "assessed" ? brand.Muted : brand.Severity["Critical"], "Coverage: " + S(cov, "text") + " · status " + st, 0); d.Gap(6);
            d.Heading("Open findings, risk-ranked (open → known exploited → severity → CVSS → EPSS)", brand.Accent);
            List<string[]> rows = new List<string[]>(); List<string> sevs = new List<string>();
            foreach (object row in Json.Arr(Json.Get(r, "rows"))) { if (!B(row, "open")) continue; rows.Add(new string[] { Num(row, "rank", "0"), S(row, "severity"), S(row, "cve"), S(row, "title"), S(row, "product") + (S(row, "installed").Length > 0 ? " " + S(row, "installed") : ""), S(row, "fix"), Num(row, "cvss", "0.#"), Num(row, "epss", "0.###"), B(row, "kev") ? "KEV" + (B(row, "ransomware") ? "/ransomware" : "") : (B(row, "exploited") ? "exploited" : ""), S(row, "status") }); sevs.Add(S(row, "severity")); }
            if (rows.Count == 0) d.Para(10, brand.Muted, "No open findings.", 0);
            else d.Table(new string[] { "#", "Severity", "CVE", "Title", "Product", "Fix", "CVSS", "EPSS", "Exploited", "Status" }, new float[] { 20, 50, 78, 118, 92, 86, 30, 34, 46, 50 }, rows, 7.6f, delegate (int ri, int ci) { return ci == 1 ? SevFill(brand, sevs[ri]) : null; });
            d.Gap(8); d.Heading("Remediation by update", brand.Accent); List<string[]> ku = new List<string[]>(); foreach (object u in Json.Arr(Json.Get(r, "remediation", "byUpdate"))) ku.Add(new string[] { S(u, "kb"), Num(u, "openCount", "0"), S(u, "worstSeverity"), B(u, "knownExploited") ? "yes" : "", string.Join(", ", JsonWrite.Strings(Json.Get(u, "products")).ToArray()) });
            if (ku.Count == 0) d.Para(10, brand.Muted, "No missing Microsoft update.", 0); else d.Table(new string[] { "Update", "Open CVEs", "Worst", "Known exploited", "Products" }, new float[] { 90, 50, 60, 70, 334 }, ku, 8, null);
            d.Gap(8); d.Heading("Remediation by product", brand.Accent); List<string[]> kp = new List<string[]>(); foreach (object p in Json.Arr(Json.Get(r, "remediation", "byProduct"))) kp.Add(new string[] { S(p, "product"), S(p, "installed"), S(p, "fix"), Num(p, "openCount", "0"), S(p, "worstSeverity") });
            if (kp.Count == 0) d.Para(10, brand.Muted, "No third-party product with an open CVE at its installed version.", 0); else d.Table(new string[] { "Product", "Installed", "Fix", "Open CVEs", "Worst" }, new float[] { 170, 70, 190, 54, 60 }, kp, 8, null);
            d.Gap(8); d.Heading("Unconfirmed third-party matches", brand.Accent); List<string[]> ku2 = new List<string[]>(); foreach (object row in Json.Arr(Json.Get(r, "unconfirmed"))) ku2.Add(new string[] { S(row, "cve"), S(row, "product"), S(row, "installed"), S(row, "evidence") });
            if (ku2.Count == 0) d.Para(10, brand.Muted, "None.", 0); else d.Table(new string[] { "CVE", "Product", "Installed", "Evidence" }, new float[] { 80, 150, 60, 314 }, ku2, 8, null);
            d.Gap(8); d.Heading("Patched / closed", brand.Accent); d.Para(10, brand.Ink, Num(sum, "patched", "0") + " finding(s) are fixed on this build; they are listed in the JSON and CSV deliverables.", 0);
            d.Gap(8); d.Heading("Feeds as of", brand.Accent); object asOf = Json.Get(r, "asOf"); d.Para(9, brand.Ink, "MSRC releases checked: " + string.Join(", ", JsonWrite.Strings(Json.Get(sum, "releases")).ToArray()) + " (window " + Num(sum, "msrcWindow", "0") + ")", 0);
            foreach (string k in new string[] { "kev", "epss", "nvd" }) { object o = Json.Get(asOf, k); if (o != null) d.Para(9, brand.Ink, k.ToUpperInvariant() + ": " + JsonWrite.Text(o, false), 0); } d.Para(9, brand.Ink, "enriched " + S(asOf, "enrichedUtc") + (JsonWrite.Bool(Json.Get(asOf, "offline")) ? " · offline feed pack" : ""), 0);
            d.Gap(8); d.Heading("Method and limitations", brand.Accent); object method = Json.Get(r, "method"); d.Para(9.5f, brand.Ink, S(method, "text"), 0); foreach (string l in JsonWrite.Strings(Json.Get(method, "limitations"))) d.Para(9.5f, brand.Ink, "- " + l, 10);
            List<string> probs = JsonWrite.Strings(Json.Get(method, "coverage", "problems")); if (probs.Count > 0) { d.Para(9.5f, brand.Ink, "Problems during enrichment:", 0); foreach (string p in probs) d.Para(9, brand.Muted, "- " + p, 10); }
            return d.Bytes(brand.Footer + " · " + Ptreport.Schema);
        }
        static string SevFill(Brand b, string sev) { string c; return b.Severity.TryGetValue(sev ?? "", out c) ? c : b.Severity["Unrated"]; }
    }

    // ───────────────────────────── a Helvetica PDF writer with chips, tables and page numbers ─────────────────────────────
    /// <summary>PDF 1.4, base-14 Helvetica / Helvetica-Bold (no embedding), filled rectangles for chips and table heads, simple wrapped tables, a header rule and "page n of N" on every page. Text is reduced to WinAnsi.</summary>
    public class PdfDoc
    {
        const float PW = 612, PH = 792, ML = 44, MR = 44, MT = 62, MB = 52;
        readonly List<StringBuilder> pages = new List<StringBuilder>(); StringBuilder cur; float y; readonly string headLeft, headRight; readonly Brand brand;
        public PdfDoc(string headerLeft, string headerRight, Brand b) { headLeft = headerLeft; headRight = headerRight; brand = b; NewPage(); }
        void NewPage() { cur = new StringBuilder(); pages.Add(cur); y = PH - MT; }
        static string F(float v) { return v.ToString("0.##", CultureInfo.InvariantCulture); }
        static string Rgb(string hex) { if (hex == null || hex.Length != 7) hex = "#000000"; float r = Convert.ToInt32(hex.Substring(1, 2), 16) / 255f, g = Convert.ToInt32(hex.Substring(3, 2), 16) / 255f, bl = Convert.ToInt32(hex.Substring(5, 2), 16) / 255f; return F(r) + " " + F(g) + " " + F(bl); }
        public static float Width(string s, float size) { return (s ?? "").Length * size * 0.5f; }
        /// <summary>WinAnsi only: ASCII as is (with ( ) \ escaped), Latin-1 as octal escapes, the glyphs the app uses mapped, the rest '?'.</summary>
        static string Esc(string s)
        {
            StringBuilder sb = new StringBuilder(); foreach (char c in s ?? "")
            {
                if (c == '(' || c == ')' || c == '\\') { sb.Append('\\').Append(c); continue; }
                if (c >= 32 && c < 127) { sb.Append(c); continue; }
                if (c >= 0xA0 && c <= 0xFF) { sb.Append('\\').Append(Convert.ToString((int)c, 8).PadLeft(3, '0')); continue; }
                switch (c) { case '·': sb.Append("\\267"); break; case '→': sb.Append("->"); break; case '—': case '–': sb.Append('-'); break; case '…': sb.Append("..."); break; case '✓': case '✔': sb.Append("OK"); break; case '✗': case '✖': sb.Append('x'); break; case '⚠': sb.Append('!'); break; case '≥': sb.Append(">="); break; case '≤': sb.Append("<="); break; case '\u2018': case '\u2019': sb.Append('\''); break; case '\u201C': case '\u201D': sb.Append('"'); break; case '\t': sb.Append(' '); break; default: sb.Append('?'); break; }
            }
            return sb.ToString();
        }
        void Text(float x, float baseline, float size, bool bold, string color, string text) { cur.Append("BT /").Append(bold ? "F2" : "F1").Append(' ').Append(F(size)).Append(" Tf ").Append(Rgb(color)).Append(" rg ").Append(F(x)).Append(' ').Append(F(baseline)).Append(" Td (").Append(Esc(text)).Append(") Tj ET\n"); }
        void Rect(float x, float top, float w, float h, string fill) { cur.Append(Rgb(fill)).Append(" rg ").Append(F(x)).Append(' ').Append(F(top - h)).Append(' ').Append(F(w)).Append(' ').Append(F(h)).Append(" re f\n"); }
        public void Ensure(float h) { if (y - h < MB) NewPage(); }
        public void Gap(float h) { y -= h; }
        public void Line(float size, bool bold, string color, string text, float indent) { Ensure(size * 1.5f); y -= size * 1.15f; Text(ML + indent, y, size, bold, color, text); y -= size * 0.3f; }
        public void Heading(string text, string color) { Ensure(26); y -= 6; Line(12.5f, true, color, text, 0); cur.Append(Rgb(brand.Rule)).Append(" RG 0.6 w ").Append(F(ML)).Append(' ').Append(F(y + 2)).Append(" m ").Append(F(PW - MR)).Append(' ').Append(F(y + 2)).Append(" l S\n"); y -= 4; }
        public void Para(float size, string color, string text, float indent) { foreach (string l in Wrap(text, PW - ML - MR - indent, size)) Line(size, false, color, l, indent); }
        static List<string> Wrap(string s, float width, float size)
        {
            List<string> o = new List<string>(); int max = Math.Max(8, (int)(width / (size * 0.5f))); StringBuilder cur = new StringBuilder();
            foreach (string w0 in (s ?? "").Replace("\r", " ").Replace("\n", " ").Split(' '))
            {
                string w = w0; while (w.Length > max) { if (cur.Length > 0) { o.Add(cur.ToString()); cur.Length = 0; } o.Add(w.Substring(0, max)); w = w.Substring(max); }
                if (cur.Length == 0) cur.Append(w); else if (cur.Length + 1 + w.Length <= max) cur.Append(' ').Append(w); else { o.Add(cur.ToString()); cur.Length = 0; cur.Append(w); }
            }
            if (cur.Length > 0) o.Add(cur.ToString()); if (o.Count == 0) o.Add(""); return o;
        }
        /// <summary>A row of filled chips: the number big, the label small, coloured when the number is above zero.</summary>
        public void Chips(string[] labels, string[] keys, object values, string[] fills, string zeroFill)
        {
            float w = (PW - ML - MR - 6 * (labels.Length - 1)) / labels.Length, h = 40; Ensure(h + 6); float top = y;
            for (int i = 0; i < labels.Length; i++) { double? n = Json.N(Json.Get(values, keys[i])); string val = n.HasValue ? n.Value.ToString("0", CultureInfo.InvariantCulture) : "-"; float x = ML + i * (w + 6); Rect(x, top, w, h, n.HasValue && n.Value > 0 ? fills[i] : zeroFill); Text(x + 8, top - 22, 16, true, "#FFFFFF", val); Text(x + 8, top - 33, 6.5f, false, "#FFFFFF", labels[i].ToUpperInvariant()); }
            y = top - h;
        }
        /// <summary>Wrapped cells, a filled header that repeats after a page break, optional per-cell fill (a severity chip).</summary>
        public void Table(string[] headers, float[] widths, List<string[]> rows, float size, Func<int, int, string> cellFill)
        {
            float total = 0; foreach (float w in widths) total += w; float scale = (PW - ML - MR) / total; float lineH = size * 1.25f, pad = 3;
            Action header = delegate ()
            {
                Ensure(lineH + pad * 2 + 4); Rect(ML, y, PW - ML - MR, lineH + pad * 2, brand.Panel); float x = ML;
                for (int c = 0; c < headers.Length; c++) { Text(x + pad, y - pad - size, size, true, brand.Muted, headers[c].ToUpperInvariant()); x += widths[c] * scale; }
                y -= lineH + pad * 2;
            };
            header();
            for (int ri = 0; ri < rows.Count; ri++)
            {
                string[] row = rows[ri]; List<List<string>> cells = new List<List<string>>(); int lines = 1;
                for (int c = 0; c < headers.Length; c++) { List<string> ls = Wrap(c < row.Length ? row[c] : "", widths[c] * scale - pad * 2, size); cells.Add(ls); if (ls.Count > lines) lines = ls.Count; }
                float rh = lines * lineH + pad * 2; if (y - rh < MB) { NewPage(); header(); }
                float x = ML;
                for (int c = 0; c < headers.Length; c++)
                {
                    string fill = cellFill != null ? cellFill(ri, c) : null;
                    if (fill != null) { Rect(x + 1, y - pad + 1, widths[c] * scale - 2, lineH + 1, fill); Text(x + pad, y - pad - size, size, true, "#FFFFFF", cells[c].Count > 0 ? cells[c][0] : ""); }
                    else for (int li = 0; li < cells[c].Count; li++) Text(x + pad, y - pad - size - li * lineH, size, false, brand.Ink, cells[c][li]);
                    x += widths[c] * scale;
                }
                y -= rh; cur.Append(Rgb(brand.Rule)).Append(" RG 0.3 w ").Append(F(ML)).Append(' ').Append(F(y)).Append(" m ").Append(F(PW - MR)).Append(' ').Append(F(y)).Append(" l S\n");
            }
        }
        public byte[] Bytes(string footer)
        {
            int n = pages.Count; List<byte[]> objs = new List<byte[]>();
            objs.Add(A("<< /Type /Catalog /Pages 2 0 R >>")); StringBuilder kids = new StringBuilder(); for (int i = 0; i < n; i++) kids.Append(6 + i * 2).Append(" 0 R ");
            objs.Add(A("<< /Type /Pages /Kids [ " + kids.ToString().Trim() + " ] /Count " + n + " >>"));
            objs.Add(A("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")); objs.Add(A("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"));
            for (int i = 0; i < n; i++)
            {
                StringBuilder c = new StringBuilder();
                // header: brand line left, report · host right, accent rule; footer: page n of N
                c.Append("BT /F2 8 Tf ").Append(Rgb(brand.Accent)).Append(" rg ").Append(F(ML)).Append(' ').Append(F(PH - 34)).Append(" Td (").Append(Esc(headLeft)).Append(") Tj ET\n");
                string hr = headRight; float hw = Width(hr, 8); c.Append("BT /F1 8 Tf ").Append(Rgb(brand.Muted)).Append(" rg ").Append(F(PW - MR - hw)).Append(' ').Append(F(PH - 34)).Append(" Td (").Append(Esc(hr)).Append(") Tj ET\n");
                c.Append(Rgb(brand.Accent)).Append(" RG 1.2 w ").Append(F(ML)).Append(' ').Append(F(PH - 40)).Append(" m ").Append(F(PW - MR)).Append(' ').Append(F(PH - 40)).Append(" l S\n");
                string pg = "Page " + (i + 1) + " of " + n; c.Append("BT /F1 7.5 Tf ").Append(Rgb(brand.Muted)).Append(" rg ").Append(F(ML)).Append(' ').Append(F(MB - 22)).Append(" Td (").Append(Esc(footer)).Append(") Tj ET\n");
                c.Append("BT /F1 7.5 Tf ").Append(Rgb(brand.Muted)).Append(" rg ").Append(F(PW - MR - Width(pg, 7.5f))).Append(' ').Append(F(MB - 22)).Append(" Td (").Append(Esc(pg)).Append(") Tj ET\n");
                c.Append(pages[i]);
                byte[] stream = Encoding.GetEncoding(1252).GetBytes(c.ToString()); byte[] head = A("<< /Length " + stream.Length + " >>\nstream\n"), tail = A("\nendstream");
                byte[] content = new byte[head.Length + stream.Length + tail.Length]; Buffer.BlockCopy(head, 0, content, 0, head.Length); Buffer.BlockCopy(stream, 0, content, head.Length, stream.Length); Buffer.BlockCopy(tail, 0, content, head.Length + stream.Length, tail.Length);
                objs.Add(content); objs.Add(A("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents " + (5 + i * 2) + " 0 R >>"));
            }
            using (MemoryStream ms = new MemoryStream())
            {
                byte[] hdr = A("%PDF-1.4\n%\u00e2\u00e3\u00cf\u00d3\n"); ms.Write(hdr, 0, hdr.Length); List<long> offs = new List<long>();
                for (int i = 0; i < objs.Count; i++) { offs.Add(ms.Position); byte[] pre = A((i + 1) + " 0 obj\n"); ms.Write(pre, 0, pre.Length); ms.Write(objs[i], 0, objs[i].Length); byte[] post = A("\nendobj\n"); ms.Write(post, 0, post.Length); }
                long xref = ms.Position; StringBuilder x = new StringBuilder(); x.Append("xref\n0 ").Append(objs.Count + 1).Append("\n0000000000 65535 f \n"); foreach (long o in offs) x.Append(o.ToString("0000000000")).Append(" 00000 n \n");
                x.Append("trailer\n<< /Size ").Append(objs.Count + 1).Append(" /Root 1 0 R >>\nstartxref\n").Append(xref).Append("\n%%EOF\n"); byte[] xb = A(x.ToString()); ms.Write(xb, 0, xb.Length);
                return ms.ToArray();
            }
        }
        static byte[] A(string s) { return Encoding.GetEncoding(1252).GetBytes(s); }
    }
}
