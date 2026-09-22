using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

// Purpose: Generate web-based HTML ADRecon report with embedded jQuery, Chart.js, DataTables.
// Dashboard-style report with interactive charts, pivot tables, and slicer filtering.
namespace AdRecon.Report
{
    // HTML Report Generator: Convert CSV data into an interactive single-page HTML report.
    public class HtmlReportGenerator
    {
        // Internal data structure representing a data sheet (corresponds to one CSV file).
        class SheetData
        {
            public string Name;
            public string Id;
            public string[] Headers;
            public List<string[]> Rows;
        }

        // Mapping between CSV files and report sheets.
        class CsvMapping
        {
            public string File;
            public string SheetName;
            public string Id;
        }

        // Main entry: Load CSV data, embed frontend libraries, generate complete HTML report file.
        public string Generate(string csvDir, string outputDir, string logo)
        {
            // Get CSV file to report sheet mapping configuration.
            var csvMapping = GetCsvMapping();
            var sheets = new List<SheetData>();

            // Read and parse each CSV file into SheetData objects.
            foreach (var m in csvMapping)
            {
                string path = Path.Combine(csvDir, m.File);
                if (!File.Exists(path)) continue;
                try
                {
                    var lines = File.ReadAllLines(path);
                    if (lines.Length < 1) continue;
                    sheets.Add(new SheetData
                    {
                        Name = m.SheetName,
                        Id = m.Id,
                        Headers = ParseCsvLine(lines[0]),
                        Rows = lines.Skip(1).Where(l => !string.IsNullOrWhiteSpace(l)).Select(l => ParseCsvLine(l)).ToList()
                    });
                }
                catch (Exception)
                {
                }
            }

            // Read frontend library files from embedded resources (jQuery, Chart.js, DataTables).
            string domain = GetDomainName(csvDir);
            string jqueryJs = ReadEmbeddedResource("AdRecon.lib.jquery.min.js");
            string chartJs = ReadEmbeddedResource("AdRecon.lib.chart.min.js");
            string dtJs = ReadEmbeddedResource("AdRecon.lib.datatables.min.js");
            string dtCss = ReadEmbeddedResource("AdRecon.lib.datatables.min.css");
            // Generate complete HTML content and write to file.
            string html = GenerateHtml(sheets, domain, jqueryJs, chartJs, dtJs, dtCss);
            string output = Path.Combine(outputDir, "ADRecon-Report.html");
            File.WriteAllText(output, html, Encoding.UTF8);
            return output;
        }

        // Read text content from assembly embedded resources (for frontend library files).
        static string ReadEmbeddedResource(string name)
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            using (Stream s = asm.GetManifestResourceStream(name))
            {
                if (s == null) return "";
                using (var r = new StreamReader(s, Encoding.UTF8))
                    return r.ReadToEnd();
            }
        }

        // Extract domain name from Domain.csv for report title display.
        static string GetDomainName(string csvDir)
        {
            string path = Path.Combine(csvDir, "Domain.csv");
            if (!File.Exists(path)) return "AD";
            foreach (string line in File.ReadLines(path))
            {
                string[] parts = line.Split(',');
                if (parts.Length >= 2 && parts[0].Trim() == "Name")
                    return parts[1].Trim();
            }
            return "AD";
        }

        // Define mapping of all CSV files to report sheets.
        static List<CsvMapping> GetCsvMapping()
        {
            return new List<CsvMapping>
            {
                new CsvMapping { File = "AboutADRecon.csv", SheetName = "About ADRecon", Id = "about" },
                new CsvMapping { File = "Forest.csv", SheetName = "Forest", Id = "forest" },
                new CsvMapping { File = "Domain.csv", SheetName = "Domain", Id = "domain" },
                new CsvMapping { File = "DomainControllers.csv", SheetName = "Domain Controllers", Id = "dc" },
                new CsvMapping { File = "Trusts.csv", SheetName = "Trusts", Id = "trusts" },
                new CsvMapping { File = "Sites.csv", SheetName = "Sites", Id = "sites" },
                new CsvMapping { File = "Subnets.csv", SheetName = "Subnets", Id = "subnets" },
                new CsvMapping { File = "SchemaHistory.csv", SheetName = "Schema History", Id = "schema" },
                new CsvMapping { File = "DefaultPasswordPolicy.csv", SheetName = "Default Password Policy", Id = "pwdpol" },
                new CsvMapping { File = "FineGrainedPasswordPolicy.csv", SheetName = "Fine Grained Password Policy", Id = "fgpp" },
                new CsvMapping { File = "Users.csv", SheetName = "Users", Id = "users" },
                new CsvMapping { File = "UserSPNs.csv", SheetName = "User SPNs", Id = "userspns" },
                new CsvMapping { File = "Groups.csv", SheetName = "Groups", Id = "groups" },
                new CsvMapping { File = "GroupMembers.csv", SheetName = "Group Members", Id = "groupmembers" },
                new CsvMapping { File = "GroupChanges.csv", SheetName = "Group Changes", Id = "groupchanges" },
                new CsvMapping { File = "Computers.csv", SheetName = "Computers", Id = "computers" },
                new CsvMapping { File = "ComputerSPNs.csv", SheetName = "Computer SPNs", Id = "computerspns" },
                new CsvMapping { File = "OUs.csv", SheetName = "OUs", Id = "ous" },
                new CsvMapping { File = "GPOs.csv", SheetName = "GPOs", Id = "gpos" },
                new CsvMapping { File = "GPLinks.csv", SheetName = "gPLinks", Id = "gplinks" },
                new CsvMapping { File = "DNSZones.csv", SheetName = "DNS Zones", Id = "dnszones" },
                new CsvMapping { File = "DNSRecords.csv", SheetName = "DNS Records", Id = "dnsrecords" },
                new CsvMapping { File = "Printers.csv", SheetName = "Printers", Id = "printers" },
                new CsvMapping { File = "BitLockerRecoveryKeys.csv", SheetName = "BitLocker", Id = "bitlocker" },
                new CsvMapping { File = "LAPS.csv", SheetName = "LAPS", Id = "laps" },
                new CsvMapping { File = "DACLs.csv", SheetName = "DACLs", Id = "dacls" },
                new CsvMapping { File = "SACLs.csv", SheetName = "SACLs", Id = "sacls" },
            };
        }

        // Simple CSV row parser, handles quoted fields and comma delimiters.
        static string[] ParseCsvLine(string line)
        {
            var fields = new List<string>();
            bool inQuote = false;
            int start = 0;
            for (int i = 0; i < line.Length; i++)
            {
                if (line[i] == '"') inQuote = !inQuote;
                else if (line[i] == ',' && !inQuote)
                {
                    fields.Add(line.Substring(start, i - start));
                    start = i + 1;
                }
            }
            fields.Add(line.Substring(start));
            return fields.ToArray();
        }

        // HTML escape function to prevent XSS attacks and ensure safe output.
        static string H(string s)
        {
            if (s == null) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&#39;");
        }

        // Find column index by column name in the header row.
        static int GetCol(string[] headers, string name)
        {
            return Array.IndexOf(headers, name);
        }

        // Safely get value of specified column from a row, returns empty string on out of bounds.
        static string GetVal(string[] row, int col)
        {
            if (col < 0 || col >= row.Length) return "";
            return row[col];
        }

        // Count rows where value in specified column is "True".
        static int CountTrue(SheetData s, string col)
        {
            int ci = GetCol(s.Headers, col);
            if (ci < 0) return 0;
            return s.Rows.Count(r => GetVal(r, ci) == "True");
        }

        // Count rows where value in specified column matches a specific value.
        static int CountTrueFalse(SheetData s, string col, string val)
        {
            int ci = GetCol(s.Headers, col);
            if (ci < 0) return 0;
            return s.Rows.Count(r => GetVal(r, ci) == val);
        }

        // Count rows where value in specified column is non-empty.
        static int CountNonEmpty(SheetData s, string col)
        {
            int ci = GetCol(s.Headers, col);
            if (ci < 0) return 0;
            return s.Rows.Count(r => !string.IsNullOrEmpty(GetVal(r, ci)));
        }

        // Count rows where value in specified column equals a specific value (generic count).
        static int CountValue(SheetData s, string col, string val)
        {
            int ci = GetCol(s.Headers, col);
            if (ci < 0) return 0;
            return s.Rows.Count(r => GetVal(r, ci) == val);
        }

        // Group and count by specified column, returns dictionary of value to count.
        static Dictionary<string, int> GroupBy(SheetData s, string col)
        {
            int ci = GetCol(s.Headers, col);
            var d = new Dictionary<string, int>();
            if (ci < 0) return d;
            foreach (var row in s.Rows)
            {
                string v = GetVal(row, ci);
                if (!string.IsNullOrEmpty(v))
                    d[v] = d.ContainsKey(v) ? d[v] + 1 : 1;
            }
            return d;
        }

        // Generate complete HTML report content including dashboard, stats, charts, and raw data.
        static string GenerateHtml(List<SheetData> sheets, string domain, string jqueryJs, string chartJs, string dtJs, string dtCss)
        {
            var sb = new StringBuilder();
            // Extract common worksheet data references.
            var users = sheets.FirstOrDefault(s => s.Id == "users");
            var computers = sheets.FirstOrDefault(s => s.Id == "computers");
            var groups = sheets.FirstOrDefault(s => s.Id == "groups");
            var groupMembers = sheets.FirstOrDefault(s => s.Id == "groupmembers");
            var computerSpns = sheets.FirstOrDefault(s => s.Id == "computerspns");
            var userSpns = sheets.FirstOrDefault(s => s.Id == "userspns");
            var pwdPol = sheets.FirstOrDefault(s => s.Id == "pwdpol");
            var fgpp = sheets.FirstOrDefault(s => s.Id == "fgpp");
            var laps = sheets.FirstOrDefault(s => s.Id == "laps");
            var bitlocker = sheets.FirstOrDefault(s => s.Id == "bitlocker");

            // Calculate basic statistics for users and computers.
            int usersTotal = users != null ? users.Rows.Count : 0;
            int usersEnabled = users != null ? CountTrue(users, "Enabled") : 0;
            int usersDisabled = usersTotal - usersEnabled;
            int compsTotal = computers != null ? computers.Rows.Count : 0;
            int compsEnabled = computers != null ? CountTrue(computers, "Enabled") : 0;
            int compsDisabled = compsTotal - compsEnabled;

            // Calculate security attribute statistics for user accounts.
            int uMustChange = users != null ? CountValue(users, "Must Change Password at Logon", "True") : 0;
            int uCannotChange = users != null ? CountValue(users, "Cannot Change Password", "True") : 0;
            int uPwdNeverExpires = users != null ? CountValue(users, "Password Never Expires", "True") : 0;
            int uReversible = users != null ? CountValue(users, "Reversible Password Encryption", "True") : 0;
            int uSmartcard = users != null ? CountValue(users, "Smartcard Logon Required", "True") : 0;
            int uDelegation = users != null ? CountValue(users, "Delegation Permitted", "True") : 0;
            int uKerbDES = users != null ? CountValue(users, "Kerberos DES Only", "True") : 0;
            int uKerbRC4 = users != null ? CountValue(users, "Kerberos RC4", "True") : 0;
            int uNoPreAuth = users != null ? CountValue(users, "Does Not Require Pre Auth", "True") : 0;
            int uLocked = users != null ? CountValue(users, "Account Locked Out", "True") : 0;
            int uDormant = users != null ? CountValue(users, "Dormant", "True") : 0;
            int uPwdNotRequired = users != null ? CountValue(users, "Password Not Required", "True") : 0;
            int uUnconstrained = users != null ? CountValue(users, "Delegation Typ", "Unconstrained") : 0;
            int uSIDHistory = users != null ? CountNonEmpty(users, "SIDHistory") : 0;

            // Calculate security attribute statistics for computer accounts.
            int cUnconstrained = computers != null ? CountValue(computers, "Delegation Typ", "Unconstrained") : 0;
            int cConstrained = computers != null ? CountValue(computers, "Delegation Type", "Constrained") : 0;
            int cSIDHistory = computers != null ? CountNonEmpty(computers, "SIDHistory") : 0;
            int cDormant = computers != null ? CountValue(computers, "Dormant", "True") : 0;
            int cCreatorSid = computers != null ? CountNonEmpty(computers, "ms-ds-CreatorSid") : 0;
            int cLAPSStored = 0;
            if (laps != null)
            {
                int storedCol = GetCol(laps.Headers, "Stored");
                if (storedCol >= 0) cLAPSStored = laps.Rows.Count(r => GetVal(r, storedCol) == "True");
            }

            // Define list of privileged groups to track.
            string[] privGroups = { "Account Operators", "Administrators", "Backup Operators", "Cert Publishers",
                "Crypto Operators", "DnsAdmins", "Domain Admins", "Enterprise Admins", "Enterprise Key Admins",
                "Incoming Forest Trust Builders", "Key Admins", "Microsoft Advanced Threat Analytics Administrators",
                "Network Operators", "Print Operators", "Protected Users", "Remote Desktop Users", "Schema Admins", "Server Operators" };
            // Count user members in each privileged group.
            var privGroupCounts = new Dictionary<string, int>();
            if (groupMembers != null)
            {
                int gnCol = GetCol(groupMembers.Headers, "Group Name");
                int atCol = GetCol(groupMembers.Headers, "AccountType");
                if (gnCol >= 0)
                {
                    foreach (var row in groupMembers.Rows)
                    {
                        string gn = GetVal(row, gnCol);
                        string at = atCol >= 0 ? GetVal(row, atCol) : "";
                        if (at != "user") continue;
                        if (Array.IndexOf(privGroups, gn) >= 0)
                            privGroupCounts[gn] = privGroupCounts.ContainsKey(gn) ? privGroupCounts[gn] + 1 : 1;
                    }
                }
            }

            // Group by operating system and SPN service for statistics.
            var osCounts = computers != null ? GroupBy(computers, "Operating System") : new Dictionary<string, int>();
            var spnCounts = computerSpns != null ? GroupBy(computerSpns, "Service") : new Dictionary<string, int>();

            // Count members per group (for Top 15 chart).
            var groupMemberCounts = new Dictionary<string, int>();
            if (groupMembers != null)
            {
                int gnCol = GetCol(groupMembers.Headers, "Group Name");
                if (gnCol >= 0)
                    foreach (var row in groupMembers.Rows)
                    {
                        string gn = GetVal(row, gnCol);
                        if (!string.IsNullOrEmpty(gn))
                            groupMemberCounts[gn] = groupMemberCounts.ContainsKey(gn) ? groupMemberCounts[gn] + 1 : 1;
                    }
            }

            // ========== HTML Document Structure ==========
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"en\">");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset=\"UTF-8\">");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            sb.AppendLine("<title>ADRecon Report - " + H(domain) + "</title>");

            // Embed DataTables CSS styles.
            if (dtCss.Length > 0)
            {
                sb.AppendLine("<style>");
                sb.AppendLine(dtCss);
                sb.AppendLine("</style>");
            }
            // Embed custom CSS styles (dashboard layout, cards, charts, tables, etc.).
            sb.AppendLine("<style>");
            sb.AppendLine(@"
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f0f2f5;color:#333}
.header{background:linear-gradient(135deg,#1a237e,#283593);color:#fff;padding:20px 30px;box-shadow:0 2px 8px rgba(0,0,0,.3)}
.header h1{font-size:24px;font-weight:300}
.header .domain{font-size:14px;opacity:.8;margin-top:4px}
.container{display:flex;min-height:calc(100vh - 80px)}
.sidebar{width:240px;background:#fff;box-shadow:2px 0 8px rgba(0,0,0,.1);padding:10px 0;overflow-y:auto;position:fixed;height:calc(100vh - 80px)}
.sidebar a{display:block;padding:10px 20px;color:#555;text-decoration:none;font-size:13px;border-left:3px solid transparent;transition:.2s}
.sidebar a:hover,.sidebar a.active{background:#e8eaf6;color:#1a237e;border-left-color:#1a237e}
.sidebar .section{padding:10px 20px 5px;font-size:11px;text-transform:uppercase;color:#999;font-weight:600;letter-spacing:1px}
.main{margin-left:240px;padding:20px 30px;flex:1;min-width:0}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 4px rgba(0,0,0,.1)}
.stat-card .value{font-size:28px;font-weight:700;color:#1a237e}
.stat-card .label{font-size:11px;color:#888;margin-top:4px}
.stat-card.warn .value{color:#e65100}
.stat-card.danger .value{color:#c62828}
.stat-card.ok .value{color:#2e7d32}
.chart-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
.chart-box{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 4px rgba(0,0,0,.1)}
.chart-box h3{font-size:14px;color:#555;margin-bottom:10px}
.sheet{display:none;background:#fff;border-radius:8px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:20px}
.sheet.active{display:block}
.sheet h2{font-size:18px;color:#1a237e;margin-bottom:12px;border-bottom:2px solid #e8eaf6;padding-bottom:8px}
table.dataTable{width:100%!important;font-size:12px}
table.dataTable thead th{background:#e8eaf6;color:#1a237e;padding:8px}
.dataTables_wrapper .dataTables_filter input{border:1px solid #ccc;border-radius:4px;padding:4px 8px}
table.stats{border-collapse:collapse;width:100%;margin-bottom:20px;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1)}
table.stats th{background:#e8eaf6;color:#1a237e;padding:10px 14px;text-align:left;font-size:13px;border-bottom:2px solid #c5cae9}
table.stats td{padding:8px 14px;border-bottom:1px solid #eee;font-size:13px}
table.stats tr:hover{background:#f5f5f5}
table.stats .num{text-align:right;font-weight:600}
table.stats .warn{color:#e65100}
table.stats .fail{color:#c62828;font-weight:700}
table.stats .pass{color:#2e7d32}
.pivot-container{background:#fff;border-radius:8px;padding:16px;box-shadow:0 1px 4px rgba(0,0,0,.1);margin-bottom:16px}
.pivot-container h3{font-size:14px;color:#555;margin-bottom:10px}
.pivot-table{border-collapse:collapse;width:100%;font-size:12px}
.pivot-table th{background:#e8eaf6;color:#1a237e;padding:8px 12px;text-align:left;border-bottom:2px solid #c5cae9;cursor:pointer;user-select:none}
.pivot-table th:hover{background:#c5cae9}
.pivot-table td{padding:6px 12px;border-bottom:1px solid #eee}
.pivot-table tr:hover{background:#f5f5f5}
.pivot-table .total{font-weight:700;background:#f5f5f5}
.slicer-panel{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;padding:10px;background:#f8f9fa;border-radius:6px}
.slicer-btn{padding:6px 14px;border:1px solid #ccc;border-radius:4px;background:#fff;cursor:pointer;font-size:12px;transition:.2s}
.slicer-btn:hover{background:#e8eaf6;border-color:#1a237e}
.slicer-btn.active{background:#1a237e;color:#fff;border-color:#1a237e}
.slicer-btn .count{margin-left:4px;color:#888;font-size:10px}
.slicer-btn.active .count{color:#ccc}
.toc{list-style:none;padding:0}
.toc li{padding:6px 0;border-bottom:1px solid #eee}
.toc li a{color:#1a237e;text-decoration:none}
.toc li a:hover{text-decoration:underline}
@media print{.sidebar{display:none}.main{margin-left:0}.header{background:#1a237e!important;-webkit-print-color-adjust:exact}}
");
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");

            // ========== Page Header ==========
            sb.AppendLine("<div class=\"header\">");
            sb.AppendLine("  <h1>ADRecon Report</h1>");
            sb.AppendLine("  <div class=\"domain\">" + H(domain) + " | Generated " + DateTime.Now.ToString("yyyy-MM-dd HH:mm") + "</div>");
            sb.AppendLine("</div>");

            sb.AppendLine("<div class=\"container\">");

            // ========== Sidebar Navigation ==========
            sb.AppendLine("<div class=\"sidebar\">");
            sb.AppendLine("  <div class=\"section\">Table of Contents</div>");
            sb.AppendLine("  <a href=\"#\" onclick=\"showSheet('toc')\" class=\"active\">Contents</a>");
            sb.AppendLine("  <div class=\"section\">Dashboard</div>");
            sb.AppendLine("  <a href=\"#\" onclick=\"showSheet('summary')\">Summary</a>");
            sb.AppendLine("  <div class=\"section\">Stats &amp; Analysis</div>");
            sb.AppendLine("  <a href=\"#\" onclick=\"showSheet('user-stats')\">User Stats</a>");
            sb.AppendLine("  <a href=\"#\" onclick=\"showSheet('comp-stats')\">Computer Stats</a>");
            sb.AppendLine("  <a href=\"#\" onclick=\"showSheet('comp-role-stats')\">Computer Role Stats</a>");
            sb.AppendLine("  <a href=\"#\" onclick=\"showSheet('os-stats')\">OS Stats</a>");
            sb.AppendLine("  <a href=\"#\" onclick=\"showSheet('priv-group-stats')\">Privileged Group Stats</a>");
            sb.AppendLine("  <a href=\"#\" onclick=\"showSheet('pwdpol-stats')\">Password Policy Compliance</a>");
            sb.AppendLine("  <div class=\"section\">Raw Data</div>");
            // Organize raw data worksheet navigation links by category.
            string[][] sections = {
                new[] { "Infrastructure", "about,forest,domain,dc,trusts,sites,subnets,schema" },
                new[] { "Security", "pwdpol,fgpp,laps,bitlocker,dacls,sacls" },
                new[] { "Accounts", "users,userspns,groups,groupmembers,groupchanges" },
                new[] { "Computers", "computers,computerspns" },
                new[] { "Organization", "ous,gpos,gplinks,dnszones,dnsrecords,printers" }
            };
            foreach (var sec in sections)
            {
                sb.AppendLine("  <div class=\"section\" style=\"margin-top:4px\">" + sec[0] + "</div>");
                foreach (var id in sec[1].Split(','))
                {
                    var s = sheets.FirstOrDefault(x => x.Id == id);
                    if (s != null)
                        sb.AppendLine("  <a href=\"#\" onclick=\"showSheet('" + s.Id + "')\">" + H(s.Name) + " <span style=\"color:#aaa;font-size:11px\">(" + s.Rows.Count + ")</span></a>");
                }
            }
            sb.AppendLine("</div>");

            sb.AppendLine("<div class=\"main\">");

            // ========== Table of Contents ==========
            sb.AppendLine("<div id=\"sheet-toc\" class=\"sheet active\">");
            sb.AppendLine("  <h2>Table of Contents</h2>");
            sb.AppendLine("  <ul class=\"toc\">");
            int tocRow = 1;
            sb.AppendLine("    <li><a href=\"#\" onclick=\"showSheet('summary')\">" + (tocRow++) + ". Dashboard Summary</a></li>");
            sb.AppendLine("    <li><a href=\"#\" onclick=\"showSheet('user-stats')\">" + (tocRow++) + ". User Stats</a></li>");
            sb.AppendLine("    <li><a href=\"#\" onclick=\"showSheet('comp-stats')\">" + (tocRow++) + ". Computer Stats</a></li>");
            sb.AppendLine("    <li><a href=\"#\" onclick=\"showSheet('comp-role-stats')\">" + (tocRow++) + ". Computer Role Stats</a></li>");
            sb.AppendLine("    <li><a href=\"#\" onclick=\"showSheet('os-stats')\">" + (tocRow++) + ". Operating System Stats</a></li>");
            sb.AppendLine("    <li><a href=\"#\" onclick=\"showSheet('priv-group-stats')\">" + (tocRow++) + ". Privileged Group Stats</a></li>");
            sb.AppendLine("    <li><a href=\"#\" onclick=\"showSheet('pwdpol-stats')\">" + (tocRow++) + ". Password Policy Compliance</a></li>");
            foreach (var s in sheets)
                sb.AppendLine("    <li><a href=\"#\" onclick=\"showSheet('" + s.Id + "')\">" + (tocRow++) + ". " + H(s.Name) + " (" + s.Rows.Count + " records)</a></li>");
            sb.AppendLine("  </ul>");
            sb.AppendLine("</div>");

            // ========== Summary Dashboard ==========
            sb.AppendLine("<div id=\"sheet-summary\" class=\"sheet\">");
            sb.AppendLine("  <h2>Dashboard Summary</h2>");
            sb.AppendLine("  <div class=\"summary\">");
            sb.AppendLine("    <div class=\"stat-card\"><div class=\"value\">" + usersTotal + "</div><div class=\"label\">Total Users</div></div>");
            sb.AppendLine("    <div class=\"stat-card ok\"><div class=\"value\">" + usersEnabled + "</div><div class=\"label\">Enabled Users</div></div>");
            sb.AppendLine("    <div class=\"stat-card danger\"><div class=\"value\">" + usersDisabled + "</div><div class=\"label\">Disabled Users</div></div>");
            sb.AppendLine("    <div class=\"stat-card\"><div class=\"value\">" + compsTotal + "</div><div class=\"label\">Total Computers</div></div>");
            sb.AppendLine("    <div class=\"stat-card ok\"><div class=\"value\">" + compsEnabled + "</div><div class=\"label\">Enabled Computers</div></div>");
            sb.AppendLine("    <div class=\"stat-card danger\"><div class=\"value\">" + compsDisabled + "</div><div class=\"label\">Disabled Computers</div></div>");
            sb.AppendLine("    <div class=\"stat-card\"><div class=\"value\">" + (groups != null ? groups.Rows.Count : 0) + "</div><div class=\"label\">Total Groups</div></div>");
            sb.AppendLine("    <div class=\"stat-card\"><div class=\"value\">" + (groupMembers != null ? groupMembers.Rows.Count : 0) + "</div><div class=\"label\">Group Memberships</div></div>");
            if (laps != null) sb.AppendLine("    <div class=\"stat-card\"><div class=\"value\">" + laps.Rows.Count + "</div><div class=\"label\">LAPS Enabled</div></div>");
            if (bitlocker != null) sb.AppendLine("    <div class=\"stat-card\"><div class=\"value\">" + bitlocker.Rows.Count + "</div><div class=\"label\">BitLocker Keys</div></div>");
            sb.AppendLine("  </div>");
            // Dashboard chart area: user and computer status pie charts.
            sb.AppendLine("  <div class=\"chart-row\">");
            sb.AppendLine("    <div class=\"chart-box\"><h3>User Accounts Status</h3><canvas id=\"chart-users\" height=\"75\"></canvas></div>");
            sb.AppendLine("    <div class=\"chart-box\"><h3>Computer Accounts Status</h3><canvas id=\"chart-comps\" height=\"75\"></canvas></div>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div class=\"chart-row\">");
            if (osCounts.Count > 0) sb.AppendLine("    <div class=\"chart-box\"><h3>Operating Systems</h3><canvas id=\"chart-os\" height=\"75\"></canvas></div>");
            if (spnCounts.Count > 0) sb.AppendLine("    <div class=\"chart-box\"><h3>Computer SPN Roles</h3><canvas id=\"chart-spn\" height=\"75\"></canvas></div>");
            sb.AppendLine("  </div>");
            if (groupMemberCounts.Count > 0)
            {
                sb.AppendLine("  <div class=\"chart-row\"><div class=\"chart-box\" style=\"grid-column:span 2\"><h3>Top 15 Groups by Membership</h3><canvas id=\"chart-groups\" height=\"75\"></canvas></div></div>");
            }
            sb.AppendLine("</div>");

            // ========== User Stats ==========
            sb.AppendLine("<div id=\"sheet-user-stats\" class=\"sheet\">");
            sb.AppendLine("  <h2>User Accounts in AD</h2>");
            sb.AppendLine("  <div class=\"summary\">");
            sb.AppendLine("    <div class=\"stat-card\"><div class=\"value\">" + usersTotal + "</div><div class=\"label\">Total Users</div></div>");
            sb.AppendLine("    <div class=\"stat-card ok\"><div class=\"value\">" + usersEnabled + "</div><div class=\"label\">Enabled (" + (usersTotal > 0 ? (usersEnabled * 100 / usersTotal) : 0) + "%)</div></div>");
            sb.AppendLine("    <div class=\"stat-card danger\"><div class=\"value\">" + usersDisabled + "</div><div class=\"label\">Disabled (" + (usersTotal > 0 ? (usersDisabled * 100 / usersTotal) : 0) + "%)</div></div>");
            sb.AppendLine("  </div>");
                // User security attributes stats table.
                sb.AppendLine("  <table class=\"stats\"><thead><tr><th>Attribute</th><th>Count</th><th>%</th></tr></thead><tbody>");
                string[] uAttrNames = { "Must Change Password at Logon", "Cannot Change Password", "Password Never Expires", "Reversible Password Encryption", "Smartcard Logon Required", "Delegation Permitted", "Kerberos DES Only", "Kerberos RC4", "Does Not Require Pre Auth", "Account Locked Out", "Dormant", "Password Not Required", "Unconstrained Delegation", "SID History" };
                int[] uAttrVals = { uMustChange, uCannotChange, uPwdNeverExpires, uReversible, uSmartcard, uDelegation, uKerbDES, uKerbRC4, uNoPreAuth, uLocked, uDormant, uPwdNotRequired, uUnconstrained, uSIDHistory };
                for (int i = 0; i < uAttrNames.Length; i++)
                {
                    string pct = usersTotal > 0 ? (uAttrVals[i] * 100.0 / usersTotal).ToString("F1") : "0";
                    string cls = uAttrVals[i] > 0 ? " class=\"warn\"" : "";
                    sb.AppendLine("    <tr><td>" + uAttrNames[i] + "</td><td class=\"num\"" + cls + ">" + uAttrVals[i] + "</td><td class=\"num\">" + pct + "%</td></tr>");
                }
                sb.AppendLine("  </tbody></table>");
            sb.AppendLine("  <div class=\"chart-row\"><div class=\"chart-box\"><h3>User Attribute Analysis</h3><canvas id=\"chart-user-attrs\" height=\"75\"></canvas></div></div>");

            // User account pivot table (grouped by enabled status).
            if (users != null)
            {
                var userPivotRows = new List<string>();
                foreach (var row in users.Rows)
                {
                    string enabled = GetVal(row, GetCol(users.Headers, "Enabled")) == "True" ? "Enabled" : "Disabled";
                    var attrs = new Dictionary<string, string>();
                    attrs["Enabled"] = enabled;
                    attrs["Must Change Password"] = GetVal(row, GetCol(users.Headers, "Must Change Password at Logon")) == "True" ? "1" : "0";
                    attrs["Cannot Change Password"] = GetVal(row, GetCol(users.Headers, "Cannot Change Password")) == "True" ? "1" : "0";
                    attrs["Password Never Expires"] = GetVal(row, GetCol(users.Headers, "Password Never Expires")) == "True" ? "1" : "0";
                    attrs["Reversible Encryption"] = GetVal(row, GetCol(users.Headers, "Reversible Password Encryption")) == "True" ? "1" : "0";
                    attrs["Smartcard Required"] = GetVal(row, GetCol(users.Headers, "Smartcard Logon Required")) == "True" ? "1" : "0";
                    attrs["Delegation Permitted"] = GetVal(row, GetCol(users.Headers, "Delegation Permitted")) == "True" ? "1" : "0";
                    attrs["Kerberos DES"] = GetVal(row, GetCol(users.Headers, "Kerberos DES Only")) == "True" ? "1" : "0";
                    attrs["Kerberos RC4"] = GetVal(row, GetCol(users.Headers, "Kerberos RC4")) == "True" ? "1" : "0";
                    attrs["No Pre-Auth"] = GetVal(row, GetCol(users.Headers, "Does Not Require Pre Auth")) == "True" ? "1" : "0";
                    attrs["Locked Out"] = GetVal(row, GetCol(users.Headers, "Account Locked Out")) == "True" ? "1" : "0";
                    attrs["Dormant"] = GetVal(row, GetCol(users.Headers, "Dormant")) == "True" ? "1" : "0";
                    attrs["Unconstrained Delegation"] = GetVal(row, GetCol(users.Headers, "Delegation Typ")) == "Unconstrained" ? "1" : "0";
                    string json = "{";
                    bool first = true;
                    foreach (var kv in attrs) { if (!first) json += ","; first = false; json += "\"" + kv.Key + "\":\"" + kv.Value + "\""; }
                    json += "}";
                    userPivotRows.Add(json);
                }
                sb.AppendLine("<script>$(document).ready(function(){createPivot('pivot-user-attrs',[" + string.Join(",", userPivotRows) + "],{rowField:'Enabled',valueFields:['Must Change Password','Cannot Change Password','Password Never Expires','Reversible Encryption','Smartcard Required','Delegation Permitted','Kerberos DES','Kerberos RC4','No Pre-Auth','Locked Out','Dormant','Unconstrained Delegation']})});</script>");
            }

            sb.AppendLine("</div>");

            // ========== Computer Stats ==========
            sb.AppendLine("<div id=\"sheet-comp-stats\" class=\"sheet\">");
            sb.AppendLine("  <h2>Computer Accounts in AD</h2>");
            sb.AppendLine("  <div class=\"summary\">");
            sb.AppendLine("    <div class=\"stat-card\"><div class=\"value\">" + compsTotal + "</div><div class=\"label\">Total Computers</div></div>");
            sb.AppendLine("    <div class=\"stat-card ok\"><div class=\"value\">" + compsEnabled + "</div><div class=\"label\">Enabled (" + (compsTotal > 0 ? (compsEnabled * 100 / compsTotal) : 0) + "%)</div></div>");
            sb.AppendLine("    <div class=\"stat-card danger\"><div class=\"value\">" + compsDisabled + "</div><div class=\"label\">Disabled (" + (compsTotal > 0 ? (compsDisabled * 100 / compsTotal) : 0) + "%)</div></div>");
            sb.AppendLine("  </div>");
            // Computer security attributes stats table.
            sb.AppendLine("  <table class=\"stats\"><thead><tr><th>Attribute</th><th>Count</th><th>%</th></tr></thead><tbody>");
            string[] cAttrNames = { "Unconstrained Delegation", "Constrained Delegation", "SID History", "Dormant", "ms-ds-CreatorSid (LAPS Potential)" };
            int[] cAttrVals = { cUnconstrained, cConstrained, cSIDHistory, cDormant, cCreatorSid };
            for (int i = 0; i < cAttrNames.Length; i++)
            {
                string pct = compsTotal > 0 ? (cAttrVals[i] * 100.0 / compsTotal).ToString("F1") : "0";
                string cls = cAttrVals[i] > 0 ? " class=\"warn\"" : "";
                sb.AppendLine("    <tr><td>" + cAttrNames[i] + "</td><td class=\"num\"" + cls + ">" + cAttrVals[i] + "</td><td class=\"num\">" + pct + "%</td></tr>");
            }
            if (laps != null)
            {
                string pct = compsTotal > 0 ? (cLAPSStored * 100.0 / compsTotal).ToString("F1") : "0";
                sb.AppendLine("    <tr><td>LAPS Stored</td><td class=\"num\">" + cLAPSStored + "</td><td class=\"num\">" + pct + "%</td></tr>");
            }
            sb.AppendLine("  </tbody></table>");
            sb.AppendLine("  <div class=\"chart-row\">");
            sb.AppendLine("    <div class=\"chart-box\"><h3>Computer Accounts</h3><canvas id=\"chart-comp-pie\" height=\"75\"></canvas></div>");
            sb.AppendLine("    <div class=\"chart-box\"><h3>Computer Attribute Analysis</h3><canvas id=\"chart-comp-attrs\" height=\"75\"></canvas></div>");
            sb.AppendLine("  </div>");

            // Computer account pivot table.
            if (computers != null)
            {
                var compPivotRows = new List<string>();
                foreach (var row in computers.Rows)
                {
                    string enabled = GetVal(row, GetCol(computers.Headers, "Enabled")) == "True" ? "Enabled" : "Disabled";
                    var attrs = new Dictionary<string, string>();
                    attrs["Enabled"] = enabled;
                    attrs["Unconstrained Delegation"] = GetVal(row, GetCol(computers.Headers, "Delegation Typ")) == "Unconstrained" ? "1" : "0";
                    attrs["Constrained Delegation"] = GetVal(row, GetCol(computers.Headers, "Delegation Type")) == "Constrained" ? "1" : "0";
                    attrs["SID History"] = !string.IsNullOrEmpty(GetVal(row, GetCol(computers.Headers, "SIDHistory"))) ? "1" : "0";
                    attrs["Dormant"] = GetVal(row, GetCol(computers.Headers, "Dormant")) == "True" ? "1" : "0";
                    attrs["LAPS"] = !string.IsNullOrEmpty(GetVal(row, GetCol(computers.Headers, "ms-ds-CreatorSid"))) ? "1" : "0";
                    string json = "{";
                    bool first = true;
                    foreach (var kv in attrs) { if (!first) json += ","; first = false; json += "\"" + kv.Key + "\":\"" + kv.Value + "\""; }
                    json += "}";
                    compPivotRows.Add(json);
                }
                sb.AppendLine("<script>$(document).ready(function(){createPivot('pivot-comp-attrs',[" + string.Join(",", compPivotRows) + "],{rowField:'Enabled',valueFields:['Unconstrained Delegation','Constrained Delegation','SID History','Dormant','LAPS']})});</script>");
            }

            sb.AppendLine("</div>");

            // ========== Computer Role Stats ==========
            sb.AppendLine("<div id=\"sheet-comp-role-stats\" class=\"sheet\">");
            sb.AppendLine("  <h2>Computer Roles in AD</h2>");
            if (spnCounts.Count > 0)
            {
                var sorted = spnCounts.OrderByDescending(kv => kv.Value).ToList();
                sb.AppendLine("  <table class=\"stats\"><thead><tr><th>Computer Role</th><th>Count</th></tr></thead><tbody>");
                foreach (var kv in sorted)
                    sb.AppendLine("    <tr><td>" + H(kv.Key) + "</td><td class=\"num\">" + kv.Value + "</td></tr>");
                sb.AppendLine("  </tbody></table>");
                sb.AppendLine("  <div class=\"chart-box\" style=\"margin-top:16px\"><h3>Computer Roles in AD</h3><canvas id=\"chart-comp-roles\" height=\"75\"></canvas></div>");
            }
            else
            {
                sb.AppendLine("  <p>No Computer SPN data available.</p>");
            }
            sb.AppendLine("</div>");

            // ========== OS Stats ==========
            sb.AppendLine("<div id=\"sheet-os-stats\" class=\"sheet\">");
            sb.AppendLine("  <h2>Operating Systems in AD</h2>");
            if (osCounts.Count > 0)
            {
                var sorted = osCounts.OrderByDescending(kv => kv.Value).ToList();
                sb.AppendLine("  <table class=\"stats\"><thead><tr><th>Operating System</th><th>Count</th></tr></thead><tbody>");
                foreach (var kv in sorted)
                    sb.AppendLine("    <tr><td>" + H(kv.Key) + "</td><td class=\"num\">" + kv.Value + "</td></tr>");
                sb.AppendLine("  </tbody></table>");
                sb.AppendLine("  <div class=\"chart-box\" style=\"margin-top:16px\"><h3>Operating Systems in AD</h3><canvas id=\"chart-os-hbar\" height=\"75\"></canvas></div>");
            }
            else
            {
                sb.AppendLine("  <p>No Computer data available.</p>");
            }
            sb.AppendLine("</div>");

            // ========== Privileged Group Stats ==========
            sb.AppendLine("<div id=\"sheet-priv-group-stats\" class=\"sheet\">");
            sb.AppendLine("  <h2>Privileged Groups in AD</h2>");
            sb.AppendLine("  <table class=\"stats\"><thead><tr><th>Group Name</th><th>Members (User)</th></tr></thead><tbody>");
            foreach (var g in privGroups)
            {
                int cnt = privGroupCounts.ContainsKey(g) ? privGroupCounts[g] : 0;
                string cls = cnt > 0 ? "" : " class=\"pass\"";
                sb.AppendLine("    <tr><td>" + H(g) + "</td><td class=\"num\"" + cls + ">" + cnt + "</td></tr>");
            }
            sb.AppendLine("  </tbody></table>");

            // Privileged group members pivot table.
            if (groupMembers != null && privGroupCounts.Count > 0)
            {
                var privPivotRows = new List<string>();
                int gnCol = GetCol(groupMembers.Headers, "Group Name");
                int unCol = GetCol(groupMembers.Headers, "UserName");
                int atCol = GetCol(groupMembers.Headers, "AccountType");
                foreach (var row in groupMembers.Rows)
                {
                    string gn = GetVal(row, gnCol);
                    if (Array.IndexOf(privGroups, gn) < 0) continue;
                    string at = atCol >= 0 ? GetVal(row, atCol) : "";
                    if (at != "user") continue;
                    string json = "{\"Group\":\"" + H(gn).Replace("'", "\\'") + "\",\"UserName\":\"" + H(GetVal(row, unCol)).Replace("'", "\\'") + "\"}";
                    privPivotRows.Add(json);
                }
                sb.AppendLine("<script>$(document).ready(function(){createPivot('pivot-priv-groups',[" + string.Join(",", privPivotRows) + "],{rowField:'Group',valueFields:['UserName']})});</script>");
            }

            sb.AppendLine("  <div class=\"chart-box\" style=\"margin-top:16px\"><h3>Privileged Group Members</h3><canvas id=\"chart-priv-groups\" height=\"75\"></canvas></div>");
            sb.AppendLine("</div>");

            // ========== Password Policy Compliance ==========
            sb.AppendLine("<div id=\"sheet-pwdpol-stats\" class=\"sheet\">");
            sb.AppendLine("  <h2>Password Policy Compliance</h2>");
            if (pwdPol != null && pwdPol.Rows.Count > 0)
            {
                // Parse password policy settings into key-value dictionary.
                var pv = new Dictionary<string, string>();
                foreach (var row in pwdPol.Rows)
                {
                    if (row.Length >= 2)
                    {
                        string policyName = row[0].Trim();
                        string currentValue = row[1].Trim();
                        pv[policyName] = currentValue;
                    }
                }

                // Extract password policy values and perform compliance checks.
                int historyLen = 0, maxAge = 0, minAge = 0, minLen = 0, lockoutDur = 0, lockoutThresh = 0, lockoutReset = 0;
                bool complexity = false, reversible = false;
                if (pv.ContainsKey("Enforce password history (passwords)")) int.TryParse(pv["Enforce password history (passwords)"], out historyLen);
                if (pv.ContainsKey("Maximum password age (days)")) int.TryParse(pv["Maximum password age (days)"], out maxAge);
                if (pv.ContainsKey("Minimum password age (days)")) int.TryParse(pv["Minimum password age (days)"], out minAge);
                if (pv.ContainsKey("Minimum password length (characters)")) int.TryParse(pv["Minimum password length (characters)"], out minLen);
                if (pv.ContainsKey("Account lockout duration (mins)")) int.TryParse(pv["Account lockout duration (mins)"], out lockoutDur);
                if (pv.ContainsKey("Account lockout threshold (attempts)")) int.TryParse(pv["Account lockout threshold (attempts)"], out lockoutThresh);
                if (pv.ContainsKey("Reset account lockout counter after (mins)")) int.TryParse(pv["Reset account lockout counter after (mins)"], out lockoutReset);
                if (pv.ContainsKey("Password must meet complexity requirements")) bool.TryParse(pv["Password must meet complexity requirements"], out complexity);
                if (pv.ContainsKey("Store password using reversible encryption for all users in the domain")) bool.TryParse(pv["Store password using reversible encryption for all users in the domain"], out reversible);

                sb.AppendLine("  <h3 style=\"margin:12px 0 8px\">Current Settings</h3>");
                sb.AppendLine("  <table class=\"stats\"><thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody>");
                sb.AppendLine("    <tr><td>Enforce password history</td><td class=\"num\">" + historyLen + " passwords</td></tr>");
                sb.AppendLine("    <tr><td>Maximum password age</td><td class=\"num\">" + maxAge + " days</td></tr>");
                sb.AppendLine("    <tr><td>Minimum password age</td><td class=\"num\">" + minAge + " days</td></tr>");
                sb.AppendLine("    <tr><td>Minimum password length</td><td class=\"num\">" + minLen + " characters</td></tr>");
                sb.AppendLine("    <tr><td>Password complexity</td><td class=\"num\">" + complexity + "</td></tr>");
                sb.AppendLine("    <tr><td>Reversible encryption</td><td class=\"num\">" + reversible + "</td></tr>");
                sb.AppendLine("    <tr><td>Account lockout duration</td><td class=\"num\">" + lockoutDur + " mins</td></tr>");
                sb.AppendLine("    <tr><td>Account lockout threshold</td><td class=\"num\">" + lockoutThresh + " attempts</td></tr>");
                sb.AppendLine("    <tr><td>Reset lockout counter</td><td class=\"num\">" + lockoutReset + " mins</td></tr>");
                sb.AppendLine("  </tbody></table>");

                // Compliance checks against multiple security standards (PCI DSS, ACSC ISM, CIS Benchmark).
                sb.AppendLine("  <h3 style=\"margin:20px 0 8px\">Compliance Check</h3>");
                sb.AppendLine("  <table class=\"stats\"><thead><tr><th>Standard</th><th>Requirement</th><th>Value</th><th>Result</th></tr></thead><tbody>");
                string[] pcStd = { "PCI DSS 3.2.1", "PCI DSS 3.2.1", "PCI DSS 3.2.1", "PCI DSS 3.2.1", "PCI DSS 3.2.1", "PCI DSS 3.2.1", "PCI DSS 4.0", "PCI DSS 4.0", "PCI DSS 4.0", "PCI DSS 4.0", "PCI DSS 4.0", "ACSC ISM", "ACSC ISM", "ACSC ISM", "CIS Benchmark", "CIS Benchmark", "CIS Benchmark", "CIS Benchmark", "CIS Benchmark", "CIS Benchmark", "CIS Benchmark", "CIS Benchmark" };
                string[] pcReq = { "History >= 4", "Max Age <= 90", "Min Length >= 7", "Complexity Required", "Lockout Duration >= 1 & <= 30", "Lockout Threshold <= 6", "History >= 4", "Max Age <= 90", "Min Length >= 12", "Complexity Required", "Lockout Threshold <= 10", "Max Age <= 365", "Min Length >= 14", "Lockout Threshold <= 5", "History >= 24", "Max Age <= 365", "Min Length >= 14", "Complexity Required", "Reversible = False", "Lockout Duration >= 1 & <= 15", "Lockout Threshold <= 5", "Lockout Reset >= 15" };
                string[] pcVal = { historyLen.ToString(), maxAge.ToString(), minLen.ToString(), complexity.ToString(), lockoutDur.ToString(), lockoutThresh.ToString(), historyLen.ToString(), maxAge.ToString(), minLen.ToString(), complexity.ToString(), lockoutThresh.ToString(), maxAge.ToString(), minLen.ToString(), lockoutThresh.ToString(), historyLen.ToString(), maxAge.ToString(), minLen.ToString(), complexity.ToString(), reversible.ToString(), lockoutDur.ToString(), lockoutThresh.ToString(), lockoutReset.ToString() };
                bool[] pcPass = { historyLen >= 4, maxAge > 0 && maxAge <= 90, minLen >= 7, complexity, lockoutDur >= 1 && lockoutDur <= 30, lockoutThresh > 0 && lockoutThresh <= 6, historyLen >= 4, maxAge > 0 && maxAge <= 90, minLen >= 12, complexity, lockoutThresh > 0 && lockoutThresh <= 10, maxAge > 0 && maxAge <= 365, minLen >= 14, lockoutThresh > 0 && lockoutThresh <= 5, historyLen >= 24, maxAge > 0 && maxAge <= 365, minLen >= 14, complexity, !reversible, lockoutDur >= 1 && lockoutDur <= 15, lockoutThresh > 0 && lockoutThresh <= 5, lockoutReset >= 15 };
                for (int i = 0; i < pcStd.Length; i++)
                {
                    string cls = pcPass[i] ? "pass\" " : "fail\" ";
                    string icon = pcPass[i] ? "&#10003;" : "&#10007;";
                    sb.AppendLine("    <tr><td>" + pcStd[i] + "</td><td>" + pcReq[i] + "</td><td class=\"num\">" + pcVal[i] + "</td><td class=\"" + cls + ">" + icon + "</td></tr>");
                }
                sb.AppendLine("  </tbody></table>");
            }
            else
            {
                sb.AppendLine("  <p>No Default Password Policy data available.</p>");
            }
            sb.AppendLine("</div>");

            // ========== Raw Data Sheets (All CSV via DataTable) ==========
            foreach (var s in sheets)
            {
                sb.AppendLine("<div id=\"sheet-" + s.Id + "\" class=\"sheet\">");
                sb.AppendLine("  <h2>" + H(s.Name) + " (" + s.Rows.Count + " records)</h2>");
                sb.AppendLine("  <table id=\"tbl-" + s.Id + "\" class=\"display\" style=\"width:100%\"><thead><tr>");
                foreach (var h in s.Headers)
                    sb.Append("<th>" + H(h) + "</th>");
                sb.AppendLine("</tr></thead><tbody>");
                foreach (var row in s.Rows)
                {
                    sb.Append("<tr>");
                    foreach (var cell in row)
                        sb.Append("<td>" + H(cell) + "</td>");
                    sb.AppendLine("</tr>");
                }
                sb.AppendLine("</tbody></table>");
                sb.AppendLine("</div>");
            }

            sb.AppendLine("</div>");
            sb.AppendLine("</div>");

            // ========== JavaScript Libraries ==========
            if (jqueryJs.Length > 0)
            {
                sb.AppendLine("<script>");
                sb.AppendLine(dtJs);
                sb.AppendLine("</script>");
            }

            if (chartJs.Length > 0)
            {
                sb.AppendLine("<script>");
                sb.AppendLine(chartJs);
                sb.AppendLine("</script>");
            }
            // ========== JavaScript: Pivot, Slicer, Charts ==========
            sb.AppendLine("<script>");

            // Global variables: chart render state, chart configs, pivot data, slicer state.
            sb.AppendLine("var chartsRendered={};");
            sb.AppendLine("var chartConfigs={};");

            sb.AppendLine("var pivotData={};");
            sb.AppendLine("var activeSlicers={};");

            // Create pivot table: generate slicer buttons and table structure.
            sb.AppendLine("function createPivot(containerId,data,opts){");
            sb.AppendLine("  var c=document.getElementById(containerId);");
            sb.AppendLine("  if(!c)return;");
            sb.AppendLine("  var html='<div class=\"slicer-panel\" id=\"slicer-'+containerId+'\">';");
            sb.AppendLine("  var groups={};");
            sb.AppendLine("  data.forEach(function(r){var k=r[opts.rowField];if(!groups[k])groups[k]=0;groups[k]++;});");
            sb.AppendLine("  html+='<button class=\"slicer-btn active\" onclick=\"filterPivot(\\''+containerId+'\\',\\'all\\')\">All<span class=\"count\">'+data.length+'</span></button>';");
            sb.AppendLine("  Object.keys(groups).sort().forEach(function(k){");
            sb.AppendLine("    html+='<button class=\"slicer-btn\" onclick=\"filterPivot(\\''+containerId+'\\',\\''+k.replace(/'/g,\"\\\\'\")+'\\')\">'+k+'<span class=\"count\">'+groups[k]+'</span></button>';");
            sb.AppendLine("  });");
            sb.AppendLine("  html+='</div>';");
            sb.AppendLine("  html+='<table class=\"pivot-table\"><thead><tr>';");
            sb.AppendLine("  opts.valueFields.forEach(function(f){html+='<th>'+f+'</th>';});");
            sb.AppendLine("  html+='</tr></thead><tbody id=\"tbody-'+containerId+'\"></tbody></table>';");
            sb.AppendLine("  c.innerHTML=html;");
            sb.AppendLine("  pivotData[containerId]={data:data,opts:opts};");
            sb.AppendLine("  activeSlicers[containerId]='all';");
            sb.AppendLine("  renderPivotTable(containerId);");
            sb.AppendLine("}");

            // Render pivot table: group, aggregate, and generate table rows based on slicer filter criteria.
            sb.AppendLine("function renderPivotTable(containerId){");
            sb.AppendLine("  var pd=pivotData[containerId];");
            sb.AppendLine("  var filtered=activeSlicers[containerId]==='all'?pd.data:pd.data.filter(function(r){return r[pd.opts.rowField]===activeSlicers[containerId];});");
            sb.AppendLine("  var groups={};");
            sb.AppendLine("  filtered.forEach(function(r){");
            sb.AppendLine("    var k=r[pd.opts.rowField];");
            sb.AppendLine("    if(!groups[k])groups[k]={};");
            sb.AppendLine("    pd.opts.valueFields.forEach(function(f){");
            sb.AppendLine("      if(!groups[k][f])groups[k][f]=0;");
            sb.AppendLine("      var v=parseFloat(r[f]);");
            sb.AppendLine("      if(!isNaN(v))groups[k][f]+=v;");
            sb.AppendLine("    });");
            sb.AppendLine("  });");
            sb.AppendLine("  var tbody=document.getElementById('tbody-'+containerId);");
            sb.AppendLine("  var html='';");
            sb.AppendLine("  var totals={};");
            sb.AppendLine("  pd.opts.valueFields.forEach(function(f){totals[f]=0;});");
            sb.AppendLine("  Object.keys(groups).sort().forEach(function(k){");
            sb.AppendLine("    html+='<tr><td><b>'+k+'</b></td>';");
            sb.AppendLine("    pd.opts.valueFields.forEach(function(f){");
            sb.AppendLine("      var v=groups[k][f]||0;");
            sb.AppendLine("      totals[f]+=v;");
            sb.AppendLine("      html+='<td class=\"num\">'+v+'</td>';");
            sb.AppendLine("    });");
            sb.AppendLine("    html+='</tr>';");
            sb.AppendLine("  });");
            sb.AppendLine("  html+='<tr class=\"total\"><td><b>Total</b></td>';");
            sb.AppendLine("  pd.opts.valueFields.forEach(function(f){html+='<td class=\"num\"><b>'+totals[f]+'</b></td>';});");
            sb.AppendLine("  html+='</tr>';");
            sb.AppendLine("  tbody.innerHTML=html;");
            sb.AppendLine("}");

            // Slicer filter function: update active slicer and re-render pivot table.
            sb.AppendLine("function filterPivot(containerId,value){");
            sb.AppendLine("  activeSlicers[containerId]=value;");
            sb.AppendLine("  var panel=document.getElementById('slicer-'+containerId);");
            sb.AppendLine("  if(panel){");
            sb.AppendLine("    panel.querySelectorAll('.slicer-btn').forEach(function(btn){");
            sb.AppendLine("      btn.classList.remove('active');");
            sb.AppendLine("    });");
            sb.AppendLine("    var btns=panel.querySelectorAll('.slicer-btn');");
            sb.AppendLine("    btns.forEach(function(btn){");
            sb.AppendLine("      if((value==='all'&&btn.textContent.indexOf('All')===0)||btn.textContent.indexOf(value)===0)btn.classList.add('active');");
            sb.AppendLine("    });");
            sb.AppendLine("  }");
            sb.AppendLine("  renderPivotTable(containerId);");
            sb.AppendLine("}");

            // Page navigation function: switch visible sheets and lazy-load charts.
            sb.AppendLine("function showSheet(id){");
            sb.AppendLine("  document.querySelectorAll('.sheet').forEach(function(s){s.classList.remove('active')});");
            sb.AppendLine("  document.getElementById('sheet-'+id).classList.add('active');");
            sb.AppendLine("  document.querySelectorAll('.sidebar a').forEach(function(a){a.classList.remove('active')});");
            sb.AppendLine("  event.target.closest('a').classList.add('active');");
            sb.AppendLine("  if(chartConfigs[id] && !chartsRendered[id]){");
            sb.AppendLine("    chartConfigs[id].forEach(function(cfg){new Chart(document.getElementById(cfg.id),{type:cfg.type,data:cfg.data,options:cfg.options||{}})});");
            sb.AppendLine("    chartsRendered[id]=true;");
            sb.AppendLine("  }");
            sb.AppendLine("}");

            // Initialize all DataTable instances (pagination, sorting, export buttons).
            sb.AppendLine("$(document).ready(function(){");
            foreach (var s in sheets)
                sb.AppendLine("  $('#tbl-" + s.Id + "').DataTable({pageLength:25,order:[],dom:'Bfrtip',buttons:['copy','csv','excel','pdf','print']});");
            sb.AppendLine("});");

            // ========== Chart Configs: Lazy Render with Chart.js ==========
            sb.AppendLine("chartConfigs['summary']=[");
            sb.AppendLine("  {id:'chart-users',type:'pie',data:{labels:['Enabled','Disabled'],datasets:[{data:[" + usersEnabled + "," + usersDisabled + "],backgroundColor:['#2e7d32','#c62828']}]}}");
            sb.AppendLine("  ,{id:'chart-comps',type:'pie',data:{labels:['Enabled','Disabled'],datasets:[{data:[" + compsEnabled + "," + compsDisabled + "],backgroundColor:['#2e7d32','#c62828']}]}}");

            if (osCounts.Count > 0)
            {
                var osLabels = string.Join(",", osCounts.Keys.Select(k => "'" + H(k).Replace("'", "\\'") + "'"));
                var osValues = string.Join(",", osCounts.Values);
                sb.AppendLine("  ,{id:'chart-os',type:'bar',data:{labels:[" + osLabels + "],datasets:[{label:'Count',data:[" + osValues + "],backgroundColor:'#42a5f5'}]},options:{indexAxis:'y',plugins:{legend:{display:false}}}}");
            }

            if (spnCounts.Count > 0)
            {
                var spnLabels = string.Join(",", spnCounts.Keys.Select(k => "'" + H(k).Replace("'", "\\'") + "'"));
                var spnValues = string.Join(",", spnCounts.Values);
                sb.AppendLine("  ,{id:'chart-spn',type:'bar',data:{labels:[" + spnLabels + "],datasets:[{label:'Count',data:[" + spnValues + "],backgroundColor:'#66bb6a'}]},options:{plugins:{legend:{display:false}}}}");
            }

            if (groupMemberCounts.Count > 0)
            {
                var topGroups = groupMemberCounts.OrderByDescending(kv => kv.Value).Take(15).ToList();
                var gLabels = string.Join(",", topGroups.Select(kv => "'" + H(kv.Key).Replace("'", "\\'") + "'"));
                var gValues = string.Join(",", topGroups.Select(kv => kv.Value));
                sb.AppendLine("  ,{id:'chart-groups',type:'bar',data:{labels:[" + gLabels + "],datasets:[{label:'Members',data:[" + gValues + "],backgroundColor:'#7e57c2'}]},options:{indexAxis:'y',plugins:{legend:{display:false}}}}");
            }
            sb.AppendLine("];");

            {
                string[] uNames = { "Must Change Pwd", "Cannot Change Pwd", "Pwd Never Expires", "Reversible Enc", "Smartcard Req", "Delegation", "Kerb DES", "Kerb RC4", "No Pre-Auth", "Locked Out", "Dormant", "Pwd Not Req", "Unconstrained", "SID History" };
                int[] uVals = { uMustChange, uCannotChange, uPwdNeverExpires, uReversible, uSmartcard, uDelegation, uKerbDES, uKerbRC4, uNoPreAuth, uLocked, uDormant, uPwdNotRequired, uUnconstrained, uSIDHistory };
                var filtered = uNames.Zip(uVals, (n, v) => new { n, v }).Where(x => x.v > 0).ToList();
                if (filtered.Count > 0)
                {
                    string labels = string.Join(",", filtered.Select(x => "'" + x.n + "'"));
                    string values = string.Join(",", filtered.Select(x => x.v));
                    sb.AppendLine("chartConfigs['user-stats']=[{id:'chart-user-attrs',type:'bar',data:{labels:[" + labels + "],datasets:[{label:'Count',data:[" + values + "],backgroundColor:'#ef5350'}]},options:{indexAxis:'y',plugins:{legend:{display:false}}}}];");
                }
            }

            sb.AppendLine("chartConfigs['comp-stats']=[");
            sb.AppendLine("  {id:'chart-comp-pie',type:'pie',data:{labels:['Enabled','Disabled'],datasets:[{data:[" + compsEnabled + "," + compsDisabled + "],backgroundColor:['#2e7d32','#c62828']}]}}");
            {
                string[] cNames = { "Unconstrained", "Constrained", "SID History", "Dormant" };
                int[] cVals = { cUnconstrained, cConstrained, cSIDHistory, cDormant };
                var filtered = cNames.Zip(cVals, (n, v) => new { n, v }).Where(x => x.v > 0).ToList();
                if (filtered.Count > 0)
                {
                    string labels = string.Join(",", filtered.Select(x => "'" + x.n + "'"));
                    string values = string.Join(",", filtered.Select(x => x.v));
                    sb.AppendLine("  ,{id:'chart-comp-attrs',type:'bar',data:{labels:[" + labels + "],datasets:[{label:'Count',data:[" + values + "],backgroundColor:'#ff9800'}]},options:{indexAxis:'y',plugins:{legend:{display:false}}}}");
                }
            }
            sb.AppendLine("];");

            if (spnCounts.Count > 0)
            {
                var sorted = spnCounts.OrderByDescending(kv => kv.Value).ToList();
                string labels = string.Join(",", sorted.Select(kv => "'" + H(kv.Key).Replace("'", "\\'") + "'"));
                string values = string.Join(",", sorted.Select(kv => kv.Value));
                sb.AppendLine("chartConfigs['comp-role-stats']=[{id:'chart-comp-roles',type:'bar',data:{labels:[" + labels + "],datasets:[{label:'Count',data:[" + values + "],backgroundColor:'#42a5f5'}]},options:{indexAxis:'y',plugins:{legend:{display:false}}}}];");
            }

            if (osCounts.Count > 0)
            {
                var sorted = osCounts.OrderByDescending(kv => kv.Value).ToList();
                string labels = string.Join(",", sorted.Select(kv => "'" + H(kv.Key).Replace("'", "\\'") + "'"));
                string values = string.Join(",", sorted.Select(kv => kv.Value));
                sb.AppendLine("chartConfigs['os-stats']=[{id:'chart-os-hbar',type:'bar',data:{labels:[" + labels + "],datasets:[{label:'Count',data:[" + values + "],backgroundColor:'#26a69a'}]},options:{indexAxis:'y',plugins:{legend:{display:false}}}}];");
            }

            if (privGroupCounts.Count > 0)
            {
                var sorted = privGroupCounts.OrderByDescending(kv => kv.Value).ToList();
                string labels = string.Join(",", sorted.Select(kv => "'" + H(kv.Key).Replace("'", "\\'") + "'"));
                string values = string.Join(",", sorted.Select(kv => kv.Value));
                sb.AppendLine("chartConfigs['priv-group-stats']=[{id:'chart-priv-groups',type:'bar',data:{labels:[" + labels + "],datasets:[{label:'Members',data:[" + values + "],backgroundColor:'#ab47bc'}]},options:{indexAxis:'y',plugins:{legend:{display:false}}}}];");
            }

            // Render dashboard summary charts immediately on page load.
            sb.AppendLine("$(document).ready(function(){if(chartConfigs['summary']){chartConfigs['summary'].forEach(function(cfg){new Chart(document.getElementById(cfg.id),{type:cfg.type,data:cfg.data,options:cfg.options||{}})});chartsRendered['summary']=true;}});");

            sb.AppendLine("</script>");
            sb.AppendLine("</body></html>");
            return sb.ToString();
        }
    }
}
