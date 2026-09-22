using System;
using System.Collections.Generic;

// AdReconConfig.cs - 命令行参数解析与运行时配置
// This file defines the configuration model and command-line parser for AdRecon.NET.
// AdReconConfig holds all runtime settings; CommandLine.Parse converts argv into an AdReconConfig instance.

namespace AdRecon.Core
{
    /// <summary>Resolved runtime configuration for a recon run.
    /// Mirrors the ADRecon.ps1 parameter block.</summary>
    public sealed class AdReconConfig
    {
        // Connection settings
        public ReconMethod Method = ReconMethod.LDAP;
        public string Domain = "";
        public string DomainController = "";
        public string CredentialUsername = "";
        public string CredentialPassword = "";

        // -GenExcel <dir> regenerates only the Excel report from existing CSV output.
        public string GenExcelDir = "";

        // Output and collection settings
        public string OutputDir = "";
        public Modules Collect = ModuleDefaults.DefaultSet;
        public OutputTypeFlag OutputType = OutputTypeFlag.None;
        public bool CollectExplicit = false;
        public bool OutputTypeExplicit = false;

        // Tuning parameters
        public int DormantTimeSpan = 90;   // days threshold for dormant accounts
        public int PassMaxAge = 30;         // password age threshold
        public bool PassMaxAgeSet = false;
        public int PageSize = 200;         // LDAP page size
        public int Threads = 10;           // parallel threads
        public bool OnlyEnabled = false;   // only include enabled accounts

        // Flags
        public bool Log = false;
        public bool Help = false;
        public bool GenReport = true;
        public bool NoConhost = false;
        public string Logo = "ADRecon";

        public static readonly string Version = "v1.27";

        // Normalisation mirroring Invoke-ADRecon.
        public void Normalize()
        {
            // Default -Collect handled at construction. Default -OutputType: STDOUT when
            // -Collect was given explicitly, else CSV+Excel (ADRecon behaviour).
            if (!OutputTypeExplicit)
            {
                if (CollectExplicit)
                    OutputType = OutputTypeFlag.STDOUT;
                else
                    OutputType = OutputTypeFlag.CSV | OutputTypeFlag.Excel;
            }

            // Excel consumes CSV files, so force CSV when Excel is chosen without it.
            if ((OutputType & OutputTypeFlag.Excel) != 0 && (OutputType & OutputTypeFlag.CSV) == 0)
                OutputType |= OutputTypeFlag.CSV;
        }
    }

    // CommandLine - 命令行参数解析器
    // Parses command-line arguments into an AdReconConfig object.
    // Supports both "/X value" and "-X value" syntax, plus boolean switches.
    public static class CommandLine
    {
        /// <summary>Parses argv into an AdReconConfig. Supports both "/X value" and "-X value"
        /// and boolean switches ("-Log", "-OnlyEnabled").</summary>
        public static AdReconConfig Parse(string[] args)
        {
            AdReconConfig c = new AdReconConfig();
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // First pass: build a name->value map from all arguments
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (a.Length < 2) continue;
                char lead = a[0];
                if (lead != '/' && lead != '-') continue;
                string name = a.Substring(1).TrimStart('-');
                string value = "";
                int eq = name.IndexOf('=');
                if (eq >= 0)
                {
                    value = name.Substring(eq + 1);
                    name = name.Substring(0, eq);
                }
                else if (i + 1 < args.Length && !(args[i + 1].StartsWith("/") || args[i + 1].StartsWith("-")))
                {
                    value = args[++i];
                }
                if (name.Length > 0) map[name.ToLowerInvariant()] = value;
            }

            // Second pass: map dictionary entries to AdReconConfig properties
            string s;

            // Connection settings
            if (map.TryGetValue("method", out s))
            {
                if (s.Equals("ADWS", StringComparison.OrdinalIgnoreCase)) c.Method = ReconMethod.ADWS;
                else c.Method = ReconMethod.LDAP;
            }
            if (map.TryGetValue("domain", out s) && s.Length > 0) c.Domain = s.Trim();
            if (map.TryGetValue("domaincontroller", out s)) c.DomainController = s;
            if (map.TryGetValue("dc", out s) && c.DomainController.Length == 0) c.DomainController = s;

            // Credentials
            if (map.TryGetValue("credential", out s) && s.Length > 0) ParseCredential(s, c);
            if (map.TryGetValue("username", out s) && s.Length > 0) c.CredentialUsername = s;
            if (map.TryGetValue("password", out s) && s.Length > 0) c.CredentialPassword = s;

            // Output paths
            if (map.TryGetValue("genexcel", out s)) c.GenExcelDir = s;
            if (map.TryGetValue("outputdir", out s)) c.OutputDir = s;

            // Collection modules
            c.CollectExplicit = map.ContainsKey("collect");
            if (c.CollectExplicit && map.TryGetValue("collect", out s) && s.Length > 0)
                c.Collect = ParseCollect(s);
            else if (c.CollectExplicit)
                c.Collect = ModuleDefaults.DefaultSet;

            // Output type flags
            c.OutputTypeExplicit = map.ContainsKey("outputtype");
            if (c.OutputTypeExplicit && map.TryGetValue("outputtype", out s) && s.Length > 0)
                c.OutputType = ParseOutputType(s);
            else if (map.ContainsKey("stdout"))
                c.OutputType |= OutputTypeFlag.STDOUT;

            // Tuning parameters
            if (map.TryGetValue("dormanttimespan", out s)) { int v; if (int.TryParse(s, out v)) c.DormantTimeSpan = v; }
            if (map.TryGetValue("passmaxage", out s)) { int v; if (int.TryParse(s, out v)) { c.PassMaxAge = v; c.PassMaxAgeSet = true; } }
            if (map.TryGetValue("pagesize", out s)) { int v; if (int.TryParse(s, out v)) c.PageSize = v; }
            if (map.TryGetValue("threads", out s)) { int v; if (int.TryParse(s, out v)) c.Threads = v; }
            if (map.TryGetValue("logo", out s) && s.Length > 0) c.Logo = s;

            // Boolean switches
            c.OnlyEnabled = map.ContainsKey("onlyenabled");
            c.Log = map.ContainsKey("log");
            c.NoConhost = map.ContainsKey("noconhost");

            if (map.TryGetValue("genreport", out s))
            {
                bool v = true;
                if (bool.TryParse(s, out v)) c.GenReport = v;
            }

            c.Help = map.ContainsKey("h") || map.ContainsKey("help") || map.ContainsKey("?");

            // Apply default normalisation rules
            c.Normalize();
            return c;
        }

        // Parses a credential string like "domain\user:password" or "user@domain:password"
        private static void ParseCredential(string value, AdReconConfig c)
        {
            // Accept "domain\user:password", "user@domain:password", or "username".
            string userPart = value, passPart = "";
            int colon = value.IndexOf(':');
            if (colon >= 0)
            {
                userPart = value.Substring(0, colon);
                passPart = value.Substring(colon + 1);
            }
            c.CredentialUsername = userPart;
            c.CredentialPassword = passPart;
        }

        // Parses a comma/semicolon-separated list of module names into a Modules bitmask
        public static Modules ParseCollect(string value)
        {
            Modules m = Modules.None;
            string[] parts = value.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string raw in parts)
            {
                string name = raw.Trim();
                if (name.Length == 0) continue;
                if (name.Equals("Default", StringComparison.OrdinalIgnoreCase)) { m |= ModuleDefaults.DefaultSet; continue; }
                if (name.Equals("All", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (object e in Enum.GetValues(typeof(Modules)))
                    {
                        int v = (int)e;
                        if (v > 0) m |= (Modules)e;
                    }
                    continue;
                }
                foreach (object e in Enum.GetValues(typeof(Modules)))
                {
                    if (((Modules)e).ToString().Equals(name, StringComparison.OrdinalIgnoreCase))
                    {
                        m |= (Modules)e;
                        break;
                    }
                }
            }
            if (m == Modules.None) m = ModuleDefaults.DefaultSet;
            return m;
        }

        // Parses a comma/semicolon-separated list of output types into a flag bitmask
        public static OutputTypeFlag ParseOutputType(string value)
        {
            OutputTypeFlag t = OutputTypeFlag.None;
            string[] parts = value.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string raw in parts)
            {
                string name = raw.Trim();
                if (name.Length == 0) continue;
                if (name.Equals("All", StringComparison.OrdinalIgnoreCase))
                {
                    t |= OutputTypeFlag.CSV | OutputTypeFlag.XML | OutputTypeFlag.JSON |
                         OutputTypeFlag.HTML | OutputTypeFlag.Excel;
                    continue;
                }
                OutputTypeFlag f;
                if (Enum.TryParse(name, true, out f))
                {
                    if (f == OutputTypeFlag.None) continue;
                    t |= f;
                }
            }
            return t;
        }
    }
}
