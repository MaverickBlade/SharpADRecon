// OrgModules.cs - 组织结构模块集合
// 包含OUsModule、GPOsModule、GPOReportModule、GPLinksModule和PrintersModule类。
// 提供组织单元、组策略对象和打印机的收集功能。

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using AdRecon.Ad;
using AdRecon.Core;

namespace AdRecon.Modules
{
    /// <summary>Mirror of Get-ADROU (LDAP path, OURecordProcessor).</summary>
    public sealed class OUsModule : IReconModule
    {
        public string Name { get { return "OUs"; } }

        // Run方法 - 收集组织单元信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Name", "Depth", "Description", "whenCreated", "whenChanged", "DistinguishedName");
            try
            {
                // 执行LDAP搜索
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(objectclass=organizationalunit)",
                    new[] { "distinguishedname", "description", "name", "whencreated", "whenchanged" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    // 添加行数据
                    AdRow row = Col.Row(cols);
                    row.Set("Name", AdSession.GetString(r, "name"));
                    row.Set("Depth", OU_DEPTH(r));
                    row.Set("Description", AdAttrs.CleanString(AdSession.GetValue(r, "description")));
                    row.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
                    row.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(r, "whenchanged")));
                    row.Set("DistinguishedName", AdSession.GetString(r, "distinguishedname"));
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADROU] Error while enumerating OU Objects");
                Log.Exception("Get-ADROU", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("OUs", cols, rows)) : null;
        }

        // OU_DEPTH - 计算OU的深度
        private static int OU_DEPTH(SearchResult r)
        {
            string dn = AdSession.GetString(r, "distinguishedname");
            return dn.Split(new[] { "OU=" }, StringSplitOptions.None).Length - 1;
        }
    }

    /// <summary>Mirror of Get-ADRGPO (LDAP path, GPORecordProcessor).</summary>
    public sealed class GPOsModule : IReconModule
    {
        public string Name { get { return "GPOs"; } }

        // Run方法 - 收集组策略对象信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("DisplayName", "GUID", "whenCreated", "whenChanged", "DistinguishedName", "FilePath");
            try
            {
                // 执行LDAP搜索
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(objectCategory=groupPolicyContainer)",
                    new[] { "displayname", "name", "whencreated", "whenchanged", "distinguishedname", "gpcfilesyspath" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    // 添加行数据
                    AdRow row = Col.Row(cols);
                    row.Set("DisplayName", AdAttrs.CleanString(AdSession.GetValue(r, "displayname")));
                    row.Set("GUID", AdAttrs.CleanString(AdSession.GetValue(r, "name")));
                    row.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
                    row.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(r, "whenchanged")));
                    row.Set("DistinguishedName", AdAttrs.CleanString(AdSession.GetValue(r, "distinguishedname")));
                    row.Set("FilePath", AdSession.GetString(r, "gpcfilesyspath"));
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRGPO] Error while enumerating groupPolicyContainer Objects");
                Log.Exception("Get-ADRGPO", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("GPOs", cols, rows)) : null;
        }
    }

    /// <summary>Mirror of Get-ADRGPOReport. Comprehensive GPO report with status, version,
    /// extensions, and linked locations. Does not require RSAT/GroupPolicy module.</summary>
    public sealed class GPOReportModule : IReconModule
    {
        public string Name { get { return "GPOReport"; } }

        // Run方法 - 收集组策略报告信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("DisplayName", "GUID", "Description", "whenCreated", "whenChanged",
                "Computer Version", "User Version", "Status", "FilePath", "Machine Extensions",
                "User Extensions", "Linked To");

            try
            {
                // 步骤1: 构建GPO DN→链接信息字典
                var linkDict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                SearchSomsForLinks(ctx, linkDict);

                // 步骤2: 查询所有GPO及其完整属性
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(objectCategory=groupPolicyContainer)",
                    new[] { "displayname", "name", "description", "whencreated", "whenchanged",
                            "versionnumber", "flags", "gpcfilesyspath",
                            "gpcmachineextensionnames", "gpcuserextensionnames",
                            "distinguishedname" },
                    SearchScope.Subtree, ctx.Config.PageSize);

                foreach (SearchResult r in results)
                {
                    AdRow row = Col.Row(cols);
                    string dn = AdSession.GetString(r, "distinguishedname");

                    // 设置基本信息
                    row.Set("DisplayName", AdAttrs.CleanString(AdSession.GetValue(r, "displayname")));
                    row.Set("GUID", AdAttrs.CleanString(AdSession.GetValue(r, "name")));
                    row.Set("Description", AdAttrs.CleanString(AdSession.GetValue(r, "description")));
                    row.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
                    row.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(r, "whenchanged")));

                    // 解析版本号：高位=计算机版本，低位=用户版本
                    int versionNum = 0;
                    int.TryParse(AdSession.GetString(r, "versionnumber"), out versionNum);
                    int compVer = versionNum >> 16;
                    int userVer = versionNum & 0xFFFF;
                    row.Set("Computer Version", compVer.ToString());
                    row.Set("User Version", userVer.ToString());

                    // 解析标志：0=全部启用，1=用户禁用，2=计算机禁用，3=全部禁用
                    int flags = 0;
                    int.TryParse(AdSession.GetString(r, "flags"), out flags);
                    string status;
                    switch (flags)
                    {
                        case 1: status = "User Disabled"; break;
                        case 2: status = "Computer Disabled"; break;
                        case 3: status = "All Disabled"; break;
                        default: status = "All Enabled"; break;
                    }
                    row.Set("Status", status);
                    row.Set("FilePath", AdSession.GetString(r, "gpcfilesyspath"));
                    row.Set("Machine Extensions", AdSession.GetString(r, "gpcmachineextensionnames"));
                    row.Set("User Extensions", AdSession.GetString(r, "gpcuserextensionnames"));

                    // 解析链接位置
                    string linkedTo = "";
                    if (dn.Length > 0 && linkDict.TryGetValue(dn, out linkedTo))
                        row.Set("Linked To", linkedTo);
                    else
                        row.Set("Linked To", "Not Linked");

                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRGPOReport] Error while enumerating GPO Report");
                Log.Exception("Get-ADRGPOReport", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("GPOReport", cols, rows)) : null;
        }

        // SearchSomsForLinks - 搜索SOM以获取链接信息
        private static void SearchSomsForLinks(ModuleContext ctx, Dictionary<string, string> linkDict)
        {
            // 搜索域和OU的gPLink属性
            var soms = new List<SearchResult>();
            try
            {
                var somSearch = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(|(objectclass=domain)(objectclass=organizationalUnit))",
                    new[] { "distinguishedname", "name", "gplink" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult s in somSearch) soms.Add(s);
            }
            catch { }

            // 搜索站点
            try
            {
                string sitesBase = "CN=Sites," + ctx.Session.ConfigurationNamingContext;
                var siteSearch = ctx.Session.Search(sitesBase, "(objectclass=site)",
                    new[] { "distinguishedname", "name", "gplink" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult s in siteSearch) soms.Add(s);
            }
            catch { }

            // 解析gPLink字符串以构建GPO DN→链接位置映射
            foreach (SearchResult som in soms)
            {
                string gPLink = AdSession.GetString(som, "gplink");
                if (gPLink.Length == 0) continue;
                string somName = AdAttrs.CleanString(AdSession.GetValue(som, "name"));

                // gPLink格式: [LDAP://CN={guid},CN=Policies,CN=System,DC=...;0]
                int pos = 0;
                while (pos < gPLink.Length)
                {
                    int start = gPLink.IndexOf("[LDAP://", pos, StringComparison.OrdinalIgnoreCase);
                    if (start < 0) break;
                    int end = gPLink.IndexOf("]", start);
                    if (end < 0) break;
                    string entry = gPLink.Substring(start + 1, end - start - 1);
                    pos = end + 1;

                    // 从DN中提取GUID
                    int cnStart = entry.IndexOf("CN={", StringComparison.OrdinalIgnoreCase);
                    if (cnStart < 0) continue;
                    int cnEnd = entry.IndexOf("}", cnStart);
                    if (cnEnd < 0) continue;
                    string guid = entry.Substring(cnStart + 4, cnEnd - cnStart - 4).ToUpper();

                    // 从LDAP路径构建GPO DN
                    string gpoDn = entry.Substring(entry.IndexOf(",CN=Policies", StringComparison.OrdinalIgnoreCase));
                    gpoDn = "CN={" + guid + "}" + gpoDn;

                    // 添加到链接位置
                    string existing;
                    if (linkDict.TryGetValue(gpoDn, out existing))
                        linkDict[gpoDn] = existing + "; " + somName;
                    else
                        linkDict[gpoDn] = somName;
                }
            }
        }
    }

    /// <summary>Mirror of Get-ADRGPLink (LDAP path, SOMRecordProcessor).  Three-stage: build
    /// GPO DN→DisplayName dictionary, then search domain/OUs and sites for gPLinks, and parse
    /// the link string to resolve link order / enforced / enabled status.</summary>
    public sealed class GPLinksModule : IReconModule
    {
        public string Name { get { return "GPLinks"; } }

        // Run方法 - 收集组策略链接信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Name", "Depth", "DistinguishedName", "Link Order", "GPO", "Enforced",
                "Link Enabled", "BlockInheritance", "gPLink", "gPOptions");
            try
            {
                // 步骤1: 构建GPO字典（DN→DisplayName）
                var gpoDict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                var gpos = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(objectCategory=groupPolicyContainer)",
                    new[] { "displayname", "distinguishedname" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult g in gpos)
                {
                    string dn = AdSession.GetString(g, "distinguishedname").ToUpper();
                    string name = AdAttrs.CleanString(AdSession.GetValue(g, "displayname"));
                    if (dn.Length > 0 && name.Length > 0 && !gpoDict.ContainsKey(dn))
                        gpoDict[dn] = name;
                }

                // 步骤2: 搜索域和OU的gPLink
                var soms = new List<SearchResult>();
                var somSearch = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(|(objectclass=domain)(objectclass=organizationalUnit))",
                    new[] { "distinguishedname", "name", "gplink", "gpoptions" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult s in somSearch) soms.Add(s);

                // 步骤3: 搜索站点
                string sitesBase = "CN=Sites," + ctx.Session.ConfigurationNamingContext;
                try
                {
                    var siteSearch = ctx.Session.Search(sitesBase, "(objectclass=site)",
                        new[] { "distinguishedname", "name", "gplink", "gpoptions" },
                        SearchScope.Subtree, ctx.Config.PageSize);
                    foreach (SearchResult s in siteSearch) soms.Add(s);
                }
                catch { }

                // 处理每个SOM
                foreach (SearchResult som in soms)
                {
                    string gPLink = AdSession.GetString(som, "gplink");
                    int depth = AdSession.GetString(som, "distinguishedname")
                        .Split(new[] { "OU=" }, StringSplitOptions.None).Length - 1;
                    bool blockInheritance = false;
                    int gpOptions;
                    if (int.TryParse(AdSession.GetString(som, "gpoptions"), out gpOptions))
                        blockInheritance = (gpOptions == 1);

                    // 解析gPLink
                    string[] links = ParseGPLinks(gPLink);
                    int order = links.Length;
                    if (order == 0)
                    {
                        // 没有链接时添加空行
                        AdRow row = Col.Row(cols);
                        row.Set("Name", AdSession.GetString(som, "name"));
                        row.Set("Depth", depth);
                        row.Set("DistinguishedName", AdSession.GetString(som, "distinguishedname"));
                        row.Set("Link Order", null);
                        row.Set("GPO", null);
                        row.Set("Enforced", null);
                        row.Set("Link Enabled", null);
                        row.Set("BlockInheritance", blockInheritance);
                        row.Set("gPLink", gPLink);
                        row.Set("gPOptions", AdSession.GetString(som, "gpoptions"));
                        rows.Add(row);
                        continue;
                    }

                    // 处理每个链接
                    foreach (string link in links)
                    {
                        string[] parts = link.Split(new[] { '/', ';' });
                        // parts[2] = DN, parts[3] = options字符串
                        int options;
                        if (!int.TryParse(parts.Length > 3 ? parts[3] : "0", out options)) options = 0;
                        bool linkEnabled = (options & 1) == 0;
                        bool enforced = (options & 2) == 2;

                        // 获取GPO名称
                        string gpoName;
                        string dnKey = parts.Length > 2 ? parts[2].ToUpper() : "";
                        if (!gpoDict.TryGetValue(dnKey, out gpoName))
                        {
                            // 回退：从DN中提取CN
                            gpoName = ExtractCN(parts.Length > 2 ? parts[2] : "");
                        }

                        // 添加行数据
                        AdRow row = Col.Row(cols);
                        row.Set("Name", AdSession.GetString(som, "name"));
                        row.Set("Depth", depth);
                        row.Set("DistinguishedName", AdSession.GetString(som, "distinguishedname"));
                        row.Set("Link Order", order);
                        row.Set("GPO", gpoName);
                        row.Set("Enforced", enforced);
                        row.Set("Link Enabled", linkEnabled);
                        row.Set("BlockInheritance", blockInheritance);
                        row.Set("gPLink", gPLink);
                        row.Set("gPOptions", AdSession.GetString(som, "gpoptions"));
                        rows.Add(row);
                        order--;
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRGPLink] Error while enumerating GPLink Objects");
                Log.Exception("Get-ADRGPLink", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("GPLinks", cols, rows)) : null;
        }

        // ParseGPLinks - 解析gPLink字符串
        private static string[] ParseGPLinks(string gPLink)
        {
            if (gPLink == null || gPLink.Length == 0) return new string[0];
            string[] raw = gPLink.Split('[', ']');
            var links = new List<string>();
            for (int i = 0; i < raw.Length; i++)
            {
                if (raw[i].StartsWith("LDAP://") || raw[i].StartsWith("LDAP:"))
                    links.Add(raw[i]);
            }
            return links.ToArray();
        }

        // ExtractCN - 从部分DN中提取CN
        private static string ExtractCN(string part)
        {
            string[] eq = part.Split(new[] { '=', ',' });
            return eq.Length > 1 ? eq[1] : part;
        }
    }

    /// <summary>Mirror of Get-ADRPrinter (LDAP path, PrinterRecordProcessor).</summary>
    public sealed class PrintersModule : IReconModule
    {
        public string Name { get { return "Printers"; } }

        // Run方法 - 收集打印机信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Name", "ServerName", "ShareName", "DriverName", "DriverVersion",
                "PortName", "URL", "whenCreated", "whenChanged");
            try
            {
                // 执行LDAP搜索
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(objectCategory=printQueue)",
                    new[] { "name", "serverName", "printShareName", "driverName",
                            "driverVersion", "portName", "url", "whenCreated", "whenChanged" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    // 添加行数据
                    AdRow row = Col.Row(cols);
                    row.Set("Name", AdSession.GetString(r, "name"));
                    row.Set("ServerName", AdSession.GetString(r, "serverName"));
                    row.Set("ShareName", AdSession.GetString(r, "printShareName"));
                    row.Set("DriverName", AdSession.GetString(r, "driverName"));
                    row.Set("DriverVersion", AdSession.GetString(r, "driverVersion"));
                    row.Set("PortName", AdSession.GetString(r, "portName"));
                    row.Set("URL", AdSession.GetString(r, "url"));
                    row.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
                    row.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(r, "whenchanged")));
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRPrinter] Error while enumerating printQueue Objects");
                Log.Exception("Get-ADRPrinter", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("Printers", cols, rows)) : null;
        }
    }
}