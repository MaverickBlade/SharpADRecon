// MetadataModules.cs - 元数据模块集合
// 包含Col辅助类、TrustsModule、SitesModule、SubnetsModule、SchemaHistoryModule、
// DefaultPasswordPolicyModule、FineGrainedPasswordPolicyModule等模块。
// 提供AD元数据的收集功能。

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using AdRecon.Ad;
using AdRecon.Core;

namespace AdRecon.Modules
{
    // Col - 列和行创建的辅助类
    internal static class Col
    {
        // New - 创建列名列表
        public static List<string> New(params string[] names)
        {
            return new List<string>(names);
        }

        // Row - 创建行对象
        public static AdRow Row(List<string> columns)
        {
            return new AdRow(columns);
        }
    }

    /// <summary>Mirror of Get-ADRTrust (LDAP path).</summary>
    public sealed class TrustsModule : IReconModule
    {
        public string Name { get { return "Trusts"; } }

        // Run方法 - 收集信任关系信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Source Domain", "Target Domain", "Trust Direction", "Trust Type",
                "Attributes", "whenCreated", "whenChanged");
            try
            {
                // 执行LDAP搜索
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext, "(objectClass=trustedDomain)",
                    new[] { "distinguishedname", "trustpartner", "trustdirection", "trusttype",
                            "trustattributes", "whencreated", "whenchanged" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    // 添加行数据
                    AdRow row = Col.Row(cols);
                    row.Set("Source Domain", AdAttrs.DnToFqdn(AdSession.GetString(r, "distinguishedname")));
                    row.Set("Target Domain", AdSession.GetString(r, "trustpartner"));
                    row.Set("Trust Direction", Direction(AdSession.GetString(r, "trustdirection")));
                    row.Set("Trust Type", TypeName(AdSession.GetString(r, "trusttype")));
                    row.Set("Attributes", DecodeAttributes(AdSession.GetString(r, "trustattributes")));
                    row.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
                    row.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(r, "whenchanged")));
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRTrust] Error while enumerating trustedDomain Objects");
                Log.Exception("Get-ADRTrust", ex);
                return null;
            }
            return rows.Count > 0
                ? (List<ModuleResult>)Clr.Of(new ModuleResult("Trusts", cols, rows))
                : null;
        }

        // Direction - 将信任方向数字转换为字符串
        private static string Direction(string v)
        {
            int i;
            if (!int.TryParse(v, out i)) return "";
            switch (i)
            {
                case 0: return "Disabled";
                case 1: return "Inbound";
                case 2: return "Outbound";
                case 3: return "BiDirectional";
                default: return v;
            }
        }

        // TypeName - 将信任类型数字转换为字符串
        private static string TypeName(string v)
        {
            int i;
            if (!int.TryParse(v, out i)) return "";
            switch (i)
            {
                case 1: return "Downlevel";
                case 2: return "Uplevel";
                case 3: return "MIT";
                case 4: return "DCE";
                default: return v;
            }
        }

        // DecodeAttributes - 解码信任属性
        private static string DecodeAttributes(string v)
        {
            int i;
            if (!int.TryParse(v, out i)) return "";
            string s = "";
            if ((i & 0x00000001) != 0) s += "Non Transitive,";
            if ((i & 0x00000002) != 0) s += "UpLevel,";
            if ((i & 0x00000004) != 0) s += "Quarantined,";
            if ((i & 0x00000008) != 0) s += "Forest Transitive,";
            if ((i & 0x00000010) != 0) s += "Cross Organization,";
            if ((i & 0x00000020) != 0) s += "Within Forest,";
            if ((i & 0x00000040) != 0) s += "Treat as External,";
            if ((i & 0x00000080) != 0) s += "Uses RC4 Encryption,";
            if ((i & 0x00000200) != 0) s += "No TGT Delegation,";
            if ((i & 0x00000400) != 0) s += "PIM Trust,";
            if (s.Length > 0) s = s.TrimEnd(',');
            return s;
        }
    }

    /// <summary>Mirror of Get-ADRSite (LDAP path).</summary>
    public sealed class SitesModule : IReconModule
    {
        public string Name { get { return "Sites"; } }

        // Run方法 - 收集站点信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Name", "Description", "whenCreated", "whenChanged");
            try
            {
                // 执行LDAP搜索
                string baseDn = "CN=Sites," + ctx.Session.ConfigurationNamingContext;
                var results = ctx.Session.Search(baseDn, "(objectClass=site)",
                    new[] { "name", "description", "whencreated", "whenchanged" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    // 添加行数据
                    AdRow row = Col.Row(cols);
                    row.Set("Name", AdSession.GetString(r, "name"));
                    row.Set("Description", AdSession.GetString(r, "description"));
                    row.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
                    row.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(r, "whenchanged")));
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRSite] Error while enumerating Site Objects");
                Log.Exception("Get-ADRSite", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("Sites", cols, rows)) : null;
        }
    }

    /// <summary>Mirror of Get-ADRSubnet (LDAP path).</summary>
    public sealed class SubnetsModule : IReconModule
    {
        public string Name { get { return "Subnets"; } }

        // Run方法 - 收集子网信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Site", "Name", "Description", "whenCreated", "whenChanged");
            try
            {
                // 执行LDAP搜索
                string baseDn = "CN=Subnets,CN=Sites," + ctx.Session.ConfigurationNamingContext;
                var results = ctx.Session.Search(baseDn, "(objectClass=subnet)",
                    new[] { "siteobject", "name", "description", "whencreated", "whenchanged" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    // 添加行数据
                    AdRow row = Col.Row(cols);
                    string site = AdSession.GetString(r, "siteobject");
                    row.Set("Site", SiteName(site));
                    row.Set("Name", AdSession.GetString(r, "name"));
                    row.Set("Description", AdSession.GetString(r, "description"));
                    row.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
                    row.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(r, "whenchanged")));
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRSubnet] Error while enumerating Subnet Objects");
                Log.Exception("Get-ADRSubnet", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("Subnets", cols, rows)) : null;
        }

        // SiteName - 从站点对象DN中提取站点名称
        private static string SiteName(string siteObject)
        {
            string[] parts = siteObject.Split(',');
            return parts.Length > 0 ? parts[0].Replace("CN=", "") : siteObject;
        }
    }

    /// <summary>Mirror of Get-ADRSchemaHistory (LDAP path). Emits the raw attribute values
    /// in the same shape as the embedded SchemaRecordProcessor.</summary>
    public sealed class SchemaHistoryModule : IReconModule
    {
        public string Name { get { return "SchemaHistory"; } }

        // Run方法 - 收集架构历史信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("ObjectClass", "Name", "whenCreated", "whenChanged", "DistinguishedName");
            try
            {
                // 执行LDAP搜索
                var results = ctx.Session.Search(ctx.Session.SchemaNamingContext, "(objectClass=*)",
                    new[] { "distinguishedname", "name", "objectclass", "whenchanged", "whencreated" },
                    SearchScope.OneLevel, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    // 添加行数据
                    string[] oc = AdSession.GetMultiString(r, "objectclass");
                    AdRow row = Col.Row(cols);
                    row.Set("ObjectClass", oc.Length > 0 ? oc[0] : "");
                    row.Set("Name", AdSession.GetString(r, "name"));
                    row.Set("whenCreated", AdSession.GetString(r, "whencreated"));
                    row.Set("whenChanged", AdSession.GetString(r, "whenchanged"));
                    row.Set("DistinguishedName", AdSession.GetString(r, "distinguishedname"));
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRSchemaHistory] Error while enumerating Schema Objects");
                Log.Exception("Get-ADRSchemaHistory", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("SchemaHistory", cols, rows)) : null;
        }
    }

    /// <summary>Mirror of Get-ADRDefaultPasswordPolicy (LDAP path) with the PCI/ACSC/CIS
    /// compliance matrix columns.</summary>
    public sealed class DefaultPasswordPolicyModule : IReconModule
    {
        public string Name { get { return "DefaultPasswordPolicy"; } }

        // Run方法 - 收集默认密码策略信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            AdSession s = ctx.Session;
            var rows = new List<AdRow>();
            var cols = Col.New("Policy", "Current Value", "PCI DSS v3.2.1", "PCI DSS v4.0",
                "PCI DSS Requirement", "ACSC ISM", "ISM Controls 16Jun2022", "CIS Benchmark 2022");
            try
            {
                // 获取密码策略属性
                using (DirectoryEntry e = s.NewEntryWithServer(s.DefaultNamingContext))
                {
                    string pwdHistory = GetProp(e, "pwdHistoryLength");
                    string maxAge = DaysFrom(e, "maxPwdAge", -864000000000L);
                    string minAge = DaysFrom(e, "minPwdAge", -864000000000L);
                    string minLength = GetProp(e, "minPwdLength");
                    string lockoutDuration = LockoutMins(GetInt64Prop(e, "lockoutDuration"));
                    string lockoutThreshold = GetProp(e, "lockoutThreshold");
                    string lockoutWindow = LockoutMins(GetInt64Prop(e, "lockoutObservationWindow"));

                    // 检查密码属性标志
                    string complexPasswords = FlagsSet(e, "pwdProperties", 1) ? "True" : "False";
                    string reversibleEncryption = FlagsSet(e, "pwdProperties", 16) ? "True" : "False";

                    // 添加所有策略行
                    Add(rows, cols, "Enforce password history (passwords)", pwdHistory,
                        "4", "4", "Req. 8.2.5 / 8.3.7", "N/A", "-", "24 or more");
                    Add(rows, cols, "Maximum password age (days)", maxAge,
                        "90", "90", "Req. 8.2.4 / 8.3.9", "365", "ISM-1590 Rev:1 Mar22", "1 to 365");
                    Add(rows, cols, "Minimum password age (days)", minAge,
                        "N/A", "N/A", "-", "N/A", "-", "1 or more");
                    Add(rows, cols, "Minimum password length (characters)", minLength,
                        "7", "12", "Req. 8.2.3 / 8.3.6", "14", "Control: ISM-0421 Rev:8 Dec21", "14 or more");
                    Add(rows, cols, "Password must meet complexity requirements", complexPasswords,
                        "True", "True", "Req. 8.2.3 / 8.3.6", "N/A", "-", "True");
                    Add(rows, cols, "Store password using reversible encryption for all users in the domain",
                        reversibleEncryption, "N/A", "N/A", "-", "N/A", "-", "False");
                    Add(rows, cols, "Account lockout duration (mins)", lockoutDuration,
                        "0 (manual unlock) or 30", "0 (manual unlock) or 30", "Req. 8.1.7 / 8.3.4", "N/A", "-", "15 or more");
                    Add(rows, cols, "Account lockout threshold (attempts)", lockoutThreshold,
                        "1 to 6", "1 to 10", "Req. 8.1.6 / 8.3.4", "1 to 5", "Control: ISM-1403 Rev:2 Oct19", "1 to 5");
                    Add(rows, cols, "Reset account lockout counter after (mins)", lockoutWindow,
                        "N/A", "N/A", "-", "N/A", "-", "15 or more");
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRDefaultPasswordPolicy] Error while enumerating the Default Password Policy");
                Log.Exception("Get-ADRDefaultPasswordPolicy", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("DefaultPasswordPolicy", cols, rows)) : null;
        }

        // Add - 添加策略行
        private static void Add(List<AdRow> rows, List<string> cols, params object[] vals)
        {
            AdRow row = Col.Row(cols);
            for (int i = 0; i < vals.Length; i++)
                row.Set(cols[i], vals[i]);
            rows.Add(row);
        }

        // GetProp - 获取属性值
        private static string GetProp(DirectoryEntry e, string name)
        {
            object v = e.Properties[name].Value;
            return v == null ? "" : v.ToString();
        }

        // GetInt64Prop - 获取64位整数属性值
        private static long GetInt64Prop(DirectoryEntry e, string name)
        {
            try
            {
                object v = e.Properties[name].Value;
                if (v == null) return 0;
                if (v is byte[]) return BitConverter.ToInt64((byte[])v, 0);
                return Convert.ToInt64(v);
            }
            catch { return 0; }
        }

        // FlagsSet - 检查属性中的标志位
        private static bool FlagsSet(DirectoryEntry e, string name, int bit)
        {
            try
            {
                object v = e.Properties[name].Value;
                if (v == null) return false;
                int i = Convert.ToInt32(v);
                return (i & bit) == bit;
            }
            catch { return false; }
        }

        // DaysFrom - 从时间间隔计算天数
        private static string DaysFrom(DirectoryEntry e, string name, long divisor)
        {
            long v = GetInt64Prop(e, name);
            if (v == 0) return "0";
            return (v / divisor).ToString();
        }

        // LockoutMins - 将锁定时间转换为分钟
        private static string LockoutMins(long v)
        {
            if (v == 0) return "0";
            long mins = v / -600000000L;
            if (mins > 99999) mins = 0;
            return mins.ToString();
        }
    }

    /// <summary>Mirror of Get-ADRFineGrainedPasswordPolicy (LDAP path).</summary>
    public sealed class FineGrainedPasswordPolicyModule : IReconModule
    {
        public string Name { get { return "FineGrainedPasswordPolicy"; } }

        // Run方法 - 收集细粒度密码策略信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Name", "Applies To", "Enforce password history",
                "Maximum password age (days)", "Minimum password age (days)", "Minimum password length",
                "Password must meet complexity requirements", "Store password using reversible encryption",
                "Account lockout duration (mins)", "Account lockout threshold",
                "Reset account lockout counter after (mins)", "Precedence");
            try
            {
                // 执行LDAP搜索
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext, "(objectClass=msDS-PasswordSettings)",
                    new[] { "name", "msds-psoappliesto", "msds-passwordhistorylength",
                            "msds-maximumpasswordage", "msds-minimumpasswordage", "msds-minimumpasswordlength",
                            "msds-passwordcomplexityenabled", "msds-passwordreversibleencryptionenabled",
                            "msds-lockoutduration", "msds-lockoutthreshold", "msds-lockoutobservationwindow",
                            "msds-passwordsettingsprecedence" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    // 添加行数据
                    AdRow row = Col.Row(cols);
                    row.Set("Name", AdSession.GetString(r, "name"));
                    row.Set("Applies To", Join(", ", AdSession.GetMultiString(r, "msds-psoappliesto")));
                    row.Set("Enforce password history", AdSession.GetString(r, "msds-passwordhistorylength"));
                    row.Set("Maximum password age (days)", Divide(AdSession.GetValue(r, "msds-maximumpasswordage"), -864000000000L));
                    row.Set("Minimum password age (days)", Divide(AdSession.GetValue(r, "msds-minimumpasswordage"), -864000000000L));
                    row.Set("Minimum password length", AdSession.GetString(r, "msds-minimumpasswordlength"));
                    row.Set("Password must meet complexity requirements", BoolStr(AdSession.GetValue(r, "msds-passwordcomplexityenabled")));
                    row.Set("Store password using reversible encryption", BoolStr(AdSession.GetValue(r, "msds-passwordreversibleencryptionenabled")));
                    row.Set("Account lockout duration (mins)", Divide(AdSession.GetValue(r, "msds-lockoutduration"), -600000000L));
                    row.Set("Account lockout threshold", AdSession.GetString(r, "msds-lockoutthreshold"));
                    row.Set("Reset account lockout counter after (mins)", Divide(AdSession.GetValue(r, "msds-lockoutobservationwindow"), -600000000L));
                    row.Set("Precedence", AdSession.GetString(r, "msds-passwordsettingsprecedence"));
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRFineGrainedPasswordPolicy] Error while enumerating the Fine Grained Password Policy");
                Log.Exception("Get-ADRFineGrainedPasswordPolicy", ex);
                return null;
            }
            return rows.Count > 0
                ? (List<ModuleResult>)Clr.Of(new ModuleResult("FineGrainedPasswordPolicy", cols, rows))
                : null;
        }

        // Join - 连接字符串数组
        private static string Join(string sep, string[] arr)
        {
            return arr.Length == 0 ? "" : string.Join(sep, arr);
        }

        // Divide - 除法运算
        private static string Divide(object v, long divisor)
        {
            try
            {
                if (v == null) return "";
                long l;
                if (v is byte[]) l = BitConverter.ToInt64((byte[])v, 0);
                else l = Convert.ToInt64(v);
                return (l / divisor).ToString();
            }
            catch { return ""; }
        }

        // BoolStr - 将值转换为布尔字符串
        private static string BoolStr(object v)
        {
            if (v == null) return "";
            if (v is bool) return (bool)v ? "True" : "False";
            try { return Convert.ToInt32(v) != 0 ? "True" : "False"; }
            catch { return v.ToString(); }
        }
    }

    /// <summary>LINQ-free list cast helper (C# 5 friendly).</summary>
    internal static class Clr
    {
        // Of - 创建包含单个项目的列表
        public static List<T> Of<T>(T item)
        {
            var l = new List<T> { item };
            return l;
        }
    }
}