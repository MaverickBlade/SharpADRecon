// ForestModule.cs - 林信息收集模块
// 镜像Get-ADRForest（LDAP路径）：收集林的基本信息，包括回收站、PAM和LAPS功能状态。

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using AdRecon.Ad;
using AdRecon.Core;

namespace AdRecon.Modules
{
    /// <summary>Mirror of Get-ADRForest (LDAP path). Emits Category/Value rows including
    /// Recycle Bin, PAM and LAPS feature status.</summary>
    public sealed class ForestModule : IReconModule
    {
        public string Name { get { return "Forest"; } }

        // 功能级别映射 - 将数字级别映射到对应的Windows版本名称
        private static readonly Dictionary<int, string> FlexLevels = new Dictionary<int, string>
        {
            { 0, "Windows2000" }, { 1, "Windows2003/Interim" }, { 2, "Windows2003" },
            { 3, "Windows2008" }, { 4, "Windows2008R2" }, { 5, "Windows2012" },
            { 6, "Windows2012R2" }, { 7, "Windows2016" }
        };

        // Run方法 - 收集林信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            AdSession s = ctx.Session;
            var cols = new List<string> { "Category", "Value" };
            var rows = new List<AdRow>();
            Action<string, object> add = (k, v) =>
            {
                var r = new AdRow(cols);
                r.Set("Category", k);
                r.Set("Value", v);
                rows.Add(r);
            };

            // 获取域DN和FQDN
            string domainDn = s.DefaultNamingContext;
            string fqdn = AdAttrs.DnToFqdn(domainDn);

            // 获取林上下文
            System.DirectoryServices.ActiveDirectory.Forest forest = null;
            try
            {
                var adDomain = DomainForest.GetDomain(s, fqdn);
                string forestName;
                try { forestName = adDomain.Forest.Name; }
                catch { forestName = AdAttrs.DnToFqdn(s.RootDomainNamingContext); }
                forest = DomainForest.GetForest(s, forestName);
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRForest] Error getting Forest Context");
                Log.Exception("Get-ADRForest", ex);
                return null;
            }

            // 获取林功能级别
            int forestLevel = RootDseInt(s, "forestFunctionality");
            string forestMode = "";
            {
                string name;
                forestMode = (FlexLevels.TryGetValue(forestLevel, out name) ? name : forestLevel.ToString()) + "Forest";
            }

            // 获取墓碑生存时间
            string tombstoneLifetime = "";
            try
            {
                string path = "CN=Directory Service,CN=Windows NT,CN=Services," + s.ConfigurationNamingContext;
                DirectorySearcher se = s.NewSearcher(path, "(name=Directory Service)",
                    new[] { "tombstoneLifetime", "whenCreated" }, SearchScope.Base, 200);
                using (se)
                {
                    SearchResult r = se.FindOne();
                    if (r != null) tombstoneLifetime = AdSession.GetString(r, "tombstoneLifetime");
                }
            }
            catch (Exception ex) { Log.Exception("Get-ADRForest Tombstone", ex); }

            // 检查回收站和PAM可选功能
            DirectoryEntry recycleBin = null, pamFeature = null;
            if (forestLevel >= 4)
                recycleBin = OptionalFeature(s, "Recycle Bin Feature");
            if (forestLevel >= 7)
                pamFeature = OptionalFeature(s, "Privileged Access Management Feature");

            // 枚举林中的域、站点和全局编录
            var domainNames = new List<string>();
            var siteNames = new List<string>();
            var gcNames = new List<string>();
            try
            {
                foreach (System.DirectoryServices.ActiveDirectory.Domain d in forest.Domains) domainNames.Add(d.Name);
                foreach (System.DirectoryServices.ActiveDirectory.ActiveDirectorySite st in forest.Sites) siteNames.Add(st.Name);
                foreach (System.DirectoryServices.ActiveDirectory.GlobalCatalog gc in forest.GlobalCatalogs) gcNames.Add(gc.Name);
            }
            catch (Exception ex) { Log.Exception("Get-ADRForest enumeration", ex); }

            // 获取林属性
            string namingMaster = "", schemaMaster = "", rootDomain = "";
            int domainCount = 0, siteCount = 0, gcCount = 0;
            try
            {
                namingMaster = forest.NamingRoleOwner.Name;
                schemaMaster = forest.SchemaRoleOwner.Name;
                rootDomain = forest.RootDomain.Name;
                domainCount = forest.Domains.Count;
                siteCount = forest.Sites.Count;
                gcCount = forest.GlobalCatalogs.Count;
            }
            catch (Exception ex) { Log.Exception("Get-ADRForest forest properties", ex); }

            // 获取林名称
            string forestNameStr;
            try { forestNameStr = forest.Name; } catch { forestNameStr = ""; }

            // 添加所有收集到的信息
            add("Name", forestNameStr);
            add("Functional Level", forestMode);
            add("Domain Naming Master", namingMaster);
            add("Schema Master", schemaMaster);
            add("RootDomain", rootDomain);
            add("Domain Count", domainCount.ToString());
            add("Site Count", siteCount.ToString());
            add("Global Catalog Count", gcCount.ToString());

            // 添加域、站点和全局编录列表
            foreach (string d in domainNames) add("Domain", d);
            foreach (string st in siteNames) add("Site", st);
            foreach (string g in gcNames) add("GlobalCatalog", g);

            // 添加墓碑生存时间
            add("Tombstone Lifetime", tombstoneLifetime.Length > 0 ? tombstoneLifetime : "Not Retrieved");

            // 添加回收站状态
            add("Recycle Bin (2008 R2 onwards)", EnabledFeature(recycleBin) ? "Enabled" : "Disabled");
            if (EnabledFeature(recycleBin))
            {
                add("Recycle Bin Enabled Date", WhenCreated(recycleBin));
                foreach (string scope in EnabledScopes(recycleBin)) add("Enabled Scope", scope);
            }
            if (recycleBin != null) { try { recycleBin.Dispose(); } catch { } }

            // 添加PAM状态
            add("Privileged Access Management (2016 onwards)", EnabledFeature(pamFeature) ? "Enabled" : "Disabled");
            if (EnabledFeature(pamFeature))
            {
                foreach (string scope in EnabledScopes(pamFeature)) add("Enabled Scope", scope);
            }
            if (pamFeature != null) { try { pamFeature.Dispose(); } catch { } }

            // 添加LAPS状态
            bool laps = LapsCheck.IsImplemented(s);
            add("LAPS", laps ? "Enabled" : "Disabled");
            if (laps)
            {
                add("LAPS Installed Date", LapsInstalledDate(s));
            }

            return new List<ModuleResult> { new ModuleResult("Forest", cols, rows) };
        }

        // RootDseInt - 从rootDSE获取整数值
        private static int RootDseInt(AdSession s, string name)
        {
            try
            {
                string v = AdSession.GetString(s.Root, name);
                int i = 0;
                if (int.TryParse(v, out i)) return i;
            }
            catch { }
            return 0;
        }

        // OptionalFeature - 获取可选功能条目
        private static DirectoryEntry OptionalFeature(AdSession s, string featureName)
        {
            try
            {
                string dn = "CN=" + featureName + ",CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + s.DefaultNamingContext;
                return s.NewEntryWithServer(dn);
            }
            catch { return null; }
        }

        // EnabledFeature - 检查功能是否已启用
        private static bool EnabledFeature(DirectoryEntry e)
        {
            if (e == null) return false;
            try { return e.Properties["msDS-EnabledFeatureBL"].Value != null; }
            catch { return false; }
        }

        // EnabledScopes - 获取功能启用的范围
        private static IEnumerable<string> EnabledScopes(DirectoryEntry e)
        {
            var list = new List<string>();
            if (e == null) return list;
            try
            {
                foreach (object o in e.Properties["msDS-EnabledFeatureBL"]) list.Add(o.ToString());
            }
            catch { }
            return list;
        }

        // WhenCreated - 获取创建时间
        private static string WhenCreated(DirectoryEntry e)
        {
            try
            {
                object v = e.Properties["whenCreated"].Value;
                return v == null ? "" : v.ToString();
            }
            catch { return ""; }
        }

        // LapsInstalledDate - 获取LAPS安装日期
        private static string LapsInstalledDate(AdSession s)
        {
            try
            {
                using (DirectoryEntry e = s.NewEntryWithServer("CN=ms-Mcs-AdmPwd," + s.SchemaNamingContext))
                {
                    object v = e.Properties["whenCreated"].Value;
                    return v == null ? "" : v.ToString();
                }
            }
            catch { return ""; }
        }
    }
}