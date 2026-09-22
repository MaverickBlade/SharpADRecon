// DomainModule.cs - 域信息收集模块
// 镜像Get-ADRDomain（LDAP路径）：收集域的基本信息并生成类别/值行。

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using AdRecon.Ad;
using AdRecon.Core;

namespace AdRecon.Modules
{
    /// <summary>Mirror of Get-ADRDomain (LDAP path). Emits Category/Value rows.</summary>
    public sealed class DomainModule : IReconModule
    {
        public string Name { get { return "Domain"; } }

        // 功能级别映射 - 将数字级别映射到对应的Windows版本名称
        private static readonly Dictionary<int, string> FlexLevels = new Dictionary<int, string>
        {
            { 0, "Windows2000" }, { 1, "Windows2003/Interim" }, { 2, "Windows2003" },
            { 3, "Windows2008" }, { 4, "Windows2008R2" }, { 5, "Windows2012" },
            { 6, "Windows2012R2" }, { 7, "Windows2016" }
        };

        // Run方法 - 收集域信息并返回结果
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

            // 获取域上下文
            System.DirectoryServices.ActiveDirectory.Domain adDomain = null;
            try
            {
                adDomain = DomainForest.GetDomain(s, fqdn);
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRDomain] Error getting Domain Context");
                Log.Exception("Get-ADRDomain", ex);
                return null;
            }

            // 获取域SID - 优先使用全局编录，回退到域根对象Sid
            string domainSid = SidFromDomainRoot(s, domainDn);

            // 从CN=Partitions交叉引用获取NetBIOS名称
            string netBios = "";
            try
            {
                string partitions = "CN=Partitions," + s.ConfigurationNamingContext;
                DirectorySearcher se = s.NewSearcher(partitions,
                    "(&(objectCategory=crossRef)(ncName=" + domainDn + "))",
                    new[] { "netbiosname" }, SearchScope.Subtree, 200);
                using (se)
                {
                    SearchResult r = se.FindOne();
                    if (r != null) netBios = AdSession.GetString(r, "netbiosname");
                }
            }
            catch (Exception ex) { Log.Exception("Get-ADRDomain NetBIOS", ex); }

            // 从rootDSE获取功能级别
            string domainMode = "";
            try
            {
                string fl = AdSession.GetString(s.Root, "domainFunctionality");
                int flInt = 0;
                if (int.TryParse(fl, out flInt))
                {
                    string name;
                    domainMode = (FlexLevels.TryGetValue(flInt, out name) ? name : fl) + "Domain";
                }
            }
            catch { }

            // 获取RID池信息
            long ridsIssued = 0, ridsRemaining = 0;
            try
            {
                using (DirectoryEntry e = s.NewEntryWithServer("CN=RID Manager$,CN=System," + domainDn))
                {
                    object pool = e.Properties["rIDAvailablePool"].Value;
                    long val = ParseInt64(pool);
                    if (val >= 0)
                    {
                        long totalSids = val / ((long)1 << 32);
                        long temp64 = totalSids * ((long)1 << 32);
                        ridsIssued = ((val - temp64) & 0xFFFFFFFF);
                        ridsRemaining = totalSids - ridsIssued;
                    }
                }
            }
            catch (Exception ex) { Log.Exception("Get-ADRDomain RID Manager", ex); }

            // 获取域创建日期和计算机账户配额
            string creationDate = "";
            string machineAccountQuota = "";
            try
            {
                using (DirectoryEntry e = s.NewEntryWithServer(domainDn))
                {
                    object wc = e.Properties["whenCreated"].Value;
                    if (wc != null) creationDate = wc.ToString();
                    object q = e.Properties["ms-DS-MachineAccountQuota"].Value;
                    if (q != null) machineAccountQuota = q.ToString();
                }
            }
            catch (Exception ex) { Log.Exception("Get-ADRDomain domain root", ex); }

            // 获取域名
            string domainName = "";
            try { domainName = adDomain.Name; }
            catch { domainName = fqdn; }

            // 添加所有收集到的信息
            add("Name", domainName);
            add("NetBIOS", netBios);
            add("Functional Level", domainMode);
            add("DomainSID", domainSid);
            if (creationDate.Length > 0) add("Creation Date", creationDate);
            add("ms-DS-MachineAccountQuota", machineAccountQuota);
            if (ridsIssued != 0) add("RIDs Issued", ridsIssued.ToString());
            if (ridsRemaining != 0) add("RIDs Remaining", ridsRemaining.ToString());

            return new List<ModuleResult> { new ModuleResult("Domain", cols, rows) };
        }

        // SidFromDomainRoot - 从域根获取域SID
        private static string SidFromDomainRoot(AdSession s, string domainDn)
        {
            // 尝试GC（端口3268），然后回退到普通LDAP绑定
            string sid = "";
            try
            {
                string host = s.BindHost;
                string gc = host.Length > 0
                    ? "GC://" + host + "/" + domainDn
                    : "GC://" + domainDn;
                if (s.Username.Length == 0)
                {
                    using (DirectoryEntry e = new DirectoryEntry(gc))
                    {
                        if (e.Properties["objectSid"].Value != null)
                            sid = DomainForest.SidToString(e.Properties["objectSid"].Value);
                    }
                }
                else
                {
                    using (DirectoryEntry e = new DirectoryEntry(gc, s.Username, s.Password))
                    {
                        if (e.Properties["objectSid"].Value != null)
                            sid = DomainForest.SidToString(e.Properties["objectSid"].Value);
                    }
                }
            }
            catch { }
            if (sid.Length > 0) return sid;

            // 回退到普通LDAP绑定
            try
            {
                using (DirectoryEntry e = s.NewEntryWithServer(domainDn))
                {
                    object o = e.Properties["objectSid"].Value;
                    if (o != null) sid = DomainForest.SidToString(o);
                }
            }
            catch { }
            return sid;
        }

        // ParseInt64 - 安全解析64位整数
        private static long ParseInt64(object v)
        {
            try
            {
                if (v == null) return -1;
                if (v is byte[]) return BitConverter.ToInt64((byte[])v, 0);
                return Convert.ToInt64(v);
            }
            catch { return -1; }
        }
    }
}