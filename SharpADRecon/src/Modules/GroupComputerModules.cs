// GroupComputerModules.cs - 组和计算机信息收集模块
// 包含GroupChangesModule、GroupMembersModule、ComputersModule和ComputerSPNsModule类。
// 镜像Get-ADRGroup和Get-ADRComputer的LDAP路径实现。

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Net;
using System.Security.Principal;
using System.Xml;
using AdRecon.Ad;
using AdRecon.Core;

namespace AdRecon.Modules
{
    /// <summary>Mirror of Get-ADRGroup - GroupChanges artifact (GroupChangeRecordProcessor).</summary>
    public sealed class GroupChangesModule : IReconModule
    {
        public string Name { get { return "GroupChanges"; } }

        // Run方法 - 收集组成员变更信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Group Name", "Group DistinguishedName", "Member DistinguishedName", "Action",
                "Added Age (Days)", "Removed Age (Days)", "Added Date", "Removed Date", "ftimeCreated", "ftimeDeleted");
            DateTime date = DateTime.Now;
            try
            {
                // 执行LDAP搜索
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext, "(objectClass=group)",
                    new[] { "distinguishedname", "samaccountname", "msds-replvaluemetadata" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    string groupName = AdSession.GetString(r, "samaccountname");
                    string groupDN = AdAttrs.CleanString(AdSession.GetValue(r, "distinguishedname"));
                    object replMeta = AdSession.GetValue(r, "msds-replvaluemetadata");
                    if (replMeta == null) continue;

                    // 处理XML元数据
                    string[] xmlArr;
                    if (replMeta is ResultPropertyValueCollection)
                    {
                        var col = (ResultPropertyValueCollection)replMeta;
                        xmlArr = new string[col.Count];
                        for (int i = 0; i < col.Count; i++) xmlArr[i] = col[i].ToString();
                    }
                    else
                    {
                        xmlArr = new string[] { replMeta.ToString() };
                    }

                    // 解析每个XML条目
                    foreach (string xmlData in xmlArr)
                    {
                        string cleaned = xmlData.Replace("\x00", "").Replace("&", "&amp;");
                        try
                        {
                            XmlDocument doc = new XmlDocument();
                            doc.LoadXml(cleaned);
                            XmlNode node = doc.SelectSingleNode("DS_REPL_VALUE_META_DATA");
                            if (node == null) continue;
                            string ftimeCreated = node["ftimeCreated"].InnerText;
                            string ftimeDeleted = node["ftimeDeleted"].InnerText;
                            string memberDN = AdAttrs.CleanString(node["pszObjectDn"].InnerText);
                            string action;
                            DateTime? addedDate = null, removedDate = null;
                            int? daysSinceAdded = null, daysSinceRemoved = null;

                            // 确定操作类型
                            if (ftimeDeleted != "1601-01-01T00:00:00Z")
                            {
                                action = "Removed";
                                addedDate = DateTime.Parse(ftimeCreated);
                                daysSinceAdded = Math.Abs((int)(date - addedDate.Value).TotalDays);
                                removedDate = DateTime.Parse(ftimeDeleted);
                                daysSinceRemoved = Math.Abs((int)(date - removedDate.Value).TotalDays);
                            }
                            else
                            {
                                action = "Added";
                                addedDate = DateTime.Parse(ftimeCreated);
                                daysSinceAdded = Math.Abs((int)(date - addedDate.Value).TotalDays);
                            }

                            // 添加行数据
                            AdRow row = Col.Row(cols);
                            row.Set("Group Name", groupName);
                            row.Set("Group DistinguishedName", groupDN);
                            row.Set("Member DistinguishedName", memberDN);
                            row.Set("Action", action);
                            row.Set("Added Age (Days)", daysSinceAdded);
                            row.Set("Removed Age (Days)", daysSinceRemoved);
                            row.Set("Added Date", addedDate);
                            row.Set("Removed Date", removedDate);
                            row.Set("ftimeCreated", ftimeCreated);
                            row.Set("ftimeDeleted", ftimeDeleted);
                            rows.Add(row);
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRGroup] Error while enumerating Group Membership Changes");
                Log.Exception("Get-ADRGroup", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("GroupChanges", cols, rows)) : null;
        }
    }

    /// <summary>Mirror of Get-ADRGroupMember (LDAP path). Builds a SID→GroupName dictionary from
    /// all groups first, then iterates every object that has memberof or primaryGroupId to emit
    /// Group Members rows.</summary>
    public sealed class GroupMembersModule : IReconModule
    {
        public string Name { get { return "GroupMembers"; } }

        // SAM账户类型常量
        private static readonly HashSet<string> GroupSamTypes = new HashSet<string>(
            new string[] { "268435456", "268435457", "536870912", "536870913" });
        private static readonly HashSet<string> UserSamTypes = new HashSet<string>(
            new string[] { "805306368" });
        private static readonly HashSet<string> ComputerSamTypes = new HashSet<string>(
            new string[] { "805306369" });
        private static readonly HashSet<string> TrustSamTypes = new HashSet<string>(
            new string[] { "805306370" });

        // Run方法 - 收集组成员信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Group Name", "Member UserName", "Member Name", "Member SID", "AccountType");

            try
            {
                // 步骤1: 构建所有组的SID→SamAccountName字典
                var groupDict = new Dictionary<string, string>();
                var groups = ctx.Session.Search(ctx.Session.DefaultNamingContext, "(objectClass=group)",
                    new[] { "objectsid", "samaccountname" }, SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult g in groups)
                {
                    try
                    {
                        object sidObj = AdSession.GetValue(g, "objectsid");
                        if (sidObj == null || !(sidObj is byte[])) continue;
                        string sid = new SecurityIdentifier((byte[])sidObj, 0).ToString();
                        string sam = AdSession.GetString(g, "samaccountname");
                        if (!groupDict.ContainsKey(sid)) groupDict[sid] = sam;
                    }
                    catch { }
                }

                // 步骤2: 获取域SID
                string domainSid = ResolveDomainSid(ctx.Session);

                // 步骤3: 遍历所有成员对象
                var members = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(|(memberof=*)(primarygroupid=*))",
                    new[] { "distinguishedname", "dnshostname", "objectclass", "primarygroupid",
                            "memberof", "samaccountname", "samaccounttype", "objectsid" },
                    SearchScope.Subtree, ctx.Config.PageSize);

                foreach (SearchResult m in members)
                {
                    string samAccountType = AdSession.GetString(m, "samaccounttype");
                    string objectClass = "";
                    string[] oc = AdSession.GetMultiString(m, "objectclass");
                    if (oc.Length > 0) objectClass = oc[oc.Length - 1];
                    string accountType = "";
                    string memberUserName = "-";
                    string memberName = "";
                    string groupName = "";
                    string sid = "";

                    try
                    {
                        object sidObj = AdSession.GetValue(m, "objectsid");
                        if (sidObj is byte[]) sid = new SecurityIdentifier((byte[])sidObj, 0).ToString();
                    }
                    catch { }

                    // 处理外部安全主体
                    if (objectClass == "foreignSecurityPrincipal")
                    {
                        accountType = "foreignSecurityPrincipal";
                        memberName = null;
                        memberUserName = SplitDN(AdSession.GetString(m, "distinguishedname"));
                        string[] memOf = AdSession.GetMultiString(m, "memberof");
                        for (int i = 0; i < memOf.Length; i++)
                        {
                            groupName = SplitDN(memOf[i]);
                            AdRow row = Col.Row(cols);
                            row.Set("Group Name", groupName);
                            row.Set("Member UserName", memberUserName);
                            row.Set("Member Name", memberName);
                            row.Set("Member SID", sid);
                            row.Set("AccountType", accountType);
                            rows.Add(row);
                        }
                        continue;
                    }

                    // 处理组成员
                    if (GroupSamTypes.Contains(samAccountType))
                    {
                        accountType = "group";
                        memberName = SplitDN(AdSession.GetString(m, "distinguishedname"));
                        string[] memOf = AdSession.GetMultiString(m, "memberof");
                        for (int i = 0; i < memOf.Length; i++)
                        {
                            groupName = SplitDN(memOf[i]);
                            AdRow row = Col.Row(cols);
                            row.Set("Group Name", groupName);
                            row.Set("Member UserName", memberUserName);
                            row.Set("Member Name", memberName);
                            row.Set("Member SID", sid);
                            row.Set("AccountType", accountType);
                            rows.Add(row);
                        }
                        continue;
                    }

                    // 处理用户成员
                    if (UserSamTypes.Contains(samAccountType))
                    {
                        accountType = "user";
                        memberName = SplitDN(AdSession.GetString(m, "distinguishedname"));
                        memberUserName = AdSession.GetString(m, "samaccountname");
                        string primaryGroupId = AdSession.GetString(m, "primarygroupid");
                        string psid = domainSid + "-" + primaryGroupId;
                        string gname;
                        if (!groupDict.TryGetValue(psid, out gname)) gname = primaryGroupId;

                        AdRow row = Col.Row(cols);
                        row.Set("Group Name", gname);
                        row.Set("Member UserName", memberUserName);
                        row.Set("Member Name", memberName);
                        row.Set("Member SID", sid);
                        row.Set("AccountType", accountType);
                        rows.Add(row);

                        string[] memOf = AdSession.GetMultiString(m, "memberof");
                        for (int i = 0; i < memOf.Length; i++)
                        {
                            groupName = SplitDN(memOf[i]);
                            row = Col.Row(cols);
                            row.Set("Group Name", groupName);
                            row.Set("Member UserName", memberUserName);
                            row.Set("Member Name", memberName);
                            row.Set("Member SID", sid);
                            row.Set("AccountType", accountType);
                            rows.Add(row);
                        }
                        continue;
                    }

                    // 处理计算机成员
                    if (ComputerSamTypes.Contains(samAccountType))
                    {
                        accountType = "computer";
                        memberName = SplitDN(AdSession.GetString(m, "distinguishedname"));
                        memberUserName = AdSession.GetString(m, "samaccountname");
                        string primaryGroupId = AdSession.GetString(m, "primarygroupid");
                        string psid = domainSid + "-" + primaryGroupId;
                        string gname;
                        if (!groupDict.TryGetValue(psid, out gname)) gname = primaryGroupId;

                        AdRow row = Col.Row(cols);
                        row.Set("Group Name", gname);
                        row.Set("Member UserName", memberUserName);
                        row.Set("Member Name", memberName);
                        row.Set("Member SID", sid);
                        row.Set("AccountType", accountType);
                        rows.Add(row);

                        string[] memOf = AdSession.GetMultiString(m, "memberof");
                        for (int i = 0; i < memOf.Length; i++)
                        {
                            groupName = SplitDN(memOf[i]);
                            row = Col.Row(cols);
                            row.Set("Group Name", groupName);
                            row.Set("Member UserName", memberUserName);
                            row.Set("Member Name", memberName);
                            row.Set("Member SID", sid);
                            row.Set("AccountType", accountType);
                            rows.Add(row);
                        }
                        continue;
                    }

                    // 处理信任账户
                    if (TrustSamTypes.Contains(samAccountType))
                    {
                        accountType = "trust";
                        memberName = SplitDN(AdSession.GetString(m, "distinguishedname"));
                        memberUserName = AdSession.GetString(m, "samaccountname");
                        string primaryGroupId = AdSession.GetString(m, "primarygroupid");
                        string psid = domainSid + "-" + primaryGroupId;
                        string gname;
                        if (!groupDict.TryGetValue(psid, out gname)) gname = primaryGroupId;

                        AdRow row = Col.Row(cols);
                        row.Set("Group Name", gname);
                        row.Set("Member UserName", memberUserName);
                        row.Set("Member Name", memberName);
                        row.Set("Member SID", sid);
                        row.Set("AccountType", accountType);
                        rows.Add(row);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRGroupMember] Error while enumerating Group Members");
                Log.Exception("Get-ADRGroupMember", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("GroupMembers", cols, rows)) : null;
        }

        // SplitDN - 从DN中提取第一个组件的值
        private static string SplitDN(string dn)
        {
            if (dn == null || dn.Length == 0) return "";
            string[] parts = dn.Split(',');
            if (parts.Length == 0) return "";
            string first = parts[0];
            int eq = first.IndexOf('=');
            return eq >= 0 ? first.Substring(eq + 1) : first;
        }

        // ResolveDomainSid - 解析域SID
        private static string ResolveDomainSid(AdSession s)
        {
            string sid = "";
            string domainDn = s.DefaultNamingContext;
            try
            {
                string host = s.BindHost;
                string gc = host.Length > 0
                    ? "GC://" + host + "/" + domainDn
                    : "GC://" + domainDn;
                using (DirectoryEntry e = s.Username.Length == 0
                    ? new DirectoryEntry(gc)
                    : new DirectoryEntry(gc, s.Username, s.Password))
                {
                    if (e.Properties["objectSid"].Value != null)
                        sid = DomainForest.SidToString(e.Properties["objectSid"].Value);
                }
            }
            catch { }
            if (sid.Length > 0) return sid;
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
    }

    /// <summary>Mirror of Get-ADRComputer - Computers artifact (LDAP path, ComputerRecordProcessor).
    /// DNS resolution via Dns.GetHostEntry is skipped on execute-assembly (no network); set to
    /// "-" if unavailable.</summary>
    public sealed class ComputersModule : IReconModule
    {
        public string Name { get { return "Computers"; } }

        // Run方法 - 收集计算机信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("UserName", "Name", "DNSHostName", "Enabled", "IPv4Address",
                "Operating System", "Logon Age (days)", "Password Age (days)",
                "Dormant (> " + ctx.Config.DormantTimeSpan + " days)",
                "Password Age (> " + UsersModule.PassMaxAgeFor(ctx) + " days)",
                "Delegation Type", "Delegation Protocol", "Delegation Services",
                "Primary Group ID", "SID", "SIDHistory", "Description", "ms-ds-CreatorSid",
                "Last Logon Date", "Password LastSet", "UserAccountControl",
                "whenCreated", "whenChanged", "Distinguished Name");

            DateTime date = DateTime.Now;
            int dormantTimeSpan = ctx.Config.DormantTimeSpan;
            int passMaxAge = UsersModule.PassMaxAgeFor(ctx);

            try
            {
                // 构建LDAP查询
                string filter = ctx.Config.OnlyEnabled
                    ? "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
                    : "(samAccountType=805306369)";
                string[] props = new[] {
                    "description", "distinguishedname", "dnshostname", "lastlogontimestamp",
                    "msDS-AllowedToDelegateTo", "ms-ds-CreatorSid", "msDS-SupportedEncryptionTypes",
                    "name", "objectsid", "operatingsystem", "operatingsystemhotfix",
                    "operatingsystemservicepack", "operatingsystemversion", "primarygroupid",
                    "pwdlastset", "samaccountname", "serviceprincipalname", "sidhistory",
                    "useraccountcontrol", "whenchanged", "whencreated" };
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext, filter, props,
                    SearchScope.Subtree, ctx.Config.PageSize);

                // 处理搜索结果
                foreach (SearchResult r in results)
                {
                    AdRow row = BuildRow(r, date, dormantTimeSpan, passMaxAge);
                    if (row != null) rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRComputer] Error while enumerating Computer Objects");
                Log.Exception("Get-ADRComputer", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("Computers", cols, rows)) : null;
        }

        // BuildRow - 从搜索结果构建计算机行数据
        private static AdRow BuildRow(SearchResult r, DateTime date, int dormantTimeSpan, int passMaxAge)
        {
            var cols = Col.New("UserName");
            AdRow row = Col.Row(cols);

            bool? enabled = null, trustedForDelegation = null, trustedToAuth = null;
            DateTime? lastLogonDate = null, passwordLastSet = null;
            int? daysSinceLastLogon = null, daysSinceLastPasswordChange = null;
            bool dormant = false, passwordNotChangedAfterMaxAge = false;
            string delegationType = null, delegationProtocol = null, delegationServices = null;

            // 获取IP地址（在执行程序集环境中优雅地跳过DNS）
            string strIP = null;
            string dnsName = AdSession.GetString(r, "dnshostname");
            if (dnsName.Length > 0)
            {
                try
                {
                    IPHostEntry entry = Dns.GetHostEntry(dnsName);
                    if (entry.AddressList.Length > 0) strIP = entry.AddressList[0].ToString();
                }
                catch { strIP = null; }
            }

            // 解码UserAccountControl标志
            int? uac = UsersModule.ReadIntNullable(r, "useraccountcontrol");
            if (uac.HasValue)
            {
                int v = uac.Value;
                enabled = !UserFlagDecoder.Bit(v, UserFlagDecoder.ACCOUNTDISABLE);
                trustedForDelegation = UserFlagDecoder.Bit(v, UserFlagDecoder.TRUSTED_FOR_DELEGATION);
                trustedToAuth = UserFlagDecoder.Bit(v, UserFlagDecoder.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION);
            }

            // 处理最后登录时间
            string lastLogonTs = AdSession.GetString(r, "lastlogontimestamp");
            if (lastLogonTs.Length > 0 && lastLogonTs != "0")
            {
                long l = UsersModule.FromFileTime(lastLogonTs);
                if (l != 0)
                {
                    lastLogonDate = DateTime.FromFileTime(l);
                    daysSinceLastLogon = Math.Abs((int)(date - lastLogonDate.Value).TotalDays);
                    if (daysSinceLastLogon.Value > dormantTimeSpan) dormant = true;
                }
            }

            // 处理密码最后设置时间
            string pwdLastSet = AdSession.GetString(r, "pwdlastset");
            if (pwdLastSet.Length > 0 && pwdLastSet != "0")
            {
                passwordLastSet = DateTime.FromFileTime(UsersModule.FromFileTime(pwdLastSet));
                daysSinceLastPasswordChange = Math.Abs((int)(date - passwordLastSet.Value).TotalDays);
                if (daysSinceLastPasswordChange.Value > passMaxAge) passwordNotChangedAfterMaxAge = true;
            }

            // 处理委派信息：仅当primaryGroupID == 515（域计算机）时允许无约束委派
            if (trustedForDelegation.HasValue && trustedForDelegation.Value)
            {
                string pgid = AdSession.GetString(r, "primarygroupid");
                if (pgid == "515")
                {
                    delegationType = "Unconstrained";
                    delegationServices = "Any";
                }
            }
            string[] allowedToDelegate = AdSession.GetMultiString(r, "msDS-AllowedToDelegateTo");
            if (allowedToDelegate.Length >= 1)
            {
                delegationType = "Constrained";
                string svc = delegationServices;
                for (int i = 0; i < allowedToDelegate.Length; i++)
                    svc = svc + "," + allowedToDelegate[i];
                delegationServices = svc.TrimStart(',');
            }
            if (trustedToAuth.HasValue && trustedToAuth.Value)
                delegationProtocol = "Any";
            else if (delegationType != null)
                delegationProtocol = "Kerberos";

            // 构建操作系统字符串
            string os = AdSession.GetString(r, "operatingsystem");
            string hotfix = AdSession.GetString(r, "operatingsystemhotfix");
            string spack = AdSession.GetString(r, "operatingsystemservicepack");
            string osver = AdSession.GetString(r, "operatingsystemversion");
            string operatingSystem = AdAttrs.CleanString(
                (os.Length > 0 ? os : "-") + " " +
                (hotfix.Length > 0 ? hotfix : " ") + " " +
                (spack.Length > 0 ? spack : " ") + " " +
                (osver.Length > 0 ? osver : " "));

            // 获取SID历史记录
            string sidHistory = UserFlagDecoder.SidsFromHistory(AdSession.GetValue(r, "sidhistory"));

            // 设置行数据
            row.Set("UserName", AdAttrs.CleanString(AdSession.GetValue(r, "samaccountname")));
            row.Set("Name", AdAttrs.CleanString(AdSession.GetValue(r, "name")));
            row.Set("DNSHostName", dnsName);
            row.Set("Enabled", enabled);
            row.Set("IPv4Address", strIP);
            row.Set("Operating System", operatingSystem);
            row.Set("Logon Age (days)", daysSinceLastLogon);
            row.Set("Password Age (days)", daysSinceLastPasswordChange);
            row.Set("Dormant (> " + dormantTimeSpan + " days)", dormant);
            row.Set("Password Age (> " + passMaxAge + " days)", passwordNotChangedAfterMaxAge);
            row.Set("Delegation Type", delegationType);
            row.Set("Delegation Protocol", delegationProtocol);
            row.Set("Delegation Services", delegationServices);
            row.Set("Primary Group ID", AdSession.GetString(r, "primarygroupid"));
            row.Set("SID", Sids.HistoryToString(AdSession.GetValue(r, "objectsid")));
            row.Set("SIDHistory", sidHistory);
            row.Set("Description", AdAttrs.CleanString(AdSession.GetValue(r, "description")));
            row.Set("ms-ds-CreatorSid", CreatorSid(r));
            row.Set("Last Logon Date", lastLogonDate);
            row.Set("Password LastSet", passwordLastSet);
            row.Set("UserAccountControl", AdSession.GetValue(r, "useraccountcontrol"));
            row.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
            row.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(r, "whenchanged")));
            row.Set("Distinguished Name", AdSession.GetString(r, "distinguishedname"));
            return row;
        }

        // CreatorSid - 获取创建者SID
        private static string CreatorSid(SearchResult r)
        {
            try
            {
                object v = AdSession.GetValue(r, "ms-ds-CreatorSid");
                if (v == null) return "";
                if (v is byte[]) return new SecurityIdentifier((byte[])v, 0).ToString();
                return v.ToString();
            }
            catch { return ""; }
        }
    }

    /// <summary>Mirror of Get-ADRComputer - ComputerSPNs artifact (ComputerSPNRecordProcessor).
    /// De-duplicates hosts per Service.</summary>
    public sealed class ComputerSPNsModule : IReconModule
    {
        public string Name { get { return "ComputerSPNs"; } }

        // Run方法 - 收集计算机SPN信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("UserName", "Name", "Service", "Host");
            try
            {
                // 构建LDAP查询
                string filter = ctx.Config.OnlyEnabled
                    ? "(&(samAccountType=805306369)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
                    : "(&(samAccountType=805306369)(servicePrincipalName=*))";
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext, filter,
                    new[] { "name", "serviceprincipalname", "samaccountname" },
                    SearchScope.Subtree, ctx.Config.PageSize);

                foreach (SearchResult r in results)
                {
                    string[] spns = AdSession.GetMultiString(r, "serviceprincipalname");
                    if (spns.Length == 0) continue;

                    string userName = AdAttrs.CleanString(AdSession.GetValue(r, "samaccountname"));
                    string name = AdAttrs.CleanString(AdSession.GetValue(r, "name"));

                    // 按服务分组SPN，用逗号连接主机，使用.Distinct()去重
                    var serviceHosts = new Dictionary<string, List<string>>();

                    for (int i = 0; i < spns.Length; i++)
                    {
                        string[] parts = spns[i].Split('/');
                        if (parts.Length < 2) continue;
                        string svc = parts[0];
                        string host = parts[1];

                        List<string> hosts;
                        if (!serviceHosts.TryGetValue(svc, out hosts))
                        {
                            hosts = new List<string>();
                            serviceHosts[svc] = hosts;
                        }
                        if (!hosts.Contains(host)) hosts.Add(host);
                    }

                    // 添加行数据
                    foreach (var kv in serviceHosts)
                    {
                        AdRow row = Col.Row(cols);
                        row.Set("UserName", userName);
                        row.Set("Name", name);
                        row.Set("Service", kv.Key);
                        row.Set("Host", string.Join(",", kv.Value.ToArray()));
                        rows.Add(row);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRComputer] Error while enumerating ComputerSPN Objects");
                Log.Exception("Get-ADRComputer", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("ComputerSPNs", cols, rows)) : null;
        }
    }
}