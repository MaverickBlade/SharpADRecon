// UserModule.cs - 用户、用户SPN和组信息收集模块
// 包含UserFlagDecoder、UsersModule、UserSPNsModule和GroupsModule类。
// 镜像Get-ADRUser和Get-ADRGroup的LDAP路径实现。

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using AdRecon.Ad;
using AdRecon.Core;

namespace AdRecon.Modules
{
    /// <summary>Shared UserAccountControl / Kerberos-encryption flag decoding used by the
    /// Users and UserSPNs modules (LDAPClass port).</summary>
    internal static class UserFlagDecoder
    {
        // UserAccountControl标志常量
        public const int ACCOUNTDISABLE = 2;                 // 0x2
        public const int LOCKOUT = 16;                       // 0x10
        public const int PASSWD_NOTREQD = 32;                // 0x20
        public const int ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128;   // 0x80
        public const int DONT_EXPIRE_PASSWD = 65536;         // 0x10000
        public const int SMARTCARD_REQUIRED = 262144;        // 0x40000
        public const int TRUSTED_FOR_DELEGATION = 524288;    // 0x80000
        public const int NOT_DELEGATED = 1048576;            // 0x100000
        public const int USE_DES_KEY_ONLY = 2097152;         // 0x200000
        public const int DONT_REQUIRE_PREAUTH = 4194304;     // 0x400000
        public const int PASSWORD_EXPIRED = 8388608;         // 0x800000
        public const int TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216; // 0x1000000

        // Kerberos加密类型常量
        public const int RC4_HMAC = 4;
        public const int AES128_CTS_HMAC_SHA1_96 = 8;
        public const int AES256_CTS_HMAC_SHA1_96 = 16;

        // Bit - 检查值中的指定位是否设置
        public static bool Bit(int value, int bit)
        {
            return (value & bit) == bit;
        }

        // SidsFromHistory - 从SID历史记录中提取SID字符串
        public static string SidsFromHistory(object value)
        {
            try
            {
                object[] arr = value as object[];
                if (arr == null)
                {
                    if (value is byte[]) return new SecurityIdentifier((byte[])value, 0).ToString();
                    return "";
                }
                string sids = "";
                for (int i = 0; i < arr.Length; i++)
                {
                    sids = sids + "," + new SecurityIdentifier((byte[])arr[i], 0).ToString();
                }
                return sids.TrimStart(',');
            }
            catch { return ""; }
        }
    }

    /// <summary>Mirror of Get-ADRUser - Users artifact (LDAP path, UserRecordProcessor).</summary>
    public sealed class UsersModule : IReconModule
    {
        public string Name { get { return "Users"; } }

        // Run方法 - 收集用户信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New(
                "UserName", "Name", "Enabled", "Must Change Password at Logon", "Cannot Change Password",
                "Password Never Expires", "Reversible Password Encryption", "Smartcard Logon Required",
                "Delegation Permitted", "Kerberos DES Only", "Kerberos RC4", "Kerberos AES-128bit",
                "Kerberos AES-256bit", "Does Not Require Pre Auth", "Never Logged in", "Logon Age (days)",
                "Password Age (days)", "Dormant (> " + ctx.Config.DormantTimeSpan + " days)",
                "Password Age (> " + ctx.Config.PassMaxAge + " days)",
                "Account Locked Out", "Password Expired", "Password Not Required", "Delegation Type",
                "Delegation Protocol", "Delegation Services", "Logon Workstations", "AdminCount",
                "Primary GroupID", "SID", "SIDHistory", "HasSPN", "Description", "Title", "Department",
                "Company", "Manager", "Info", "Last Logon Date", "Password LastSet",
                "Account Expiration Date", "Account Expiration (days)", "Mobile", "Email", "HomeDirectory",
                "ProfilePath", "ScriptPath", "UserAccountControl", "First Name", "Middle Name", "Last Name",
                "Country", "whenCreated", "whenChanged", "DistinguishedName", "CanonicalName");

            try
            {
                // 获取密码最大年龄并构建LDAP查询
                int passMaxAge = PassMaxAgeFor(ctx);
                string filter = ctx.Config.OnlyEnabled
                    ? "(&(samAccountType=805306368)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
                    : "(samAccountType=805306368)";
                string[] props = new[] {
                    "accountExpires", "admincount", "c", "canonicalname", "company", "department",
                    "description", "distinguishedname", "givenName", "homedirectory", "info",
                    "lastLogontimestamp", "mail", "manager", "memberof", "middleName", "mobile",
                    "msDS-AllowedToDelegateTo", "msDS-SupportedEncryptionTypes", "name",
                    "ntsecuritydescriptor", "objectsid", "primarygroupid", "profilepath", "pwdLastSet",
                    "samaccountname", "scriptpath", "serviceprincipalname", "sidhistory", "sn", "title",
                    "useraccountcontrol", "userworkstations", "whenchanged", "whencreated" };

                // 执行LDAP搜索
                DateTime date = DateTime.Now;
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext, filter, props,
                    SearchScope.Subtree, ctx.Config.PageSize, SecurityMasks.Dacl);

                // 处理搜索结果
                foreach (SearchResult r in results)
                {
                    AdRow row = BuildRow(ctx, r, date, ctx.Config.DormantTimeSpan, passMaxAge);
                    if (row != null)
                    {
                        row.HasSPN = AdSession.GetMultiString(r, "serviceprincipalname").Length > 0;
                        rows.Add(row);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRUser] Error while enumerating User Objects");
                Log.Exception("Get-ADRUser", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("Users", cols, rows)) : null;
        }

        // PassMaxAgeFor - 获取密码最大年龄
        internal static int PassMaxAgeFor(ModuleContext ctx)
        {
            if (ctx.Config.PassMaxAgeSet)
            {
                return ctx.Config.PassMaxAge > 0 ? ctx.Config.PassMaxAge : 90;
            }
            // 回退到默认域密码策略
            try
            {
                using (DirectoryEntry e = ctx.Session.NewEntryWithServer(ctx.Session.DefaultNamingContext))
                {
                    object v = e.Properties["maxpwdage"].Value;
                    long l = 0;
                    if (v == null) return 90;
                    if (v is byte[]) l = BitConverter.ToInt64((byte[])v, 0);
                    else l = Convert.ToInt64(v);
                    int days = (int)(l / -864000000000L);
                    return days > 0 ? days : 90;
                }
            }
            catch { return 90; }
        }

        // BuildRow - 从搜索结果构建用户行数据
        private static AdRow BuildRow(ModuleContext ctx, SearchResult r, DateTime date,
            int dormantTimeSpan, int passMaxAge)
        {
            AdRow row = Col.Row(Col.New("__"));
            int? uac = ReadIntNullable(r, "useraccountcontrol");

            // 解码UserAccountControl标志
            bool? enabled = null, passwordNeverExpires = null, accountLockedOut = null,
                delegationPermitted = null, smartcardRequired = null, reversibleEncryption = null,
                useDesKeyOnly = null, passwordNotRequired = null, passwordExpired = null,
                trustedForDelegation = null, trustedToAuthForDelegation = null, doesNotRequirePreAuth = null;
            if (uac.HasValue)
            {
                int v = uac.Value;
                enabled = !UserFlagDecoder.Bit(v, UserFlagDecoder.ACCOUNTDISABLE);
                passwordNeverExpires = UserFlagDecoder.Bit(v, UserFlagDecoder.DONT_EXPIRE_PASSWD);
                accountLockedOut = UserFlagDecoder.Bit(v, UserFlagDecoder.LOCKOUT);
                delegationPermitted = !UserFlagDecoder.Bit(v, UserFlagDecoder.NOT_DELEGATED);
                smartcardRequired = UserFlagDecoder.Bit(v, UserFlagDecoder.SMARTCARD_REQUIRED);
                reversibleEncryption = UserFlagDecoder.Bit(v, UserFlagDecoder.ENCRYPTED_TEXT_PASSWORD_ALLOWED);
                useDesKeyOnly = UserFlagDecoder.Bit(v, UserFlagDecoder.USE_DES_KEY_ONLY);
                passwordNotRequired = UserFlagDecoder.Bit(v, UserFlagDecoder.PASSWD_NOTREQD);
                passwordExpired = UserFlagDecoder.Bit(v, UserFlagDecoder.PASSWORD_EXPIRED);
                trustedForDelegation = UserFlagDecoder.Bit(v, UserFlagDecoder.TRUSTED_FOR_DELEGATION);
                trustedToAuthForDelegation = UserFlagDecoder.Bit(v, UserFlagDecoder.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION);
                doesNotRequirePreAuth = UserFlagDecoder.Bit(v, UserFlagDecoder.DONT_REQUIRE_PREAUTH);
            }

            // 解码Kerberos加密类型
            bool? kerbRc4 = null, kerbAes128 = null, kerbAes256 = null;
            int? kerbEnc = ReadIntNullable(r, "msds-supportedencryptiontypes");
            if (kerbEnc.HasValue)
            {
                int k = kerbEnc.Value;
                kerbRc4 = UserFlagDecoder.Bit(k, UserFlagDecoder.RC4_HMAC);
                kerbAes128 = UserFlagDecoder.Bit(k, UserFlagDecoder.AES128_CTS_HMAC_SHA1_96);
                kerbAes256 = UserFlagDecoder.Bit(k, UserFlagDecoder.AES256_CTS_HMAC_SHA1_96);
            }

            // 初始化变量
            bool mustChangePasswordAtLogon = false;
            bool cannotChangePassword = false;
            DateTime? lastLogonDate = null;
            DateTime? passwordLastSet = null;
            DateTime? accountExpires = null;
            int? accountExpirationNumOfDays = null;
            int? daysSinceLastLogon = null;
            int? daysSinceLastPasswordChange = null;
            bool passwordNotChangedAfterMaxAge = false;
            bool neverLoggedIn = false;
            bool dormant = false;

            // 检查是否无法更改密码
            cannotChangePassword = DecodeCannotChange(r);

            // 处理最后登录时间
            string lastLogonTs = AdSession.GetString(r, "lastlogontimestamp");
            if (lastLogonTs.Length > 0)
            {
                long l = FromFileTime(lastLogonTs);
                if (l != 0)
                {
                    lastLogonDate = DateTime.FromFileTime(l);
                    daysSinceLastLogon = Math.Abs((int)(date - lastLogonDate.Value).TotalDays);
                    if (daysSinceLastLogon.Value > dormantTimeSpan) dormant = true;
                }
                else neverLoggedIn = true;
            }
            else neverLoggedIn = true;

            // 处理密码最后设置时间
            string pwdLastSet = AdSession.GetString(r, "pwdlastset");
            if (pwdLastSet.Length > 0)
            {
                if (pwdLastSet == "0")
                {
                    if (passwordNeverExpires.HasValue && !passwordNeverExpires.Value)
                        mustChangePasswordAtLogon = true;
                }
                else
                {
                    passwordLastSet = DateTime.FromFileTime(FromFileTime(pwdLastSet));
                    daysSinceLastPasswordChange = Math.Abs((int)(date - passwordLastSet.Value).TotalDays);
                    if (daysSinceLastPasswordChange.Value > passMaxAge)
                        passwordNotChangedAfterMaxAge = true;
                }
            }

            // 处理账户过期时间
            object uacObj = AdSession.GetValue(r, "useraccountcontrol");
            long accountExpiresLong;
            if (TryFromFileTime(AdSession.GetValue(r, "accountexpires"), out accountExpiresLong))
            {
                if (accountExpiresLong != 0 && accountExpiresLong != 9223372036854775807L)
                {
                    try
                    {
                        accountExpires = DateTime.FromFileTime(accountExpiresLong);
                        accountExpirationNumOfDays = (int)(accountExpires.Value - date).TotalDays;
                    }
                    catch { }
                }
            }

            // 处理委派信息
            string delegationType = null, delegationProtocol = null, delegationServices = null;
            if (uacObj != null)
            {
                if (trustedForDelegation.HasValue && trustedForDelegation.Value)
                {
                    delegationType = "Unconstrained";
                    delegationServices = "Any";
                }
                string[] allowedToDelegate = AdSession.GetMultiString(r, "msDS-AllowedToDelegateTo");
                if (allowedToDelegate.Length >= 1)
                {
                    delegationType = "Constrained";
                    string services = delegationServices;
                    for (int i = 0; i < allowedToDelegate.Length; i++)
                        services = services + "," + allowedToDelegate[i];
                    delegationServices = services.TrimStart(',');
                }
                if (trustedToAuthForDelegation.HasValue && trustedToAuthForDelegation.Value)
                    delegationProtocol = "Any";
                else if (delegationType != null)
                    delegationProtocol = "Kerberos";
            }

            // 获取SID历史记录
            string sidHistory = UserFlagDecoder.SidsFromHistory(AdSession.GetValue(r, "sidhistory"));

            // 设置行数据
            SetStr(row, "UserName", AdAttrs.CleanString(AdSession.GetValue(r, "samaccountname")));
            SetStr(row, "Name", AdAttrs.CleanString(AdSession.GetValue(r, "name")));
            SetVal(row, "Enabled", enabled);
            row.Set("Must Change Password at Logon", mustChangePasswordAtLogon);
            row.Set("Cannot Change Password", cannotChangePassword);
            SetVal(row, "Password Never Expires", passwordNeverExpires);
            SetVal(row, "Reversible Password Encryption", reversibleEncryption);
            SetVal(row, "Smartcard Logon Required", smartcardRequired);
            SetVal(row, "Delegation Permitted", delegationPermitted);
            SetVal(row, "Kerberos DES Only", useDesKeyOnly);
            SetVal(row, "Kerberos RC4", kerbRc4);
            SetVal(row, "Kerberos AES-128bit", kerbAes128);
            SetVal(row, "Kerberos AES-256bit", kerbAes256);
            SetVal(row, "Does Not Require Pre Auth", doesNotRequirePreAuth);
            row.Set("Never Logged in", neverLoggedIn);
            SetVal(row, "Logon Age (days)", daysSinceLastLogon);
            SetVal(row, "Password Age (days)", daysSinceLastPasswordChange);
            row.Set("Dormant (> " + dormantTimeSpan + " days)", dormant);
            row.Set("Password Age (> " + passMaxAge + " days)", passwordNotChangedAfterMaxAge);
            SetVal(row, "Account Locked Out", accountLockedOut);
            SetVal(row, "Password Expired", passwordExpired);
            SetVal(row, "Password Not Required", passwordNotRequired);
            SetVal(row, "Delegation Type", delegationType);
            SetVal(row, "Delegation Protocol", delegationProtocol);
            SetVal(row, "Delegation Services", delegationServices);
            SetStr(row, "Logon Workstations", AdSession.GetValue(r, "userworkstations"));
            SetStr(row, "AdminCount", AdSession.GetValue(r, "admincount"));
            SetStr(row, "Primary GroupID", AdSession.GetValue(r, "primarygroupid"));
            SetVal(row, "SID", Sids.HistoryToString(AdSession.GetValue(r, "objectsid")));
            row.Set("SIDHistory", sidHistory);
            bool hasSpn = false;
            if (AdSession.GetMultiString(r, "serviceprincipalname").Length > 0) hasSpn = true;
            row.Set("HasSPN", hasSpn);
            SetStr(row, "Description", AdAttrs.CleanString(AdSession.GetValue(r, "description")));
            SetStr(row, "Title", AdAttrs.CleanString(AdSession.GetValue(r, "title")));
            SetStr(row, "Department", AdAttrs.CleanString(AdSession.GetValue(r, "department")));
            SetStr(row, "Company", AdAttrs.CleanString(AdSession.GetValue(r, "company")));
            SetStr(row, "Manager", AdAttrs.CleanString(AdSession.GetValue(r, "manager")));
            SetStr(row, "Info", AdAttrs.CleanString(AdSession.GetValue(r, "info")));
            SetVal(row, "Last Logon Date", lastLogonDate);
            SetVal(row, "Password LastSet", passwordLastSet);
            SetVal(row, "Account Expiration Date", accountExpires);
            SetVal(row, "Account Expiration (days)", accountExpirationNumOfDays);
            SetStr(row, "Mobile", AdAttrs.CleanString(AdSession.GetValue(r, "mobile")));
            SetStr(row, "Email", AdAttrs.CleanString(AdSession.GetValue(r, "mail")));
            SetStr(row, "HomeDirectory", AdSession.GetValue(r, "homedirectory"));
            SetStr(row, "ProfilePath", AdSession.GetValue(r, "profilepath"));
            SetStr(row, "ScriptPath", AdSession.GetValue(r, "scriptpath"));
            SetStr(row, "UserAccountControl", uacObj);
            SetStr(row, "First Name", AdAttrs.CleanString(AdSession.GetValue(r, "givenname")));
            SetStr(row, "Middle Name", AdAttrs.CleanString(AdSession.GetValue(r, "middlename")));
            SetStr(row, "Last Name", AdAttrs.CleanString(AdSession.GetValue(r, "sn")));
            SetStr(row, "Country", AdAttrs.CleanString(AdSession.GetValue(r, "c")));
            SetVal(row, "whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
            SetVal(row, "whenChanged", AdAttrs.AsDate(AdSession.GetValue(r, "whenchanged")));
            SetStr(row, "DistinguishedName", AdAttrs.CleanString(AdSession.GetValue(r, "distinguishedname")));
            SetStr(row, "CanonicalName", AdAttrs.CleanString(AdSession.GetValue(r, "canonicalname")));
            return row;
        }

        // DecodeCannotChange - 检查用户是否无法更改密码
        internal static bool DecodeCannotChange(SearchResult r)
        {
            try
            {
                object ntsd = AdSession.GetValue(r, "ntsecuritydescriptor");
                if (ntsd == null) return false;
                byte[] binary;
                if (ntsd is byte[]) binary = (byte[])ntsd;
                else binary = null;
                if (binary == null || binary.Length == 0) return false;

                ActiveDirectorySecurity dirObjSec = new ActiveDirectorySecurity();
                dirObjSec.SetSecurityDescriptorBinaryForm(binary);
                System.Security.AccessControl.AuthorizationRuleCollection rules =
                    dirObjSec.GetAccessRules(true, false, typeof(NTAccount));
                bool denyEveryone = false, denySelf = false;
                string changePassGuid = "ab721a53-1e2f-11d0-9819-00aa0040529b";
                foreach (System.DirectoryServices.ActiveDirectoryAccessRule rule in rules)
                {
                    if (rule.ObjectType.ToString().Equals(changePassGuid) &&
                        rule.AccessControlType == System.Security.AccessControl.AccessControlType.Deny)
                    {
                        string o = rule.IdentityReference.ToString();
                        if (o == "Everyone") denyEveryone = true;
                        if (o == "NT AUTHORITY\\SELF") denySelf = true;
                    }
                }
                return denyEveryone && denySelf;
            }
            catch { return false; }
        }

        // ReadIntNullable - 从搜索结果中安全读取整数值
        internal static int? ReadIntNullable(SearchResult r, string name)
        {
            object v = AdSession.GetValue(r, name);
            if (v == null) return null;
            try
            {
                if (v is byte[]) return BitConverter.ToInt32((byte[])v, 0);
                return Convert.ToInt32(v);
            }
            catch { return null; }
        }

        // FromFileTime - 从字符串解析文件时间
        internal static long FromFileTime(string s)
        {
            long l;
            return long.TryParse(s, out l) ? l : 0;
        }

        // TryFromFileTime - 尝试从对象解析文件时间
        internal static bool TryFromFileTime(object v, out long l)
        {
            l = 0;
            if (v == null) return false;
            try
            {
                if (v is byte[]) l = BitConverter.ToInt64((byte[])v, 0);
                else l = Convert.ToInt64(v);
                return true;
            }
            catch { return false; }
        }

        // SetVal - 设置行值
        private static void SetVal(AdRow row, string name, object value)
        {
            row.Set(name, value);
        }

        // SetStr - 设置行字符串值
        private static void SetStr(AdRow row, string name, object value)
        {
            row.Set(name, value == null ? "" : value.ToString());
        }
    }

    /// <summary>SID rendering for byte[] attribute values (objectSID / sidHistory).</summary>
    internal static class Sids
    {
        /// <summary>objectSID is a single byte[]; sidhistory is a multi-valued byte[].
        /// Renders the first value, mirroring the parser's use of Properties[..][0].</summary>
        public static string HistoryToString(object value)
        {
            try
            {
                if (value == null) return "";
                if (value is byte[]) return new SecurityIdentifier((byte[])value, 0).ToString();
                return value.ToString();
            }
            catch { return ""; }
        }
    }

    /// <summary>Mirror of Get-ADRUser - UserSPNs artifact (LDAP path, UserSPNRecordProcessor).</summary>
    public sealed class UserSPNsModule : IReconModule
    {
        public string Name { get { return "UserSPNs"; } }

        // Run方法 - 收集用户SPN信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("UserName", "Name", "Enabled", "Service", "Host", "Password Last Set",
                "Description", "Primary GroupID", "Memberof");
            try
            {
                // 构建LDAP查询
                string filter = ctx.Config.OnlyEnabled
                    ? "(&(samAccountType=805306368)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
                    : "(&(samAccountType=805306368)(servicePrincipalName=*))";
                string[] props = new[] { "name", "description", "memberof", "samaccountname",
                    "serviceprincipalname", "primarygroupid", "pwdlastset", "useraccountcontrol" };
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext, filter, props,
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    // 处理用户属性
                    bool? enabled = null;
                    DateTime? passwordLastSet = null;
                    int? uac = UsersModule.ReadIntNullable(r, "useraccountcontrol");
                    if (uac.HasValue)
                        enabled = !UserFlagDecoder.Bit(uac.Value, UserFlagDecoder.ACCOUNTDISABLE);

                    string pwd = AdSession.GetString(r, "pwdlastset");
                    if (pwd.Length > 0 && pwd != "0")
                        passwordLastSet = DateTime.FromFileTime(UsersModule.FromFileTime(pwd));

                    string description = AdAttrs.CleanString(AdSession.GetValue(r, "description"));
                    string primaryGroupId = AdSession.GetString(r, "primarygroupid");

                    // 处理成员关系
                    string memberof = "";
                    string[] members = AdSession.GetMultiString(r, "memberof");
                    for (int i = 0; i < members.Length; i++)
                    {
                        string m = members[i].Split(',')[0].Split('=')[1];
                        memberof = memberof == "" ? m : memberof + "," + m;
                    }

                    // 处理SPN
                    string[] spns = AdSession.GetMultiString(r, "serviceprincipalname");
                    for (int i = 0; i < spns.Length; i++)
                    {
                        string spn = spns[i];
                        string[] parts = spn.Split('/');
                        if (parts.Length < 2) continue;
                        AdRow row = Col.Row(cols);
                        row.Set("UserName", AdAttrs.CleanString(AdSession.GetValue(r, "samaccountname")));
                        row.Set("Name", AdAttrs.CleanString(AdSession.GetValue(r, "name")));
                        row.Set("Enabled", enabled);
                        row.Set("Service", parts[0]);
                        row.Set("Host", parts[1]);
                        row.Set("Password Last Set", passwordLastSet);
                        row.Set("Description", description);
                        row.Set("Primary GroupID", primaryGroupId);
                        row.Set("Memberof", memberof);
                        rows.Add(row);
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRUser] Error while enumerating UserSPN Objects");
                Log.Exception("Get-ADRUser", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("UserSPNs", cols, rows)) : null;
        }
    }

    /// <summary>Mirror of Get-ADRGroup - Groups artifact (LDAP path, GroupRecordProcessor).</summary>
    public sealed class GroupsModule : IReconModule
    {
        public string Name { get { return "Groups"; } }

        // Run方法 - 收集组信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Name", "AdminCount", "GroupCategory", "GroupScope", "ManagedBy", "SID",
                "SIDHistory", "Description", "whenCreated", "whenChanged", "DistinguishedName", "CanonicalName");
            try
            {
                // 执行LDAP搜索
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext, "(objectClass=group)",
                    new[] { "admincount", "canonicalname", "distinguishedname", "description", "grouptype",
                            "samaccountname", "sidhistory", "managedby", "msds-replvaluemetadata",
                            "objectsid", "whencreated", "whenchanged" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    AdRow row = Col.Row(cols);
                    // 处理托管人信息
                    string managedByValue = AdSession.GetString(r, "managedby");
                    string managedBy = "";
                    if (managedByValue.Length > 0)
                    {
                        string[] byCn = managedByValue.Split(new[] { "CN=" }, StringSplitOptions.RemoveEmptyEntries);
                        if (byCn.Length > 0)
                            managedBy = byCn[0].Split(new[] { "OU=" }, StringSplitOptions.RemoveEmptyEntries)[0].TrimEnd(',');
                    }

                    // 处理组类型和作用域
                    string groupCategory = null, groupScope = null;
                    int? groupType = UsersModule.ReadIntNullable(r, "grouptype");
                    if (groupType.HasValue)
                    {
                        int g = groupType.Value;
                        bool security = (g & unchecked((int)0x80000000)) != 0;
                        groupCategory = security ? "Security" : "Distribution";
                        if ((g & 8) == 8) groupScope = "Universal";
                        else if ((g & 2) == 2) groupScope = "Global";
                        else if ((g & 4) == 4) groupScope = "DomainLocal";
                    }

                    // 处理SID历史记录
                    string sidHistory = UserFlagDecoder.SidsFromHistory(AdSession.GetValue(r, "sidhistory"));

                    // 设置行数据
                    row.Set("Name", AdSession.GetString(r, "samaccountname"));
                    row.Set("AdminCount", AdSession.GetString(r, "admincount"));
                    row.Set("GroupCategory", groupCategory);
                    row.Set("GroupScope", groupScope);
                    row.Set("ManagedBy", managedBy);
                    row.Set("SID", Sids.HistoryToString(AdSession.GetValue(r, "objectsid")));
                    row.Set("SIDHistory", sidHistory);
                    row.Set("Description", AdAttrs.CleanString(AdSession.GetValue(r, "description")));
                    row.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
                    row.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(r, "whenchanged")));
                    row.Set("DistinguishedName", AdAttrs.CleanString(AdSession.GetValue(r, "distinguishedname")));
                    row.Set("CanonicalName", AdSession.GetString(r, "canonicalname"));
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRGroup] Error while enumerating Group Objects");
                Log.Exception("Get-ADRGroup", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("Groups", cols, rows)) : null;
        }
    }
}