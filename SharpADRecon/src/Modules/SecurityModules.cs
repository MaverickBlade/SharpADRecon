// SecurityModules.cs - 安全模块集合
// 包含LapsModule、BitLockerModule、PasswordAttributesModule、AclsModule、
// KerberoastModule和ServiceLogonModule类。
// 提供安全相关功能的收集，包括LAPS、BitLocker、ACL、Kerberoast等。

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Management;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using AdRecon.Ad;
using AdRecon.Core;

namespace AdRecon.Modules
{
    /// <summary>Mirror of Get-ADRLAPS (LDAP path, LAPSRecordProcessor).</summary>
    public sealed class LapsModule : IReconModule
    {
        public string Name { get { return "LAPS"; } }

        // Run方法 - 收集LAPS信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Hostname", "Enabled", "Stored", "Readable", "Password", "Expiration");
            try
            {
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(samAccountType=805306369)",
                    new[] { "cn", "dnshostname", "ms-mcs-admpwd", "ms-mcs-admpwdexpirationtime", "useraccountcontrol" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    AdRow row = Col.Row(cols);
                    bool? enabled = null;
                    int? uac = UsersModule.ReadIntNullable(r, "useraccountcontrol");
                    if (uac.HasValue)
                        enabled = !UserFlagDecoder.Bit(uac.Value, UserFlagDecoder.ACCOUNTDISABLE);

                    bool passwordStored = false;
                    DateTime? expiration = null;
                    object expObj = AdSession.GetValue(r, "ms-mcs-admpwdexpirationtime");
                    if (expObj != null)
                    {
                        long l;
                        if (UsersModule.TryFromFileTime(expObj, out l) && l != 0)
                        {
                            expiration = DateTime.FromFileTime(l);
                            passwordStored = true;
                        }
                    }

                    string hostname = AdSession.GetString(r, "dnshostname");
                    if (hostname.Length == 0) hostname = AdSession.GetString(r, "cn");

                    row.Set("Hostname", hostname);
                    row.Set("Enabled", enabled);
                    row.Set("Stored", passwordStored);
                    row.Set("Readable", AdSession.GetValue(r, "ms-mcs-admpwd") != null);
                    row.Set("Password", AdSession.GetString(r, "ms-mcs-admpwd"));
                    row.Set("Expiration", expiration);
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRLAPS] Error while enumerating LAPS Objects");
                Log.Exception("Get-ADRLAPS", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("LAPS", cols, rows)) : null;
        }
    }

    /// <summary>Mirror of Get-ADRBitLocker (LDAP path).  Enumerates msFVE-RecoveryInformation
    /// objects and looks up associated computer objects for TPM info.</summary>
    public sealed class BitLockerModule : IReconModule
    {
        public string Name { get { return "BitLocker"; } }

        // Run方法 - 收集BitLocker恢复密钥信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Distinguished Name", "Name", "whenCreated", "Recovery Key ID",
                "Recovery Key", "Volume GUID", "msTPM-OwnerInformation",
                "msTPM-TpmInformationForComputer", "TPM Owner Password");
            try
            {
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(objectClass=msFVE-RecoveryInformation)",
                    new[] { "distinguishedName", "msfve-recoverypassword", "msfve-recoveryguid",
                            "msfve-volumeguid", "name", "whencreated" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    AdRow row = Col.Row(cols);
                    string dn = AdSession.GetString(r, "distinguishedname");
                    // DN format: ...{GUID-RID},CN=... — extract parent computer DN.
                    string computerDN = ExtractComputerDN(dn);

                    row.Set("Distinguished Name", computerDN);
                    row.Set("Name", AdSession.GetString(r, "name"));
                    row.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(r, "whencreated")));
                    row.Set("Recovery Key ID", FormatGuid(AdSession.GetValue(r, "msfve-recoveryguid")));
                    row.Set("Recovery Key", AdSession.GetString(r, "msfve-recoverypassword"));
                    row.Set("Volume GUID", FormatGuid(AdSession.GetValue(r, "msfve-volumeguid")));

                    // Look up computer object for TPM info.
                    string tpmOwner = "", tpmInfo = "", tpmPassword = "";
                    if (computerDN.Length > 0)
                    {
                        try
                        {
                            using (DirectorySearcher cs = ctx.Session.NewSearcher(ctx.Session.DefaultNamingContext,
                                "(&(samAccountType=805306369)(distinguishedName=" + computerDN + "))",
                                new[] { "mstpm-ownerinformation", "mstpm-tpminformationforcomputer" },
                                SearchScope.Subtree, ctx.Config.PageSize))
                            {
                                SearchResultCollection comp = cs.FindAll();
                                try
                                {
                                    if (comp.Count > 0)
                                    {
                                        SearchResult cr = comp[0];
                                        tpmOwner = AdSession.GetString(cr, "mstpm-ownerinformation");
                                        tpmInfo = AdSession.GetString(cr, "mstpm-tpminformationforcomputer");
                                    }
                                }
                                finally { comp.Dispose(); }
                            }
                        }
                        catch { }
                    }
                    row.Set("msTPM-OwnerInformation", tpmOwner);
                    row.Set("msTPM-TpmInformationForComputer", tpmInfo);
                    row.Set("TPM Owner Password", tpmPassword);
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRBitLocker] Error while enumerating BitLocker Recovery Keys");
                Log.Exception("Get-ADRBitLocker", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("BitLocker", cols, rows)) : null;
        }

        private static string ExtractComputerDN(string fullDn)
        {
            // fullDn looks like: CN={GUID-RID},CN=...,CN=Computers,DC=...
            int idx = fullDn.IndexOf("},CN=");
            if (idx < 0) idx = fullDn.IndexOf("},OU=");
            if (idx < 0) return fullDn;
            return fullDn.Substring(idx + 2);
        }

        private static string FormatGuid(object v)
        {
            if (v == null) return "";
            try
            {
                if (v is byte[])
                {
                    Guid g = new Guid((byte[])v);
                    return g.ToString();
                }
                return v.ToString();
            }
            catch { return ""; }
        }
    }

    /// <summary>Mirror of Get-ADRPasswordAttributes (LDAP path).</summary>
    public sealed class PasswordAttributesModule : IReconModule
    {
        public string Name { get { return "PasswordAttributes"; } }

        // Run方法 - 收集密码属性信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("SamAccountName", "DistinguishedName", "UserAccountControl", "Description");
            try
            {
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(|(userAccountControl:1.2.840.113556.1.4.803:=128)(userAccountControl:1.2.840.113556.1.4.803:=32))",
                    new[] { "samaccountname", "distinguishedname", "useraccountcontrol", "description" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    AdRow row = Col.Row(cols);
                    row.Set("SamAccountName", AdAttrs.CleanString(AdSession.GetValue(r, "samaccountname")));
                    row.Set("DistinguishedName", AdAttrs.CleanString(AdSession.GetValue(r, "distinguishedname")));
                    row.Set("UserAccountControl", AdSession.GetString(r, "useraccountcontrol"));
                    row.Set("Description", AdAttrs.CleanString(AdSession.GetValue(r, "description")));
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRPasswordAttributes] Error while enumerating Password Attributes");
                Log.Exception("Get-ADRPasswordAttributes", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("PasswordAttributes", cols, rows)) : null;
        }
    }

    /// <summary>Mirror of Get-ADRAcl - DACL artifact (LDAP path, DACLRecordProcessor).
    /// Builds SID→Name and GUID→Name dictionaries, then parses ntsecuritydescriptor on all
    /// domain/OU/GPO/user/computer/group/container objects.</summary>
    public sealed class AclsModule : IReconModule
    {
        public string Name { get { return "ACLs"; } }

        // DACL和SACL掩码常量
        private const string DACL_MASK = "DACLs";
        private const string SACL_MASK = "SACLs";

        // Run方法 - 收集ACL信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var daclRows = new List<AdRow>();
            var saclRows = new List<AdRow>();
            var daclCols = Col.New("Name", "Type", "ObjectTypeName", "InheritedObjectTypeName",
                "ActiveDirectoryRights", "AccessControlType", "IdentityReferenceName", "OwnerName",
                "Inherited", "ObjectFlags", "InheritanceFlags", "InheritanceType",
                "PropagationFlags", "ObjectType", "InheritedObjectType", "IdentityReference",
                "Owner", "DistinguishedName");
            var saclCols = Col.New("Name", "Type", "ObjectTypeName", "InheritedObjectTypeName",
                "ActiveDirectoryRights", "IdentityReferenceName", "AuditFlags", "ObjectFlags",
                "InheritanceFlags", "InheritanceType", "Inherited", "PropagationFlags",
                "ObjectType", "InheritedObjectType", "IdentityReference", "DistinguishedName");
            try
            {
                AdSession s = ctx.Session;

                // Step 1: Build GUID→Name dictionaries.
                var guids = new Dictionary<string, string>();
                guids["00000000-0000-0000-0000-000000000000"] = "All";                BuildGuidDictionary(s, guids);

                // Step 2: Build SID→Name dictionary.
                var sids = new Dictionary<string, string>();
                BuildSidDictionary(ctx, sids);

                // Step 3: Enumerate domain/OU/GPO/user/computer/group objects with security descriptors.
                var objs = new List<SearchResult>();
                string mainFilter = "(|(objectClass=domain)(objectCategory=organizationalUnit)" +
                    "(objectCategory=groupPolicyContainer)(samAccountType=805306368)" +
                    "(samAccountType=805306369)(samaccounttype=268435456)(samaccounttype=268435457)" +
                    "(samaccounttype=536870912)(samaccounttype=536870913))";
                SecurityMasks secMask = SecurityMasks.Dacl | SecurityMasks.Group |
                    SecurityMasks.Owner | SecurityMasks.Sacl;
                var mainSearch = s.Search(s.DefaultNamingContext, mainFilter,
                    new[] { "displayname", "distinguishedname", "name", "ntsecuritydescriptor",
                            "objectclass", "objectsid" },
                    SearchScope.Subtree, ctx.Config.PageSize, secMask);
                foreach (SearchResult r in mainSearch) objs.Add(r);

                // Containers (root-level OneLevel).
                try
                {
                    var containerSearch = s.Search(s.DefaultNamingContext, "(objectClass=container)",
                        new[] { "distinguishedname", "name", "ntsecuritydescriptor", "objectclass" },
                        SearchScope.OneLevel, ctx.Config.PageSize, secMask);
                    foreach (SearchResult r in containerSearch) objs.Add(r);
                }
                catch { }

                foreach (SearchResult obj in objs)
                {
                    string objName = AdAttrs.CleanString(AdSession.GetValue(obj, "name"));
                    string objType = GetObjectType(obj);
                    if (objType == "GPO") objName = AdAttrs.CleanString(AdSession.GetValue(obj, "displayname"));

                    byte[] ntsd = GetNTSD(obj);
                    if (ntsd == null) continue;

                    try
                    {
                        ActiveDirectorySecurity sec = new ActiveDirectorySecurity();
                        sec.SetSecurityDescriptorBinaryForm(ntsd);

                        // DACLs.
                        try
                        {
                            AuthorizationRuleCollection accessRules = sec.GetAccessRules(true, true, typeof(NTAccount));
                            foreach (ActiveDirectoryAccessRule rule in accessRules)
                            {
                                string identRef = rule.IdentityReference.ToString();
                                string owner = sec.GetOwner(typeof(SecurityIdentifier)).ToString();
                                AdRow row = Col.Row(daclCols);
                                row.Set("Name", objName);
                                row.Set("Type", objType);
                                row.Set("ObjectTypeName", ResolveGuid(guids, rule.ObjectType.ToString()));
                                row.Set("InheritedObjectTypeName", ResolveGuid(guids, rule.InheritedObjectType.ToString()));
                                row.Set("ActiveDirectoryRights", rule.ActiveDirectoryRights.ToString());
                                row.Set("AccessControlType", rule.AccessControlType.ToString());
                                row.Set("IdentityReferenceName", ResolveSid(sids, identRef));
                                row.Set("OwnerName", ResolveSid(sids, owner));
                                row.Set("Inherited", rule.IsInherited);
                                row.Set("ObjectFlags", rule.ObjectFlags.ToString());
                                row.Set("InheritanceFlags", rule.InheritanceFlags.ToString());
                                row.Set("InheritanceType", rule.InheritanceType.ToString());
                                row.Set("PropagationFlags", rule.PropagationFlags.ToString());
                                row.Set("ObjectType", rule.ObjectType);
                                row.Set("InheritedObjectType", rule.InheritedObjectType);
                                row.Set("IdentityReference", rule.IdentityReference.ToString());
                                row.Set("Owner", owner);
                                row.Set("DistinguishedName", AdSession.GetString(obj, "distinguishedname"));
                                daclRows.Add(row);
                            }
                        }
                        catch { }

                        // SACLs.
                        try
                        {
                            AuthorizationRuleCollection auditRules = sec.GetAuditRules(true, true, typeof(NTAccount));
                            foreach (ActiveDirectoryAuditRule rule in auditRules)
                            {
                                string identRef = rule.IdentityReference.ToString();
                                AdRow row = Col.Row(saclCols);
                                row.Set("Name", objName);
                                row.Set("Type", objType);
                                row.Set("ObjectTypeName", ResolveGuid(guids, rule.ObjectType.ToString()));
                                row.Set("InheritedObjectTypeName", ResolveGuid(guids, rule.InheritedObjectType.ToString()));
                                row.Set("ActiveDirectoryRights", rule.ActiveDirectoryRights.ToString());
                                row.Set("IdentityReferenceName", ResolveSid(sids, identRef));
                                row.Set("AuditFlags", rule.AuditFlags.ToString());
                                row.Set("ObjectFlags", rule.ObjectFlags.ToString());
                                row.Set("InheritanceFlags", rule.InheritanceFlags.ToString());
                                row.Set("InheritanceType", rule.InheritanceType.ToString());
                                row.Set("Inherited", rule.IsInherited);
                                row.Set("PropagationFlags", rule.PropagationFlags.ToString());
                                row.Set("ObjectType", rule.ObjectType);
                                row.Set("InheritedObjectType", rule.InheritedObjectType);
                                row.Set("IdentityReference", rule.IdentityReference.ToString());
                                row.Set("DistinguishedName", AdSession.GetString(obj, "distinguishedname"));
                                saclRows.Add(row);
                            }
                        }
                        catch { }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRAcl] Error while enumerating ACL Objects");
                Log.Exception("Get-ADRAcl", ex);
                return null;
            }

            var results = new List<ModuleResult>();
            if (daclRows.Count > 0)
                results.Add(new ModuleResult(DACL_MASK, daclCols, daclRows));
            if (saclRows.Count > 0)
                results.Add(new ModuleResult(SACL_MASK, saclCols, saclRows));
            return results.Count > 0 ? results : null;
        }

        private static void BuildGuidDictionary(AdSession s, Dictionary<string, string> guids)
        {
            // Schema GUIDs.
            try
            {
                string schemaNC = s.SchemaNamingContext;
                var schemaSearch = s.Search(schemaNC, "(schemaIDGUID=*)",
                    new[] { "schemaidguid", "name" }, SearchScope.OneLevel, 200);
                foreach (SearchResult r in schemaSearch)
                {
                    try
                    {
                        object v = AdSession.GetValue(r, "schemaidguid");
                        if (v is byte[])
                        {
                            Guid g = new Guid((byte[])v);
                            string k = g.ToString().Trim('{', '}');
                            guids[k.ToLower()] = AdSession.GetString(r, "name");
                        }
                    }
                    catch { }
                }
            }
            catch { }

            // Extended Rights (controlAccessRight).
            try
            {
                string extRightsDN = s.SchemaNamingContext.Replace("Schema", "Extended-Rights");
                var rightsSearch = s.Search(extRightsDN, "(objectClass=controlAccessRight)",
                    new[] { "rightsguid", "name" }, SearchScope.Subtree, 200);
                foreach (SearchResult r in rightsSearch)
                {
                    try
                    {
                        string rg = AdSession.GetString(r, "rightsguid").Trim('{', '}').ToLower();
                        string nm = AdSession.GetString(r, "name");
                        if (rg.Length > 0 && !guids.ContainsKey(rg)) guids[rg] = nm;
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static void BuildSidDictionary(ModuleContext ctx, Dictionary<string, string> sids)
        {
            try
            {
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(|(objectclass=user)(objectclass=computer)(objectclass=group))",
                    new[] { "objectsid", "name", "objectclass" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                {
                    try
                    {
                        string oc = "";
                        string[] ocArr = AdSession.GetMultiString(r, "objectclass");
                        if (ocArr.Length > 0) oc = ocArr[ocArr.Length - 1];
                        if (oc != "user" && oc != "computer" && oc != "group") continue;
                        object sidObj = AdSession.GetValue(r, "objectsid");
                        if (sidObj is byte[])
                        {
                            string sid = new SecurityIdentifier((byte[])sidObj, 0).ToString();
                            string name = AdSession.GetString(r, "name");
                            if (!sids.ContainsKey(sid)) sids[sid] = name;
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static string GetObjectType(SearchResult r)
        {
            string[] oc = AdSession.GetMultiString(r, "objectclass");
            if (oc.Length == 0) return "Unknown";
            string last = oc[oc.Length - 1];
            switch (last)
            {
                case "user": return "User";
                case "computer": return "Computer";
                case "group": return "Group";
                case "container": return "Container";
                case "groupPolicyContainer": return "GPO";
                case "organizationalUnit": return "OU";
                case "domainDNS": return "Domain";
                default: return last;
            }
        }

        private static byte[] GetNTSD(SearchResult r)
        {
            object v = AdSession.GetValue(r, "ntsecuritydescriptor");
            if (v is byte[]) return (byte[])v;
            try
            {
                DirectoryEntry de = r.GetDirectoryEntry();
                return (byte[])de.ObjectSecurity.GetSecurityDescriptorBinaryForm();
            }
            catch { return null; }
        }

        private static string ResolveGuid(Dictionary<string, string> guids, string key)
        {
            if (key == null || key.Length == 0) return "";
            string name;
            if (guids.TryGetValue(key.Trim('{', '}').ToLower(), out name)) return name;
            return key;
        }

        private static string ResolveSid(Dictionary<string, string> sids, string sidOrName)
        {
            string name;
            if (sids.TryGetValue(sidOrName, out name)) return name;
            return sidOrName;
        }
    }

    /// <summary>Mirror of Get-ADRKerberoast (LDAP path).  For every user with an SPN, a
    /// Kerberos TGS is requested via System.IdentityModel.KerberosRequestorSecurityToken
    /// and the embedded ticket ciphertext is spliced into hashcat/JtR lines, exactly like
    /// the original Get-ADRSPNTicket.</summary>
    public sealed class KerberoastModule : IReconModule
    {
        public string Name { get { return "Kerberoast"; } }

        // Run方法 - 收集Kerberoast信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var cols = Col.New("Username", "ServicePrincipalName", "John", "Hashcat");
            var rows = new List<AdRow>();
            List<SearchResult> results;

            try
            {
                var found = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(&(!objectClass=computer)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))",
                    new[] { "distinguishedname", "samaccountname", "serviceprincipalname" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                results = new List<SearchResult>();
                foreach (SearchResult s in found) results.Add(s);
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRKerberoast] Error while enumerating UserSPN Objects");
                Log.Exception("Get-ADRKerberoast", ex);
                return null;
            }

            if (results.Count == 0)
                return null;

            // "runas /netonly" impersonation so TGS requests run as the alternate account.
            IntPtr token = IntPtr.Zero;
            bool impersonated = false;
            if (ctx.Session.Username.Length > 0)
            {
                try
                {
                    impersonated = Impersonate(ctx.Session.Username, ctx.Session.Password, ref token);
                    Log.Notice("Alternate credentials impersonated for TGS requests");
                }
                catch (Exception ex)
                {
                    Log.Warning("[Get-ADRKerberoast] LogonUser() Error: " + ex.Message + " - continuing with current token");
                }
            }

            try
            {
                foreach (SearchResult r in results)
                {
                    string sam = AdSession.GetString(r, "samaccountname");
                    if (sam.Length == 0) continue;

                    string dn = AdSession.GetString(r, "distinguishedname");
                    string userDomain = "";
                    int dcIdx = dn.IndexOf("DC=", StringComparison.OrdinalIgnoreCase);
                    if (dcIdx >= 0)
                        userDomain = dn.Substring(dcIdx).Replace("DC=", "").Replace(",", ".");

                    foreach (string spn in AdSession.GetMultiString(r, "serviceprincipalname"))
                    {
                        TicketResult h = GetSPNTicket(spn);
                        AdRow row = Col.Row(cols);
                        row.Set("Username", sam);
                        row.Set("ServicePrincipalName", spn);
                        // John the Ripper format: $krb5tgs$SPN:hash
                        if (h.Hash != null)
                            row.Set("John", "$krb5tgs$" + spn + ":" + h.Hash);
                        // hashcat format: $krb5tgs$etype$*user$domain$SPN*$hash
                        if (h.Hash != null && h.Etype >= 0)
                            row.Set("Hashcat", "$krb5tgs$" + h.Etype + "$*" + sam + "$" + userDomain + "$" + spn + "*$" + h.Hash);
                        rows.Add(row);
                    }
                }
            }
            finally
            {
                if (impersonated)
                    RevertToSelfAndClose(token);
            }

            return rows.Count > 0 ? Clr.Of(new ModuleResult("Kerberoast", cols, rows)) : null;
        }

        /// <summary>Port of Get-ADRSPNTicket: request a TGS for the SPN and regex-splice the
        /// GSS-API frame to extract the embedded ticket ciphertext (hashcat-compatible blob)
        /// and the encryption type.</summary>
        private static TicketResult GetSPNTicket(string spn)
        {
            var result = new TicketResult { Etype = -1, Hash = null };
            try
            {
                var token = new System.IdentityModel.Tokens.KerberosRequestorSecurityToken(spn);
                byte[] req = token.GetRequest();
                if (req == null || req.Length == 0)
                    return result;

                string hex = BitConverter.ToString(req).Replace("-", "");
                Match m = Regex.Match(hex,
                    "a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)");
                if (!m.Success)
                {
                    Log.Warning("[Get-ADRSPNTicket] Unable to parse ticket structure for the SPN " + spn);
                    return result;
                }

                result.Etype = Convert.ToByte(m.Groups["EtypeLen"].Value, 16);
                int cipherTextLen = (int)Convert.ToUInt32(m.Groups["CipherTextLen"].Value, 16) - 4;
                string dataToEnd = m.Groups["DataToEnd"].Value;

                if (cipherTextLen > 0 && (cipherTextLen * 2 + 4) <= dataToEnd.Length &&
                    dataToEnd.Substring(cipherTextLen * 2, 4) == "A482")
                {
                    string cipher = dataToEnd.Substring(0, cipherTextLen * 2);
                    result.Hash = cipher.Substring(0, 32) + "$" + cipher.Substring(32);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRSPNTicket] Error requesting ticket for SPN " + spn);
                Log.Exception("Get-ADRSPNTicket", ex);
            }
            return result;
        }

        private sealed class TicketResult
        {
            public int Etype;
            public string Hash;
        }

        /// <summary>Get-ADRUserImpersonation port: LogonUser with LOGON32_LOGON_NEW_CREDENTIALS
        /// (runas /netonly) then ImpersonateLoggedOnUser.</summary>
        private static bool Impersonate(string username, string password, ref IntPtr token)
        {
            string domain = "";
            string user = username;
            int idx = username.IndexOf('\\');
            if (idx >= 0)
            {
                domain = username.Substring(0, idx);
                user = username.Substring(idx + 1);
            }

            IntPtr h;
            // LOGON32_LOGON_NEW_CREDENTIALS = 9, LOGON32_PROVIDER_WINNT50 = 3
            if (!Native.LogonUser(user, domain, password, 9, 3, out h))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                if (!Native.ImpersonateLoggedOnUser(h))
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            catch
            {
                Native.CloseHandle(h);
                throw;
            }
            token = h;
            return true;
        }

        private static void RevertToSelfAndClose(IntPtr token)
        {
            try { Native.RevertToSelf(); } catch { }
            try { if (token != IntPtr.Zero) Native.CloseHandle(token); } catch { }
        }

        private static class Native
        {
            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool LogonUser(string lpszUsername, string lpszDomain,
                string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool RevertToSelf();

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool CloseHandle(IntPtr hObject);
        }
    }

    /// <summary>Mirror of Get-ADRDomainAccountsUsedForServiceLogon (LDAP path).
    /// Enumerates enabled Windows computer objects, probes each host on TCP 135 and
    /// queries Win32_Service over DCOM/WMI (Get-CimInstance equivalent), reporting any
    /// service whose StartName belongs to a domain account.</summary>
    public sealed class ServiceLogonModule : IReconModule
    {
        public string Name { get { return "DomainAccountsUsedForServiceLogon"; } }

        // Run方法 - 收集服务登录域账户信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var cols = Col.New("Account", "Service Name", "SystemName", "Running as Domain User");
            var rows = new List<AdRow>();

            // The original checks StartName.ToUpper().Contains(<domain name>). Use the
            // domain object's first DNS label (e.g. acme.local -> ACME), upper-cased.
            string currentDomain = "";
            try
            {
                string fqdn = AdAttrs.DnToFqdn(ctx.Session.DefaultNamingContext);
                int dot = fqdn.IndexOf('.');
                currentDomain = (dot >= 0 ? fqdn.Substring(0, dot) : fqdn).ToUpperInvariant();
            }
            catch { }

            var hosts = new List<SearchResult>();
            try
            {
                var results = ctx.Session.Search(ctx.Session.DefaultNamingContext,
                    "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2)(operatingSystem=*Windows*))",
                    new[] { "name", "dnshostname", "operatingsystem" },
                    SearchScope.Subtree, ctx.Config.PageSize);
                foreach (SearchResult r in results)
                    hosts.Add(r);
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRDomainAccountsUsedForServiceLogon] Error while enumerating Windows Computer Objects");
                Log.Exception("Get-ADRDomainAccountsUsedForServiceLogon", ex);
                return null;
            }

            if (hosts.Count == 0)
                return null;

            int maxThreads = Math.Max(1, ctx.Config.Threads);
            using (var sem = new SemaphoreSlim(maxThreads))
            {
                var tasks = new List<Task>();
                foreach (SearchResult host in hosts)
                {
                    string hostname = AdSession.GetString(host, "dnshostname");
                    if (hostname.Length == 0) continue;
                    string h = hostname;
                    tasks.Add(Task.Run(delegate
                    {
                        sem.Wait();
                        try
                        {
                            List<ServiceInfo> services = QueryHost(h, ctx.Session.Username, ctx.Session.Password);
                            lock (rows)
                            {
                                foreach (ServiceInfo s in services)
                                {
                                    if (string.IsNullOrEmpty(s.StartName)) continue;
                                    AdRow row = Col.Row(cols);
                                    row.Set("Account", s.StartName);
                                    row.Set("Service Name", s.Name);
                                    row.Set("SystemName", s.SystemName);
                                    row.Set("Running as Domain User",
                                        currentDomain.Length > 0 &&
                                        s.StartName.ToUpperInvariant().Contains(currentDomain));
                                    rows.Add(row);
                                }
                            }
                        }
                        finally { sem.Release(); }
                    }));
                }
                try { Task.WaitAll(tasks.ToArray(), TimeSpan.FromSeconds(300)); }
                catch (AggregateException) { }
            }

            return rows.Count > 0 ? Clr.Of(new ModuleResult("DomainAccountsUsedForServiceLogon", cols, rows)) : null;
        }

        private static List<ServiceInfo> QueryHost(string hostname, string user, string pass)
        {
            var list = new List<ServiceInfo>();
            if (!PortOpen(hostname, 135)) return list;
            try
            {
                var options = new ConnectionOptions();
                options.Impersonation = ImpersonationLevel.Impersonate;
                options.Timeout = TimeSpan.FromSeconds(30);
                if (user.Length > 0)
                {
                    options.Username = user;
                    options.Password = pass;
                }
                var scope = new ManagementScope(@"\\" + hostname + @"\root\cimv2", options);
                scope.Connect();
                var query = new ObjectQuery("SELECT Name, StartName, SystemName FROM Win32_Service");
                using (ManagementObjectCollection col = new ManagementObjectSearcher(scope, query).Get())
                {
                    foreach (ManagementBaseObject o in col)
                    {
                        try
                        {
                            var si = new ServiceInfo();
                            si.Name = Property(o, "Name");
                            si.StartName = Property(o, "StartName");
                            si.SystemName = Property(o, "SystemName");
                            list.Add(si);
                        }
                        finally { o.Dispose(); }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Exception(hostname, ex);
            }
            return list;
        }

        private static string Property(ManagementBaseObject o, string name)
        {
            try
            {
                object v = o[name];
                return v == null ? "" : Convert.ToString(v);
            }
            catch { return ""; }
        }

        private static bool PortOpen(string host, int port)
        {
            var client = new TcpClient();
            try
            {
                IAsyncResult ar = client.BeginConnect(host, port, null, null);
                bool ok = ar.AsyncWaitHandle.WaitOne(250, false) && client.Connected;
                if (ok)
                {
                    client.EndConnect(ar);
                    return true;
                }
                return false;
            }
            catch { return false; }
            finally { client.Close(); }
        }

        private sealed class ServiceInfo
        {
            public string Name;
            public string StartName;
            public string SystemName;
        }
    }
}