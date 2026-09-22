// AdSession.cs - LDAP connection and search wrapper
// Provides a managed wrapper around System.DirectoryServices for Active Directory queries.
// Handles binding, paged searches, and property extraction with proper resource cleanup.

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using AdRecon.Core;

namespace AdRecon.Ad
{
    /// <summary>Binds to a directory and provides paged LDAP queries over
    /// System.DirectoryServices (the LDAP-method equivalent of ADRecon's
    /// $objDomain / DirectorySearcher usage). Execute-assembly friendly.</summary>
    public sealed class AdSession : IDisposable
    {
        // Connection credentials and target server / domain
        public string Domain { get; private set; }
        public string DomainController { get; private set; }
        public string Username { get; private set; }
        public string Password { get; private set; }

        // Root directory entry for the session
        public DirectoryEntry Root { get; private set; }

        // Naming contexts retrieved from RootDSE (DefaultNamingContext may be overridden by -Domain)
        public string DefaultNamingContext { get; private set; }
        public string ConfigurationNamingContext { get; private set; }
        public string SchemaNamingContext { get; private set; }
        public string RootDomainNamingContext { get; private set; }
        public string Fqdn { get; private set; }
        public string DomainSid { get; private set; }

        // Connection state flag
        public bool Connected { get; private set; }

        public AdSession(string domain, string domainController, string username, string password)
        {
            Domain = domain ?? "";
            DomainController = domainController ?? "";
            Username = username ?? "";
            Password = password ?? "";
        }

        /// <summary>Performs the initial bind and populates naming contexts from RootDSE.
        /// When -Domain is set, DefaultNamingContext is forced to that domain's DN so
        /// modules do not silently collect against the joined / DC-default domain.</summary>
        public bool Connect()
        {
            try
            {
                string bindHost = ResolveBindHost();
                if (bindHost.Length == 0)
                    Root = NewEntry("LDAP://RootDSE");
                else
                    Root = NewEntry("LDAP://" + bindHost);

                DirectoryEntry rootDse = FindRootDse(bindHost);
                try
                {
                    string rootDefaultNc = GetString(rootDse, "defaultNamingContext");
                    ConfigurationNamingContext = GetString(rootDse, "configurationNamingContext");
                    SchemaNamingContext = GetString(rootDse, "schemaNamingContext");
                    RootDomainNamingContext = GetString(rootDse, "rootDomainNamingContext");
                    Fqdn = GetString(rootDse, "dnsHostName");

                    string requestedDn = AdAttrs.FqdnToDn(Domain);
                    if (requestedDn.Length > 0)
                    {
                        DefaultNamingContext = requestedDn;
                        if (rootDefaultNc.Length > 0 &&
                            !string.Equals(rootDefaultNc, requestedDn, StringComparison.OrdinalIgnoreCase))
                        {
                            Log.Notice("Target domain NC=" + requestedDn
                                + " (RootDSE defaultNamingContext was " + rootDefaultNc + ")");
                        }
                        else
                        {
                            Log.Notice("Target domain NC=" + requestedDn);
                        }
                    }
                    else
                    {
                        DefaultNamingContext = rootDefaultNc;
                    }

                    if (DefaultNamingContext.Length == 0)
                    {
                        Log.Warning("LDAP bind succeeded but no defaultNamingContext; pass -Domain <fqdn>");
                        Connected = false;
                        return false;
                    }

                    Connected = true;
                }
                finally
                {
                    rootDse.Dispose();
                }
            }
            catch (Exception ex)
            {
                Log.Warning("LDAP bind failed: " + ex.Message);
                Connected = false;
                return false;
            }
            return Connected;
        }

        /// <summary>Prefer explicit DC; else use -Domain as LDAP host (DNS resolves to a DC).</summary>
        public string BindHost
        {
            get { return ResolveBindHost(); }
        }

        private string ResolveBindHost()
        {
            if (DomainController.Length > 0) return DomainController;
            if (Domain.Length > 0) return Domain;
            return "";
        }

        private DirectoryEntry FindRootDse(string bindHost)
        {
            DirectoryEntry e;
            if (bindHost.Length == 0)
                e = NewEntry("LDAP://RootDSE");
            else
                e = NewEntry("LDAP://" + bindHost + "/RootDSE");
            // Touch to force bind.
            object n = e.Properties["defaultNamingContext"].Value;
            return e;
        }

        public DirectoryEntry NewEntry(string path)
        {
            if (Username.Length == 0)
                return new DirectoryEntry(path);
            return new DirectoryEntry(path, Username, Password);
        }

        public DirectoryEntry NewEntryWithServer(string dn)
        {
            string host = ResolveBindHost();
            if (host.Length == 0) return NewEntry("LDAP://" + dn);
            return NewEntry("LDAP://" + host + "/" + dn);
        }

        /// <summary>Runs a paged, disposed DirectorySearcher over the given base DN.
        /// Scope Control: Subtree unless specified.</summary>
        public IEnumerable<SearchResult> Search(string baseDn, string filter, string[] properties,
            SearchScope scope, int pageSize)
        {
            List<SearchResult> results = new List<SearchResult>();
            DirectorySearcher searcher = null;
            try
            {
                searcher = NewSearcher(baseDn, filter, properties, scope, pageSize);
                SearchResultCollection col = searcher.FindAll();
                try
                {
                    foreach (SearchResult r in col)
                        results.Add(r);
                }
                finally { col.Dispose(); }
            }
            finally
            {
                if (searcher != null) searcher.Dispose();
            }
            return results;
        }

        public DirectorySearcher NewSearcher(string baseDn, string filter, string[] properties,
            SearchScope scope, int pageSize)
        {
            DirectorySearcher s = new DirectorySearcher(NewEntryWithServer(baseDn));
            s.Filter = filter;
            s.PageSize = pageSize;
            s.SearchScope = scope;
            if (properties != null)
                foreach (string p in properties) s.PropertiesToLoad.Add(p);
            return s;
        }

        /// <summary>Search variant that also requests DACL/SACL security descriptors
        /// (required by the Users module's CannotChangePassword check).</summary>
        public IEnumerable<SearchResult> Search(string baseDn, string filter, string[] properties,
            SearchScope scope, int pageSize, SecurityMasks masks)
        {
            List<SearchResult> results = new List<SearchResult>();
            DirectorySearcher searcher = null;
            try
            {
                searcher = NewSearcher(baseDn, filter, properties, scope, pageSize);
                searcher.SecurityMasks = masks;
                SearchResultCollection col = searcher.FindAll();
                try
                {
                    foreach (SearchResult r in col)
                        results.Add(r);
                }
                finally { col.Dispose(); }
            }
            finally
            {
                if (searcher != null) searcher.Dispose();
            }
            return results;
        }

        public static string GetString(DirectoryEntry e, string name)
        {
            try
            {
                object v = e.Properties[name].Value;
                if (v == null) return "";
                return v.ToString();
            }
            catch { return ""; }
        }

        public static string GetString(SearchResult r, string name)
        {
            try
            {
                ResultPropertyValueCollection c = r.Properties[name];
                if (c == null || c.Count == 0) return "";
                return c[0].ToString();
            }
            catch { return ""; }
        }

        public static string[] GetMultiString(SearchResult r, string name)
        {
            try
            {
                ResultPropertyValueCollection c = r.Properties[name];
                if (c == null || c.Count == 0) return new string[0];
                string[] outArr = new string[c.Count];
                for (int i = 0; i < c.Count; i++) outArr[i] = c[i].ToString();
                return outArr;
            }
            catch { return new string[0]; }
        }

        public static object GetValue(SearchResult r, string name)
        {
            try
            {
                ResultPropertyValueCollection c = r.Properties[name];
                if (c == null || c.Count == 0) return null;
                return c[0];
            }
            catch { return null; }
        }

        public void Dispose()
        {
            if (Root != null) { try { Root.Dispose(); } catch { } Root = null; }
        }
    }
}
