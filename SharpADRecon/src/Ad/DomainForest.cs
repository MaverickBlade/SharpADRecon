// DomainForest.cs - Domain and Forest information collection
// Provides methods to retrieve Active Directory domain and forest objects.
// Handles credential passing and fallback to current domain/forest.

using System;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;

namespace AdRecon.Ad
{
    /// <summary>Wraps System.DirectoryServices.ActiveDirectory.Domain/Forest binds,
    /// mirroring the LDAP-method credential handling in ADRecon.</summary>
    // Helper class for domain and forest discovery
    public static class DomainForest
    {
        // Retrieves a Domain object for the specified FQDN, using session credentials
        public static Domain GetDomain(AdSession session, string fqdn)
        {
            string target = (fqdn != null && fqdn.Length > 0) ? fqdn : session.Domain;
            bool useCurrent = session.Username.Length == 0
                && session.DomainController.Length == 0
                && session.Domain.Length == 0
                && (target == null || target.Length == 0);
            if (useCurrent)
                return Domain.GetCurrentDomain();
            if (target == null || target.Length == 0)
                target = session.Domain;
            try
            {
                if (session.Username.Length == 0)
                    return Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, target));
                return Domain.GetDomain(new DirectoryContext(DirectoryContextType.Domain, target,
                    session.Username, session.Password));
            }
            catch
            {
                if (session.Username.Length == 0 && session.Domain.Length == 0) return Domain.GetCurrentDomain();
                throw;
            }
        }

        // Retrieves a Forest object for the specified name, using session credentials
        public static Forest GetForest(AdSession session, string forestName)
        {
            bool useCurrent = session.Username.Length == 0
                && session.DomainController.Length == 0
                && session.Domain.Length == 0
                && (forestName == null || forestName.Length == 0);
            if (useCurrent)
                return Forest.GetCurrentForest();
            string target = (forestName != null && forestName.Length > 0) ? forestName : session.Domain;
            try
            {
                if (session.Username.Length == 0)
                    return Forest.GetForest(new DirectoryContext(DirectoryContextType.Forest, target));
                return Forest.GetForest(new DirectoryContext(DirectoryContextType.Forest, target,
                    session.Username, session.Password));
            }
            catch
            {
                if (session.Username.Length == 0 && session.Domain.Length == 0) return Forest.GetCurrentForest();
                throw;
            }
        }

        /// <summary>Converts an objectSid (byte[]) or string to its S-1-5-... form.</summary>
        // Converts SID from byte array or string to standard string format
        public static string SidToString(object objectSid)
        {
            try
            {
                byte[] b = objectSid as byte[];
                if (b != null && b.Length > 0)
                    return new System.Security.Principal.SecurityIdentifier(b, 0).ToString();
                if (objectSid != null)
                    return objectSid.ToString();
            }
            catch { }
            return "";
        }
    }

    /// <summary>Get-ADRLAPSCheck port: is the ms-Mcs-AdmPwd schema attribute present?</summary>
    // Checks if LAPS (Local Administrator Password Solution) is implemented
    public static class LapsCheck
    {
        // Determines if the LAPS schema attribute exists in the directory
        public static bool IsImplemented(AdSession session)
        {
            // 检查LAPS架构属性是否存在
            try
            {
                if (session.Username.Length == 0)
                {
                    return DirectoryEntry.Exists("LDAP://CN=ms-Mcs-AdmPwd," + session.SchemaNamingContext);
                }
                using (DirectoryEntry e = session.NewEntryWithServer("CN=ms-Mcs-AdmPwd," + session.SchemaNamingContext))
                {
                    return e.Path != null && e.Path.Length > 0;
                }
            }
            catch { return false; }
        }
    }
}