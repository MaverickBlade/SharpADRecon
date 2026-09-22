using System;

// AdReconEnums.cs - Enumeration types for AdRecon.NET
// Defines all enums used across the codebase: collection method, output formats, and module flags.

namespace AdRecon.Core
{
    /// <summary>Collection method. ADWS mirrors the RSAT/ActiveDirectory-module path;
    /// LDAP uses raw DirectoryEntry/DirectorySearcher. This port implements the LDAP path
    /// natively (execute-assembly friendly) and keeps Method only for output parity.</summary>
    public enum ReconMethod
    {
        ADWS = 0,
        LDAP = 1
    }

    /// <summary>Output formats, mirroring the ADRecon -OutputType switch.</summary>
    [Flags]
    public enum OutputTypeFlag
    {
        None = 0,
        STDOUT = 1,
        CSV = 2,
        XML = 4,
        JSON = 8,
        HTML = 16,
        Excel = 32
    }

    /// <summary>Collection modules; mirror of ADRecon's -Collect valid values.
    /// Each flag represents a distinct recon module that can be toggled independently.</summary>
    [Flags]
    public enum Modules
    {
        None = 0,

        // Forest and domain level modules
        Forest = 1 << 0,
        Domain = 1 << 1,
        Trusts = 1 << 2,
        Sites = 1 << 3,
        Subnets = 1 << 4,
        SchemaHistory = 1 << 5,

        // Policy modules
        PasswordPolicy = 1 << 6,
        FineGrainedPasswordPolicy = 1 << 7,

        // Infrastructure modules
        DomainControllers = 1 << 8,

        // User-related modules
        Users = 1 << 9,
        UserSPNs = 1 << 10,
        PasswordAttributes = 1 << 11,

        // Group-related modules
        Groups = 1 << 12,
        GroupChanges = 1 << 13,
        GroupMembers = 1 << 14,

        // OU and GPO modules
        OUs = 1 << 15,
        GPOs = 1 << 16,
        GPLinks = 1 << 17,

        // DNS modules
        DNSZones = 1 << 18,
        DNSRecords = 1 << 19,

        // Computer and device modules
        Printers = 1 << 20,
        Computers = 1 << 21,
        ComputerSPNs = 1 << 22,

        // Security and compliance modules
        LAPS = 1 << 23,
        BitLocker = 1 << 24,
        ACLs = 1 << 25,

        // Reporting and attack-simulation modules
        GPOReport = 1 << 26,
        Kerberoast = 1 << 27,
        DomainAccountsUsedForServiceLogon = 1 << 28
    }

    // ModuleDefaults - 默认模块集合
    // Provides the default set of modules used when -Collect is not specified.
    public static class ModuleDefaults
    {
        /// <summary>The ADRecon "Default" -Collect set: everything except ACLs,
        /// Kerberoast and DomainAccountsUsedForServiceLogon; GPOReport included.</summary>
        public static Modules DefaultSet
        {
            get
            {
                Modules all = 0;
                foreach (object m in Enum.GetValues(typeof(Modules)))
                {
                    int v = (int)m;
                    if (v > 0) all |= (Modules)m;
                }
                // Excluded from default per ADRecon (commented out in Invoke-ADRecon).
                all &= ~Modules.ACLs;
                all &= ~Modules.Kerberoast;
                all &= ~Modules.DomainAccountsUsedForServiceLogon;
                return all;
            }
        }
    }
}