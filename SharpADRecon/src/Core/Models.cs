using System;
using System.Collections.Generic;
using System.DirectoryServices;
using AdRecon.Ad;
using AdRecon.Core;

// Models.cs - Core data models for AdRecon.NET
// Defines the fundamental types used throughout the recon pipeline:
// AdRow (single row of output), ModuleResult (full module output),
// ModuleContext (shared runtime context), and IReconModule (module interface).

namespace AdRecon
{
    /// <summary>A single row of module output: an ordered column set shared by the module
    /// result plus a property bag - the .NET analog of a PSObject with note-properties.</summary>
    public sealed class AdRow
    {
        // Ordered column names (shared across all rows in a module result)
        public readonly List<string> Columns;
        // Key-value store for cell values
        public readonly Dictionary<string, object> Values;
        // Flag indicating this row has an associated SPN
        public bool HasSPN;

        // Constructor with empty values dictionary
        public AdRow(List<string> columns)
        {
            Columns = columns;
            Values = new Dictionary<string, object>(StringComparer.Ordinal);
        }

        // Constructor with pre-populated values
        public AdRow(List<string> columns, Dictionary<string, object> values)
        {
            Columns = columns;
            Values = values;
        }

        // Sets a value by column name (null becomes empty string)
        public void Set(string name, object value)
        {
            Values[name] = value ?? "";
        }

        // Sets a value only if it's non-null and non-empty
        public void SetIfNotEmpty(string name, object value)
        {
            if (value != null && value.ToString().Length > 0)
                Values[name] = value;
        }

        // Gets a value by column name, returns empty string if missing
        public object Get(string name)
        {
            object v;
            if (Values.TryGetValue(name, out v)) return v;
            return "";
        }

        // Convenience getter returning the value as a string
        public string GetString(string name)
        {
            return Convert.ToString(Get(name));
        }

        /// <summary>Compatible with AdRow clone for parallel processing - copies columns
        /// reference and all values.</summary>
        public AdRow Clone()
        {
            var v = new Dictionary<string, object>(Values, StringComparer.Ordinal);
            return new AdRow(Columns, v) { HasSPN = HasSPN };
        }
    }

    /// <summary>Output of one module: name used as export file stem + rows with a fixed
    /// column order (the CSV header schema).</summary>
    public sealed class ModuleResult
    {
        public string ModuleName;      // file stem, e.g. "Users", "DACLs", "Domain"
        public List<string> Columns;   // ordered column names for CSV header
        public List<AdRow> Rows;       // collected data rows

        public ModuleResult(string moduleName, List<string> columns, List<AdRow> rows)
        {
            ModuleName = moduleName;
            Columns = columns;
            Rows = rows;
        }

        // Creates an empty result (useful when a module has no data)
        public static ModuleResult Empty(string moduleName)
        {
            return new ModuleResult(moduleName, new List<string>(), new List<AdRow>());
        }
    }

    /// <summary>Context handed to every module: config, session, output location.</summary>
    public sealed class ModuleContext
    {
        public AdReconConfig Config;   // parsed command-line configuration
        public AdSession Session;      // active LDAP session
        public string OutputDir;       // root output directory
        public bool AnyFileOutputs;    // true if any file-based output is enabled

        public ModuleContext(AdReconConfig config, AdSession session, string outputDir, bool anyFileOutputs)
        {
            Config = config;
            Session = session;
            OutputDir = outputDir;
            AnyFileOutputs = anyFileOutputs;
        }
    }

    /// <summary>A single ADRecon collection module. May emit several artifacts
    /// (e.g. Users + UserSPNs, Groups + GroupChanges).</summary>
    public interface IReconModule
    {
        // Module display name (also used as file stem prefix)
        string Name { get; }
        // Executes the module and returns one or more result sets
        List<ModuleResult> Run(ModuleContext ctx);
    }
}