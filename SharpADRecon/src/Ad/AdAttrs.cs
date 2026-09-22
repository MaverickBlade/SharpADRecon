// AdAttrs.cs - Attribute cleaning and parsing helpers
// Contains utility methods for converting and cleaning Active Directory attribute values.
// Ported from ADRecon's PowerShell and embedded C# code.

using System;
using System.Text.RegularExpressions;
using AdRecon.Core;

namespace AdRecon.Ad
{
    /// <summary>Attribute conversion helpers ported from ADRecon's PowerShell + embedded C#.</summary>
    // Static helper class for AD attribute transformations
    public static class AdAttrs
    {
        // Mirrors ADWSClass.Replacements + CleanString.
        private static readonly string[] CleanReplace = new string[]
        {
            "`", "", // backtick
            "\r", " ",
            "\n", " ",
            "\t", " ",
            "\"", "'"
        };

        // Cleans attribute strings by removing special chars and normalizing whitespace
        public static string CleanString(object value)
        {
            // 清理字符串中的特殊字符
            if (value == null) return "";
            string s = value.ToString();
            if (s.Length == 0) return s;
            for (int i = 0; i < CleanReplace.Length; i += 2)
                s = s.Replace(CleanReplace[i], CleanReplace[i + 1]);
            // fold multiple spaces into one
            s = Regex.Replace(s, @"\s{2,}", " ").Trim();
            return s;
        }

        // Get-DateDiff port: difference between now and the given date.
        // Calculates time elapsed since a given date
        public static TimeSpan DateDiff(DateTime value)
        {
            return DateTime.Now - value;
        }

        // Get-DNtoFQDN port: e.g. "DC=corp,DC=contoso,DC=com" -> "corp.contoso.com".
        // Converts a distinguished name to a fully qualified domain name
        public static string DnToFqdn(string dn)
        {
            if (dn == null || dn.Length == 0) return dn;
            string[] parts = dn.Split(',');
            string fqdn = "";
            foreach (string p in parts)
            {
                string t = p.Trim();
                if (t.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    if (fqdn.Length > 0) fqdn += ".";
                    fqdn += t.Substring(3);
                }
            }
            return fqdn;
        }

        /// <summary>Inverse of DnToFqdn: "corp.contoso.com" -> "DC=corp,DC=contoso,DC=com".</summary>
        public static string FqdnToDn(string fqdn)
        {
            if (fqdn == null || fqdn.Length == 0) return "";
            string s = fqdn.Trim().TrimEnd('.');
            if (s.Length == 0) return "";
            // Already a DN
            if (s.IndexOf("DC=", StringComparison.OrdinalIgnoreCase) >= 0)
                return s;
            string[] labels = s.Split(new[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length == 0) return "";
            var parts = new System.Text.StringBuilder();
            for (int i = 0; i < labels.Length; i++)
            {
                if (i > 0) parts.Append(',');
                parts.Append("DC=");
                parts.Append(labels[i]);
            }
            return parts.ToString();
        }

        /// <summary>Converts an Active Directory large integer (FILETIME in 100ns since 1601)
        /// to a local DateTime. Returns null for 0 / sentinel values.</summary>
        // Converts FILETIME (100ns intervals since 1601) to DateTime
        public static DateTime? FromFileTime(object val)
        {
            // 将FILETIME转换为DateTime
            long ft;
            if (val == null) return null;
            try
            {
                if (val is long) ft = (long)val;
                else if (val is Int64) ft = (Int64)val;
                else if (val is uint) ft = (uint)val;
                else if (val is int) ft = (int)val;
                else if (val is byte[]) return FromFileTimeBytes((byte[])val);
                else ft = long.Parse(val.ToString());
            }
            catch { return null; }
            return FromFileTimeLong(ft);
        }

        // Helper to convert a long FILETIME to DateTime
        private static DateTime? FromFileTimeLong(long ft)
        {
            if (ft == 0) return null;
            try { return DateTime.FromFileTime(ft); }
            catch { return null; }
        }

        // Helper to convert a byte array FILETIME to DateTime
        private static DateTime? FromFileTimeBytes(byte[] b)
        {
            if (b == null || b.Length == 0) return null;
            try { return DateTime.FromFileTime(BitConverter.ToInt64(b, 0)); }
            catch { return null; }
        }

        /// <summary>Interval: FILETIME value converted to a DateTime diff against now,
        /// returned in days as an int (the "Age (days)" columns).</summary>
        // Calculates age in days from a FILETIME value
        public static int AgeDays(object val)
        {
            DateTime? d = FromFileTime(val);
            if (!d.HasValue) return -1;
            return (int)Math.Floor((DateTime.Now - d.Value).TotalDays);
        }

        /// <summary>Parses LDAP GeneralizedTime strings ("20100101000000.0Z") into a
        /// DateTime. Dates without a fractional/offset part are treated as UTC when the
        /// string ends with 'Z'. Mirrors the [DateTime] cast used throughout ADRecon.</summary>
        // Parses LDAP GeneralizedTime strings into DateTime format
        public static string AsDate(object value)
        {
            if (value == null) return "";
            if (value is DateTime) return ((DateTime)value).ToString();
            string s = value.ToString();
            if (s.Length == 0) return s;
            try
            {
                DateTime d = DateTime.Parse(s, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None);
                return d.ToString();
            }
            catch { return s; }
        }
    }
}
