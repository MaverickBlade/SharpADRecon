// DnsModule.cs - DNS区域和记录模块
// 镜像Get-ADRDNSZone（LDAP路径），包括通过Convert-DNSRecord进行的二进制DNS记录解码。
// 搜索三个AD分区：域、DC=DomainDnsZones和DC=ForestDnsZones。

using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Text;
using AdRecon.Ad;
using AdRecon.Core;

namespace AdRecon.Modules
{
    /// <summary>Mirror of Get-ADRDNSZone (LDAP path) including binary DNS record decoding
    /// via Convert-DNSRecord.  Searches three AD partitions: domain, DC=DomainDnsZones,
    /// and DC=ForestDnsZones.</summary>
    public sealed class DnsZonesModule : IReconModule
    {
        // 调用者模块标志
        private readonly Core.Modules _invoker;

        public DnsZonesModule(Core.Modules invoker) { _invoker = invoker; }

        public string Name { get { return "DNSZones"; } }

        // Run方法 - 收集DNS区域和记录信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            bool wantZones = (ctx.Config.Collect & Core.Modules.DNSZones) != 0;
            bool wantRecords = (ctx.Config.Collect & Core.Modules.DNSRecords) != 0;

            // The DNSZones pass already enumerates zones and records together. Running the
            // DNSRecords pass too would re-scan the whole DNS partitions, so make it a no-op.
            if (_invoker == Core.Modules.DNSRecords && wantZones && wantRecords)
                return null;

            var zones = new List<AdRow>();
            var zoneCols = Col.New("Name", "RecordCount", "USNCreated", "USNChanged",
                "whenCreated", "whenChanged", "DistinguishedName");
            var nodes = new List<AdRow>();
            var nodeCols = Col.New("ZoneName", "Name", "RecordType", "Data", "TTL", "Age",
                "TimeStamp", "UpdatedAtSerial", "whenCreated", "whenChanged",
                "showInAdvancedViewOnly", "DistinguishedName");

            try
            {
                AdSession s = ctx.Session;
                string domainDn = s.DefaultNamingContext;
                string domainDnsBase = "DC=DomainDnsZones," + domainDn;

                // ForestDnsZones base requires forest DNS name → DC= conversion.
                string forestDnsBase = "DC=ForestDnsZones," + s.RootDomainNamingContext;

                var zoneSearchBases = new List<string>();
                zoneSearchBases.Add(domainDn);
                zoneSearchBases.Add(domainDnsBase);
                if (forestDnsBase.Length > 0) zoneSearchBases.Add(forestDnsBase);

                foreach (string baseDn in zoneSearchBases)
                {
                    SearchResultCollection zoneResults = null;
                    try
                    {
                        using (DirectorySearcher zs = s.NewSearcher(baseDn, "(objectClass=dnsZone)",
                            new[] { "name", "whencreated", "whenchanged", "usncreated", "usnchanged", "distinguishedname" },
                            SearchScope.Subtree, ctx.Config.PageSize))
                        {
                            zoneResults = zs.FindAll();
                        }
                    }
                    catch { continue; }
                    if (zoneResults == null) continue;

                    try
                    {
                        foreach (SearchResult zr in zoneResults)
                        {
                            string zoneName = AdAttrs.CleanString(AdSession.GetValue(zr, "name"));
                            string zoneDN = AdSession.GetString(zr, "distinguishedname");
                            AdRow zoneRow = Col.Row(zoneCols);
                            zoneRow.Set("Name", zoneName);
                            zoneRow.Set("USNCreated", AdSession.GetString(zr, "usncreated"));
                            zoneRow.Set("USNChanged", AdSession.GetString(zr, "usnchanged"));
                            zoneRow.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(zr, "whencreated")));
                            zoneRow.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(zr, "whenchanged")));
                            zoneRow.Set("DistinguishedName", zoneDN);

                            // Enumerate nodes under this zone.
                            int nodeCount = 0;
                            try
                            {
                                using (DirectorySearcher ns = s.NewSearcher(zoneDN, "(objectClass=dnsNode)",
                                    new[] { "distinguishedname", "dnsrecord", "name", "dc",
                                            "showinadvancedviewonly", "whenchanged", "whencreated" },
                                    SearchScope.Subtree, ctx.Config.PageSize))
                                {
                                    SearchResultCollection nodeResults = ns.FindAll();
                                    try
                                    {
                                        foreach (SearchResult nr in nodeResults)
                                        {
                                            nodeCount++;
                                            string nodeName = AdSession.GetString(nr, "name");
                                            if (nodeName.Length == 0) nodeName = AdSession.GetString(nr, "dc");
                                            byte[] dnsRec = GetBytes(nr, "dnsrecord");
                                            string recType = "", data = "";
                                            int ttl = 0, age = 0, updatedAtSerial = 0;
                                            string timeStamp = "";

                                            if (dnsRec != null && dnsRec.Length > 0)
                                            {
                                                DnsRecord decoded = DnsRecordDecoder.Decode(dnsRec);
                                                if (decoded != null)
                                                {
                                                    recType = decoded.RecordType;
                                                    data = decoded.Data;
                                                    ttl = decoded.TTL;
                                                    age = decoded.Age;
                                                    updatedAtSerial = decoded.UpdatedAtSerial;
                                                    timeStamp = decoded.TimeStamp;
                                                }
                                            }

                                            AdRow nodeRow = Col.Row(nodeCols);
                                            nodeRow.Set("ZoneName", zoneName);
                                            nodeRow.Set("Name", nodeName);
                                            nodeRow.Set("RecordType", recType);
                                            nodeRow.Set("Data", data);
                                            nodeRow.Set("TTL", ttl);
                                            nodeRow.Set("Age", age);
                                            nodeRow.Set("TimeStamp", timeStamp);
                                            nodeRow.Set("UpdatedAtSerial", updatedAtSerial);
                                            nodeRow.Set("whenCreated", AdAttrs.AsDate(AdSession.GetValue(nr, "whencreated")));
                                            nodeRow.Set("whenChanged", AdAttrs.AsDate(AdSession.GetValue(nr, "whenchanged")));
                                            nodeRow.Set("showInAdvancedViewOnly", AdSession.GetString(nr, "showinadvancedviewonly"));
                                            nodeRow.Set("DistinguishedName", AdSession.GetString(nr, "distinguishedname"));
                                            nodes.Add(nodeRow);
                                        }
                                    }
                                    finally { nodeResults.Dispose(); }
                                }
                            }
                            catch { }
                            zoneRow.Set("RecordCount", nodeCount);
                            zones.Add(zoneRow);
                        }
                    }
                    finally { zoneResults.Dispose(); }
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRDNSZone] Error while enumerating DNS Zone Objects");
                Log.Exception("Get-ADRDNSZone", ex);
                return null;
            }

            var results = new List<ModuleResult>();
            if (zones.Count > 0 && wantZones)
                results.Add(new ModuleResult("DNSZones", zoneCols, zones));
            if (nodes.Count > 0 && wantRecords)
                results.Add(new ModuleResult("DNSRecords", nodeCols, nodes));
            return results.Count > 0 ? results : null;
        }

        private static byte[] GetBytes(SearchResult r, string name)
        {
            try
            {
                ResultPropertyValueCollection c = r.Properties[name];
                if (c == null || c.Count == 0) return null;
                object v = c[0];
                if (v is byte[]) return (byte[])v;
                return null;
            }
            catch { return null; }
        }
    }

    /// <summary>Port of Convert-DNSRecord.  Decodes a binary DNS record blob.</summary>
    internal sealed class DnsRecord
    {
        public string RecordType;
        public string Data;
        public int TTL;
        public int Age;
        public string TimeStamp;
        public int UpdatedAtSerial;
    }

    internal static class DnsRecordDecoder
    {
        private static readonly DateTime FILETIME_EPOCH = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static DnsRecord Decode(byte[] buf)
        {
            if (buf == null || buf.Length < 24) return null;
            DnsRecord rec = new DnsRecord();
            rec.UpdatedAtSerial = (int)BitConverter.ToUInt32(buf, 8);

            byte[] ttlRaw = new byte[4];
            ttlRaw[0] = buf[15]; ttlRaw[1] = buf[14]; ttlRaw[2] = buf[13]; ttlRaw[3] = buf[12];
            rec.TTL = (int)BitConverter.ToUInt32(ttlRaw, 0);

            rec.Age = (int)BitConverter.ToUInt32(buf, 20);
            if (rec.Age != 0)
                rec.TimeStamp = FILETIME_EPOCH.AddHours(rec.Age).ToString();
            else
                rec.TimeStamp = "[static]";

            ushort rDataType = BitConverter.ToUInt16(buf, 2);
            switch (rDataType)
            {
                case 1: // A
                    rec.RecordType = "A";
                    rec.Data = buf[24] + "." + buf[25] + "." + buf[26] + "." + buf[27];
                    break;
                case 2: // NS
                    rec.RecordType = "NS";
                    rec.Data = DecodeName(buf, 24);
                    break;
                case 5: // CNAME
                    rec.RecordType = "CNAME";
                    rec.Data = DecodeName(buf, 24);
                    break;
                case 6: // SOA
                    rec.RecordType = "SOA";
                    rec.Data = DecodeSOA(buf);
                    break;
                case 12: // PTR
                    rec.RecordType = "PTR";
                    rec.Data = DecodeName(buf, 24);
                    break;
                case 13: // HINFO
                    rec.RecordType = "HINFO";
                    rec.Data = DecodeHINFO(buf);
                    break;
                case 15: // MX
                    rec.RecordType = "MX";
                    rec.Data = DecodeMX(buf);
                    break;
                case 16: // TXT
                    rec.RecordType = "TXT";
                    rec.Data = DecodeTXT(buf);
                    break;
                case 28: // AAAA
                    rec.RecordType = "AAAA";
                    rec.Data = DecodeAAAA(buf);
                    break;
                case 33: // SRV
                    rec.RecordType = "SRV";
                    rec.Data = DecodeSRV(buf);
                    break;
                default:
                    rec.RecordType = "UNKNOWN";
                    byte[] remaining = new byte[buf.Length - 24];
                    Array.Copy(buf, 24, remaining, 0, remaining.Length);
                    rec.Data = Convert.ToBase64String(remaining);
                    break;
            }
            return rec;
        }

        private static string DecodeName(byte[] buf, int offset)
        {
            StringBuilder sb = new StringBuilder();
            int idx = offset;
            while (idx < buf.Length)
            {
                int len = buf[idx++];
                if (len == 0) break;
                if (idx + len > buf.Length) break;
                for (int i = 0; i < len; i++)
                    sb.Append((char)buf[idx++]);
                sb.Append('.');
            }
            return sb.ToString().TrimEnd('.');
        }

        private static string DecodeSOA(byte[] buf)
        {
            int idx = 44;
            string primaryNS = DecodeName(buf, idx);
            idx = idx + buf[idx] + 1;
            string rp = DecodeName(buf, idx);
            idx = idx + buf[idx] + 1;
            // Serial, Refresh, Retry, Expires, MinTTL — all big-endian from buf[24..43].
            byte[] serialRaw = new byte[4];
            serialRaw[0] = buf[27]; serialRaw[1] = buf[26]; serialRaw[2] = buf[25]; serialRaw[3] = buf[24];
            uint serial = BitConverter.ToUInt32(serialRaw, 0);
            byte[] refreshRaw = new byte[4];
            refreshRaw[0] = buf[31]; refreshRaw[1] = buf[30]; refreshRaw[2] = buf[29]; refreshRaw[3] = buf[28];
            uint refresh = BitConverter.ToUInt32(refreshRaw, 0);
            byte[] retryRaw = new byte[4];
            retryRaw[0] = buf[35]; retryRaw[1] = buf[34]; retryRaw[2] = buf[33]; retryRaw[3] = buf[32];
            uint retry = BitConverter.ToUInt32(retryRaw, 0);
            byte[] expiresRaw = new byte[4];
            expiresRaw[0] = buf[39]; expiresRaw[1] = buf[38]; expiresRaw[2] = buf[37]; expiresRaw[3] = buf[36];
            uint expires = BitConverter.ToUInt32(expiresRaw, 0);
            byte[] minttlRaw = new byte[4];
            minttlRaw[0] = buf[43]; minttlRaw[1] = buf[42]; minttlRaw[2] = buf[41]; minttlRaw[3] = buf[40];
            uint minttl = BitConverter.ToUInt32(minttlRaw, 0);
            return "[" + serial + "][" + primaryNS + "][" + rp + "][" + refresh + "][" + retry + "][" + expires + "][" + minttl + "]";
        }

        private static string DecodeHINFO(byte[] buf)
        {
            int cpuLen = buf[24];
            StringBuilder cpu = new StringBuilder();
            int idx = 25;
            for (int i = 0; i < cpuLen; i++) cpu.Append((char)buf[idx++]);
            idx++; // skip length byte for OS
            int osLen = buf[idx - 1];
            StringBuilder os = new StringBuilder();
            for (int i = 0; i < osLen; i++) os.Append((char)buf[idx++]);
            return "[" + cpu.ToString() + "][" + os.ToString() + "]";
        }

        private static string DecodeMX(byte[] buf)
        {
            byte[] priRaw = new byte[2];
            priRaw[0] = buf[25]; priRaw[1] = buf[24];
            ushort priority = BitConverter.ToUInt16(priRaw, 0);
            string host = DecodeName(buf, 26);
            return "[" + priority + "][" + host + "]";
        }

        private static string DecodeTXT(byte[] buf)
        {
            int len = buf[24];
            StringBuilder sb = new StringBuilder();
            int idx = 25;
            for (int i = 0; i < len; i++) sb.Append((char)buf[idx++]);
            return sb.ToString();
        }

        private static string DecodeAAAA(byte[] buf)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 24; i < 40; i += 2)
            {
                byte[] blockRaw = new byte[2];
                blockRaw[0] = buf[i + 1]; blockRaw[1] = buf[i];
                ushort block = BitConverter.ToUInt16(blockRaw, 0);
                sb.Append(block.ToString("x4"));
                if (i != 38) sb.Append(':');
            }
            return sb.ToString();
        }

        private static string DecodeSRV(byte[] buf)
        {
            byte[] priRaw = new byte[2]; priRaw[0] = buf[25]; priRaw[1] = buf[24];
            ushort pri = BitConverter.ToUInt16(priRaw, 0);
            byte[] wgtRaw = new byte[2]; wgtRaw[0] = buf[27]; wgtRaw[1] = buf[26];
            ushort wgt = BitConverter.ToUInt16(wgtRaw, 0);
            byte[] portRaw = new byte[2]; portRaw[0] = buf[29]; portRaw[1] = buf[28];
            ushort port = BitConverter.ToUInt16(portRaw, 0);
            string host = DecodeName(buf, 30);
            return "[" + pri + "][" + wgt + "][" + port + "][" + host + "]";
        }
    }
}