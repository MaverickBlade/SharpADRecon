// DomainControllerModule.cs - 域控制器信息收集模块
// 镜像Get-ADRDomainController（LDAP路径，DomainControllerRecordProcessor）：
// 通过System.DirectoryServices.ActiveDirectory枚举域控制器，并探测每个SMB端口的方言支持。

using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.DirectoryServices.ActiveDirectory;
using AdRecon.Ad;
using AdRecon.Core;

namespace AdRecon.Modules
{
    /// <summary>Result of an SMB port/dialect probe for a domain controller.</summary>
    internal sealed class SmbProbe
    {
        public bool PortOpen;
        public bool SMBv1;
        public bool SMBv2_0202;
        public bool SMBv2_0210;
        public bool SMBv3_0300;
        public bool SMBv3_0302;
        public bool SMBv3_0311;
        public bool Signing;
    }

    /// <summary>Port of the embedded "Samba" SMB scanner (port 445 dialect negotiation)
    /// used by the DomainControllers module in ADRecon.</summary>
    internal static class SmbScanner
    {
        // SMB协议结构体定义
        [StructLayout(LayoutKind.Explicit)]
        struct SMB_Header
        {
            [FieldOffset(0)] public byte Protocol0;
            [FieldOffset(1)] public byte Protocol1;
            [FieldOffset(2)] public byte Protocol2;
            [FieldOffset(3)] public byte Protocol3;
            [FieldOffset(4)] public byte Command;
            [FieldOffset(5)] public int Status;
            [FieldOffset(9)] public byte Flags;
            [FieldOffset(10)] public ushort Flags2;
            [FieldOffset(12)] public ushort PIDHigh;
            [FieldOffset(14)] public ulong SecurityFeatures;
            [FieldOffset(22)] public ushort Reserved;
            [FieldOffset(24)] public ushort TID;
            [FieldOffset(26)] public ushort PIDLow;
            [FieldOffset(28)] public ushort UID;
            [FieldOffset(30)] public ushort MID;
        }

        [StructLayout(LayoutKind.Explicit)]
        struct SMB2_Header
        {
            // SMB2协议头结构
            [FieldOffset(0)] public uint ProtocolId;
            [FieldOffset(4)] public ushort StructureSize;
            [FieldOffset(6)] public ushort CreditCharge;
            [FieldOffset(8)] public uint Status;
            [FieldOffset(12)] public ushort Command;
            [FieldOffset(14)] public ushort CreditRequest_Response;
            [FieldOffset(16)] public uint Flags;
            [FieldOffset(20)] public uint NextCommand;
            [FieldOffset(24)] public ulong MessageId;
            [FieldOffset(32)] public uint Reserved2;
            [FieldOffset(36)] public uint TreeId;
            [FieldOffset(40)] public ulong SessionId;
            [FieldOffset(48)] public ulong Signature1;
            [FieldOffset(56)] public ulong Signature2;
        }

        [StructLayout(LayoutKind.Explicit)]
        struct SMB2_NegotiateRequest
        {
            // SMB2协商请求结构
            [FieldOffset(0)] public ushort StructureSize;
            [FieldOffset(2)] public ushort DialectCount;
            [FieldOffset(4)] public ushort SecurityMode;
            [FieldOffset(6)] public ushort Reserved;
            [FieldOffset(8)] public uint Capabilities;
            [FieldOffset(12)] public Guid ClientGuid;
            [FieldOffset(28)] public ulong ClientStartTime;
            [FieldOffset(36)] public ushort DialectToTest;
        }

        private const int SMB_COM_NEGOTIATE = 0x72;
        private const int SMB2_NEGOTIATE = 0;

        // Probe - 探测服务器的SMB方言支持
        public static SmbProbe Probe(string server)
        {
            SmbProbe p = new SmbProbe();
            if (server == null || server.Length == 0) { p.PortOpen = false; return p; }
            try
            {
                // 测试SMB1方言支持
                bool v1 = false, v2a = false, v2b = false, v3a = false, v3b = false, v3c = false;
                try { v1 = DoesServerSupportDialect(server, "NT LM 0.12"); } catch (ApplicationException) { }
                try
                {
                    // 测试SMB2/3方言支持
                    v2a = DoesServerSupportDialectWithSmbV2(server, 0x0202, false);
                    v2b = DoesServerSupportDialectWithSmbV2(server, 0x0210, false);
                    v3a = DoesServerSupportDialectWithSmbV2(server, 0x0300, false);
                    v3b = DoesServerSupportDialectWithSmbV2(server, 0x0302, false);
                    v3c = DoesServerSupportDialectWithSmbV2(server, 0x0311, false);
                }
                catch (ApplicationException) { }

                // 检查签名支持
                bool signing = false;
                if (v3c) signing = DoesServerSupportDialectWithSmbV2(server, 0x0311, true);
                else if (v3b) signing = DoesServerSupportDialectWithSmbV2(server, 0x0302, true);
                else if (v3a) signing = DoesServerSupportDialectWithSmbV2(server, 0x0300, true);
                else if (v2b) signing = DoesServerSupportDialectWithSmbV2(server, 0x0210, true);
                else if (v2a) signing = DoesServerSupportDialectWithSmbV2(server, 0x0202, true);
                else if (v1) signing = false;

                // 设置探测结果
                p.PortOpen = true;
                p.SMBv1 = v1;
                p.SMBv2_0202 = v2a;
                p.SMBv2_0210 = v2b;
                p.SMBv3_0300 = v3a;
                p.SMBv3_0302 = v3b;
                p.SMBv3_0311 = v3c;
                p.Signing = signing;
            }
            catch (Exception)
            {
                p.PortOpen = false;
            }
            return p;
        }

        // GenerateSmbHeader - 生成SMB1协议头
        private static byte[] GenerateSmbHeader(byte command)
        {
            SMB_Header h = new SMB_Header();
            h.Protocol0 = 0xFF; h.Protocol1 = 0x53; h.Protocol2 = 0x4D; h.Protocol3 = 0x42;
            h.Command = command;
            h.Status = 0;
            h.Flags = 0x08 | 0x10;
            h.Flags2 = 0x0001 | 0x0002 | 0x0010 | 0x0040 | 0x0800 | 0x4000 | 0x8000;
            h.PIDHigh = 0;
            h.SecurityFeatures = 0;
            h.Reserved = 0;
            h.TID = 0xffff;
            h.PIDLow = 0xFEFF;
            h.UID = 0;
            h.MID = 0;
            return getBytes(h);
        }

        // GenerateSmb2Header - 生成SMB2协议头
        private static byte[] GenerateSmb2Header(byte command)
        {
            SMB2_Header h = new SMB2_Header();
            h.ProtocolId = 0x424D53FE;
            h.Command = command;
            h.StructureSize = 64;
            h.MessageId = 0;
            h.Reserved2 = 0xFEFF;
            return getBytes(h);
        }

        // getBytes - 将结构体转换为字节数组
        private static byte[] getBytes(object structure)
        {
            int size = Marshal.SizeOf(structure);
            byte[] arr = new byte[size];
            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(structure, ptr, true);
                Marshal.Copy(ptr, arr, 0, size);
            }
            finally { Marshal.FreeHGlobal(ptr); }
            return arr;
        }

        // getDialect - 获取方言字符串的字节表示
        private static byte[] getDialect(string dialect)
        {
            byte[] b = Encoding.ASCII.GetBytes(dialect);
            byte[] output = new byte[b.Length + 2];
            output[0] = 2;
            output[output.Length - 1] = 0;
            Array.Copy(b, 0, output, 1, b.Length);
            return output;
        }

        // GetNegotiateMessage - 获取SMB1协商消息
        private static byte[] GetNegotiateMessage(byte[] dialect)
        {
            byte[] output = new byte[dialect.Length + 3];
            output[0] = 0;
            output[1] = (byte)dialect.Length;
            output[2] = 0;
            Array.Copy(dialect, 0, output, 3, dialect.Length);
            return output;
        }

        // GetNegotiateMessageSmbv2 - 获取SMB2协商消息
        private static byte[] GetNegotiateMessageSmbv2(ushort dialectToTest)
        {
            SMB2_NegotiateRequest r = new SMB2_NegotiateRequest();
            r.StructureSize = 36;
            r.DialectCount = 1;
            r.SecurityMode = 1;
            r.ClientGuid = Guid.NewGuid();
            r.DialectToTest = dialectToTest;
            return getBytes(r);
        }

        // GetNegotiatePacket - 获取协商数据包
        private static byte[] GetNegotiatePacket(byte[] header, byte[] smbPacket)
        {
            byte[] output = new byte[smbPacket.Length + header.Length + 4];
            output[0] = 0; output[1] = 0; output[2] = 0;
            output[3] = (byte)(smbPacket.Length + header.Length);
            Array.Copy(header, 0, output, 4, header.Length);
            Array.Copy(smbPacket, 0, output, 4 + header.Length, smbPacket.Length);
            return output;
        }

        // DoesServerSupportDialect - 检查服务器是否支持SMB1方言
        private static bool DoesServerSupportDialect(string server, string dialect)
        {
            using (TcpClient client = new TcpClient())
            {
                try { client.Connect(server, 445); }
                catch (Exception) { throw new Exception("port 445 is closed on " + server); }
                try
                {
                    NetworkStream stream = client.GetStream();
                    byte[] header = GenerateSmbHeader(SMB_COM_NEGOTIATE);
                    byte[] negotiatemessage = GetNegotiateMessage(getDialect(dialect));
                    byte[] packet = GetNegotiatePacket(header, negotiatemessage);
                    stream.Write(packet, 0, packet.Length);
                    stream.Flush();
                    byte[] netbios = new byte[4];
                    if (ReadExact(stream, netbios) != netbios.Length) return false;
                    byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB_Header))];
                    if (ReadExact(stream, smbHeader) != smbHeader.Length) return false;
                    byte[] response = new byte[3];
                    if (ReadExact(stream, response) != response.Length) return false;
                    if (response[1] == 0 && response[2] == 0) return true;
                    return false;
                }
                catch (Exception) { throw new ApplicationException("Smb1 is not supported on " + server); }
            }
        }

        // DoesServerSupportDialectWithSmbV2 - 检查服务器是否支持SMB2/3方言
        private static bool DoesServerSupportDialectWithSmbV2(string server, int dialect, bool checkSigning)
        {
            using (TcpClient client = new TcpClient())
            {
                try { client.Connect(server, 445); }
                catch (Exception) { throw new Exception("port 445 is closed on " + server); }
                try
                {
                    NetworkStream stream = client.GetStream();
                    byte[] header = GenerateSmb2Header(SMB2_NEGOTIATE);
                    byte[] negotiatemessage = GetNegotiateMessageSmbv2((ushort)dialect);
                    byte[] packet = GetNegotiatePacket(header, negotiatemessage);
                    stream.Write(packet, 0, packet.Length);
                    stream.Flush();
                    byte[] netbios = new byte[4];
                    if (ReadExact(stream, netbios) != netbios.Length) return false;
                    byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB2_Header))];
                    if (ReadExact(stream, smbHeader) != smbHeader.Length) return false;
                    if (smbHeader[8] != 0 || smbHeader[9] != 0 || smbHeader[10] != 0 || smbHeader[11] != 0)
                        return false;
                    byte[] response = new byte[6];
                    if (ReadExact(stream, response) != response.Length) return false;
                    if (checkSigning)
                    {
                        if (response[2] == 3) return true;
                        return false;
                    }
                    int selectedDialect = response[5] * 0x100 + response[4];
                    return selectedDialect == dialect;
                }
                catch (Exception) { throw new ApplicationException("Smb2 is not supported on " + server); }
            }
        }

        // ReadExact - 从流中精确读取指定字节数
        private static int ReadExact(NetworkStream stream, byte[] buffer)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int n = stream.Read(buffer, offset, buffer.Length - offset);
                if (n <= 0) break;
                offset += n;
            }
            return offset;
        }
    }

    /// <summary>Mirror of Get-ADRDomainController (LDAP path, DomainControllerRecordProcessor).
    /// Enumerates domain controllers via System.DirectoryServices.ActiveDirectory and probes
    /// each SMB port for dialect support.</summary>
    public sealed class DomainControllersModule : IReconModule
    {
        public string Name { get { return "DomainControllers"; } }

        // Run方法 - 收集域控制器信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            var rows = new List<AdRow>();
            var cols = Col.New("Domain", "Site", "Name", "IPv4Address", "Operating System", "Hostname",
                "Infra", "Naming", "Schema", "RID", "PDC", "SMB Port Open", "SMB1(NT LM 0.12)",
                "SMB2(0x0202)", "SMB2(0x0210)", "SMB3(0x0300)", "SMB3(0x0302)", "SMB3(0x0311)", "SMB Signing");
            try
            {
                // 获取域控制器集合
                Domain dcRoot = DomainForest.GetDomain(ctx.Session, AdAttrs.DnToFqdn(ctx.Session.DefaultNamingContext));
                DomainControllerCollection dcs = dcRoot.DomainControllers;
                foreach (DomainController dc in dcs)
                {
                    AdRow row = Col.Row(cols);
                    bool? infra = null, naming = null, schema = null, rid = null, pdc = null;
                    string domain = null, site = null, os = null;
                    try
                    {
                        // 获取DC的基本信息
                        domain = dc.Domain.ToString();
                        foreach (ActiveDirectoryRole role in dc.Roles)
                        {
                            switch (role.ToString())
                            {
                                case "InfrastructureRole": infra = true; break;
                                case "NamingRole": naming = true; break;
                                case "SchemaRole": schema = true; break;
                                case "RidRole": rid = true; break;
                                case "PdcRole": pdc = true; break;
                            }
                        }
                        site = dc.SiteName;
                        os = dc.OSVersion.ToString();
                    }
                    catch (ActiveDirectoryServerDownException)
                    {
                        infra = null; naming = null; schema = null; rid = null; pdc = null;
                    }
                    catch (Exception) { }

                    // 获取不带FQDN后缀的名称
                    string fqdnName = dc.Name;
                    string shortName = SplitShort(fqdnName);

                    // 设置行数据
                    row.Set("Domain", domain);
                    row.Set("Site", site);
                    row.Set("Name", shortName);
                    row.Set("IPv4Address", dc.IPAddress);
                    row.Set("Operating System", os);
                    row.Set("Hostname", fqdnName);
                    row.Set("Infra", infra);
                    row.Set("Naming", naming);
                    row.Set("Schema", schema);
                    row.Set("RID", rid);
                    row.Set("PDC", pdc);

                    // SMB探测
                    if (dc.IPAddress != null && dc.IPAddress.Length > 0)
                    {
                        SmbProbe p = SmbScanner.Probe(dc.IPAddress);
                        row.Set("SMB Port Open", p.PortOpen);
                        row.Set("SMB1(NT LM 0.12)", p.SMBv1);
                        row.Set("SMB2(0x0202)", p.SMBv2_0202);
                        row.Set("SMB2(0x0210)", p.SMBv2_0210);
                        row.Set("SMB3(0x0300)", p.SMBv3_0300);
                        row.Set("SMB3(0x0302)", p.SMBv3_0302);
                        row.Set("SMB3(0x0311)", p.SMBv3_0311);
                        row.Set("SMB Signing", p.Signing);
                    }
                    else
                    {
                        row.Set("SMB Port Open", false);
                        row.Set("SMB1(NT LM 0.12)", null);
                        row.Set("SMB2(0x0202)", null);
                        row.Set("SMB2(0x0210)", null);
                        row.Set("SMB3(0x0300)", null);
                        row.Set("SMB3(0x0302)", null);
                        row.Set("SMB3(0x0311)", null);
                        row.Set("SMB Signing", null);
                    }
                    rows.Add(row);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[Get-ADRDomainController] Error while enumerating Domain Controller Objects");
                Log.Exception("Get-ADRDomainController", ex);
                return null;
            }
            return rows.Count > 0 ? Clr.Of(new ModuleResult("DomainControllers", cols, rows)) : null;
        }

        // SplitShort - 从FQDN中提取短名称
        private static string SplitShort(string fqdn)
        {
            if (fqdn == null || fqdn.Length == 0) return "";
            int dot = fqdn.IndexOf('.');
            return dot >= 0 ? fqdn.Substring(0, dot) : fqdn;
        }
    }
}