// ModuleRegistry.cs - 模块注册表
// 将Core.Modules标志映射到模块实例。未实现的模块返回空存根，以便在模块逐步移植时保持构建正常。

using System;
using System.Collections.Generic;
using AdRecon.Core;

namespace AdRecon.Modules
{
    /// <summary>Maps Core.Modules flags to module instances. Unimplemented modules return
    /// an Empty stub so the build stays green while modules are ported incrementally.</summary>
    public static class ModuleRegistry
    {
        // 模块映射字典 - 存储模块标志到模块工厂函数的映射
        private static readonly Dictionary<Core.Modules, Func<IReconModule>> _map =
            new Dictionary<Core.Modules, Func<IReconModule>>();

        // 静态构造函数 - 注册所有已实现的模块
        static ModuleRegistry()
        {
            _map[Core.Modules.Domain] = () => new DomainModule();
            _map[Core.Modules.Forest] = () => new ForestModule();
            _map[Core.Modules.Trusts] = () => new TrustsModule();
            _map[Core.Modules.Sites] = () => new SitesModule();
            _map[Core.Modules.Subnets] = () => new SubnetsModule();
            _map[Core.Modules.SchemaHistory] = () => new SchemaHistoryModule();
            _map[Core.Modules.PasswordPolicy] = () => new DefaultPasswordPolicyModule();
            _map[Core.Modules.FineGrainedPasswordPolicy] = () => new FineGrainedPasswordPolicyModule();
            _map[Core.Modules.DomainControllers] = () => new DomainControllersModule();
            _map[Core.Modules.Users] = () => new UsersModule();
            _map[Core.Modules.UserSPNs] = () => new UserSPNsModule();
            _map[Core.Modules.Groups] = () => new GroupsModule();
            _map[Core.Modules.GroupChanges] = () => new GroupChangesModule();
            _map[Core.Modules.GroupMembers] = () => new GroupMembersModule();
            _map[Core.Modules.Computers] = () => new ComputersModule();
            _map[Core.Modules.ComputerSPNs] = () => new ComputerSPNsModule();
            _map[Core.Modules.LAPS] = () => new LapsModule();
            _map[Core.Modules.BitLocker] = () => new BitLockerModule();
            _map[Core.Modules.PasswordAttributes] = () => new PasswordAttributesModule();
            _map[Core.Modules.ACLs] = () => new AclsModule();
            _map[Core.Modules.OUs] = () => new OUsModule();
            _map[Core.Modules.GPOs] = () => new GPOsModule();
            _map[Core.Modules.GPOReport] = () => new GPOReportModule();
            _map[Core.Modules.GPLinks] = () => new GPLinksModule();
            _map[Core.Modules.DNSZones] = () => new DnsZonesModule(Core.Modules.DNSZones);
            _map[Core.Modules.DNSRecords] = () => new DnsZonesModule(Core.Modules.DNSRecords);
            _map[Core.Modules.Printers] = () => new PrintersModule();
            _map[Core.Modules.Kerberoast] = () => new KerberoastModule();
            _map[Core.Modules.DomainAccountsUsedForServiceLogon] = () => new ServiceLogonModule();
        }

        // IsImplemented - 检查模块是否已实现
        public static bool IsImplemented(Core.Modules m)
        {
            return _map.ContainsKey(m);
        }

        // Create - 创建指定模块的实例
        public static IReconModule Create(Core.Modules m)
        {
            Func<IReconModule> f;
            if (_map.TryGetValue(m, out f)) return f();
            return CreateStub(m);
        }

        // CreateStub - 创建未实现模块的存根实例
        public static IReconModule CreateStub(Core.Modules m)
        {
            string name = m.ToString();
            return new StubModule(name);
        }

        // StubModule - 未实现模块的存根类
        private sealed class StubModule : IReconModule
        {
            private readonly string _name;
            public StubModule(string name) { _name = name; }
            public string Name { get { return _name; } }
            public List<ModuleResult> Run(ModuleContext ctx)
            {
                Log.Warning("[Module " + _name + "] Not yet ported; producing no output.");
                return new List<ModuleResult>();
            }
        }
    }
}