// ModuleRunner.cs - 模块执行协调器
// 按照ADRecon的调度顺序执行已配置的收集模块，并导出每个工件。
// 镜像了Invoke-ADRecon的最终循环逻辑。

using System;
using System.Collections.Generic;
using AdRecon.Core;
using AdRecon.Export;

namespace AdRecon.Modules
{
    /// <summary>Runs the configured collection modules in ADRecon's dispatch order and
    /// exports each artifact. Mirrors the final loop of Invoke-ADRecon.</summary>
    public static class ModuleRunner
    {
        // 模块执行顺序 - 定义了所有收集模块的调度顺序
        // This array defines the execution order for all collection modules.
        private static readonly Core.Modules[] Order =
        {
            Core.Modules.Domain, Core.Modules.Forest, Core.Modules.Trusts, Core.Modules.Sites, Core.Modules.Subnets,
            Core.Modules.SchemaHistory, Core.Modules.PasswordPolicy, Core.Modules.FineGrainedPasswordPolicy,
            Core.Modules.DomainControllers,
            Core.Modules.Users, Core.Modules.UserSPNs,
            Core.Modules.PasswordAttributes,
            Core.Modules.Groups, Core.Modules.GroupChanges, Core.Modules.GroupMembers,
            Core.Modules.OUs, Core.Modules.GPOs, Core.Modules.GPLinks,
            Core.Modules.DNSZones, Core.Modules.DNSRecords,
            Core.Modules.Printers,
            Core.Modules.Computers, Core.Modules.ComputerSPNs,
            Core.Modules.LAPS, Core.Modules.BitLocker, Core.Modules.ACLs,
            Core.Modules.GPOReport, Core.Modules.Kerberoast,
            Core.Modules.DomainAccountsUsedForServiceLogon
        };

        // Run方法 - 主入口点，按顺序执行所有已选择的模块
        public static void Run(ModuleContext ctx)
        {
            Core.Modules collect = ctx.Config.Collect;
            foreach (Core.Modules m in Order)
            {
                if ((collect & m) == 0) continue;
                RunModule(ctx, m);
            }
        }

        // RunModule - 执行单个模块并处理其结果
        private static void RunModule(ModuleContext ctx, Core.Modules m)
        {
            // Banner text parity with ADRecon's Write-Output "[-] <name>".
            Log.Module(ModuleBanner(m));

            IReconModule module = ModuleRegistry.Create(m);
            if (!ModuleRegistry.IsImplemented(m))
            {
                // Stub emits its own warning and returns nothing.
                module.Run(ctx);
                return;
            }

            try
            {
                // 执行模块并获取结果 - Execute module and get results
                List<ModuleResult> results = module.Run(ctx);
                if (results == null) return;
                foreach (ModuleResult r in results)
                {
                    if (r == null || r.Rows == null || r.Rows.Count == 0) continue;
                    if (!ArtifactSelected(ctx.Config.Collect, r.ModuleName)) continue;
                    AdExporter.Export(r, ctx.OutputDir, ctx.Config.OutputType);
                }
            }
            catch (Exception ex)
            {
                Log.Warning("[" + module.Name + "] Module failed: " + ex.Message);
                Log.Exception(module.Name, ex);
            }
        }

        // ArtifactSelected - 检查特定工件是否被选中用于导出
        private static bool ArtifactSelected(Core.Modules collect, string artifact)
        {
            switch (artifact)
            {
                case "Users": return (collect & Core.Modules.Users) != 0;
                case "UserSPNs": return (collect & Core.Modules.UserSPNs) != 0;
                case "Groups": return (collect & Core.Modules.Groups) != 0;
                case "GroupChanges": return (collect & Core.Modules.GroupChanges) != 0;
                case "Computers": return (collect & Core.Modules.Computers) != 0;
                case "ComputerSPNs": return (collect & Core.Modules.ComputerSPNs) != 0;
                case "DNSZones": return (collect & Core.Modules.DNSZones) != 0;
                case "DNSRecords": return (collect & Core.Modules.DNSRecords) != 0;
                case "DACLs": return (collect & Core.Modules.ACLs) != 0;
                case "SACLs": return (collect & Core.Modules.ACLs) != 0;
                case "GPOs": return (collect & Core.Modules.GPOs) != 0;
                default: return true;
            }
        }

        // ModuleBanner - 返回模块的显示名称
        public static string ModuleBanner(Core.Modules m)
        {
            switch (m)
            {
                case Core.Modules.Domain: return "Domain";
                case Core.Modules.Forest: return "Forest";
                case Core.Modules.Trusts: return "Trusts";
                case Core.Modules.Sites: return "Sites";
                case Core.Modules.Subnets: return "Subnets";
                case Core.Modules.SchemaHistory: return "SchemaHistory - May take some time";
                case Core.Modules.PasswordPolicy: return "Default Password Policy";
                case Core.Modules.FineGrainedPasswordPolicy: return "Fine Grained Password Policy - May need a Privileged Account";
                case Core.Modules.DomainControllers: return "Domain Controllers";
                case Core.Modules.Users: return "Users and SPNs - May take some time";
                case Core.Modules.UserSPNs: return "";
                case Core.Modules.PasswordAttributes: return "PasswordAttributes - Experimental";
                case Core.Modules.Groups: return "Groups and Membership Changes - May take some time";
                case Core.Modules.GroupChanges: return "";
                case Core.Modules.GroupMembers: return "Group Memberships - May take some time";
                case Core.Modules.OUs: return "OrganizationalUnits (OUs)";
                case Core.Modules.GPOs: return "GPOs";
                case Core.Modules.GPLinks: return "gPLinks - Scope of Management (SOM)";
                case Core.Modules.DNSZones: return "DNS Zones and Records";
                case Core.Modules.DNSRecords: return "";
                case Core.Modules.Printers: return "Printers";
                case Core.Modules.Computers: return "Computers and SPNs - May take some time";
                case Core.Modules.ComputerSPNs: return "";
                case Core.Modules.LAPS: return "LAPS - Needs Privileged Account";
                case Core.Modules.BitLocker: return "BitLocker Recovery Keys - Needs Privileged Account";
                case Core.Modules.ACLs: return "ACLs - May take some time";
                case Core.Modules.GPOReport: return "GPOReport - May take some time";
                case Core.Modules.Kerberoast: return "Kerberoast";
                case Core.Modules.DomainAccountsUsedForServiceLogon: return "Domain Accounts used for Service Logon";
                default: return m.ToString();
            }
        }
    }
}