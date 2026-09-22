// AboutModule.cs - 关于信息收集模块
// 镜像Get-ADRAbout：在报告中写入键/值摘要信息。

using System;
using System.Collections.Generic;
using AdRecon.Core;

namespace AdRecon.Modules
{
    /// <summary>Mirror of Get-ADRAbout: a key/value summary written into the report.</summary>
    public sealed class AboutModule : IReconModule
    {
        // 关于信息字段
        public readonly DateTime StartDate;
        public readonly string RanOnComputer;
        public readonly string TotalTimeMinutes;

        // 构造函数 - 初始化关于信息
        public AboutModule(DateTime startDate, string ranOnComputer, string totalTimeMinutes)
        {
            StartDate = startDate;
            RanOnComputer = ranOnComputer;
            TotalTimeMinutes = totalTimeMinutes;
        }

        public string Name { get { return "About"; } }

        // Run方法 - 收集关于信息并返回结果
        public List<ModuleResult> Run(ModuleContext ctx)
        {
            // 构建列和行数据
            var cols = new List<string> { "Category", "Value" };
            var rows = new List<AdRow>();
            Action<string, string> add = (k, v) =>
            {
                var r = new AdRow(cols);
                r.Set("Category", k);
                r.Set("Value", v);
                rows.Add(r);
            };

            // 添加各种关于信息
            add("Date", StartDate.ToString("MM/dd/yyyy HH:mm:ss"));
            add("ADRecon", "https://github.com/adrecon/ADRecon");
            add("Method Version", AdReconConfig.Version);
            add("Ran as user",
                ctx.Config.CredentialUsername.Length > 0 ? ctx.Config.CredentialUsername : Environment.UserName);
            add("Ran on computer", RanOnComputer);
            add("Execution Time (mins)", TotalTimeMinutes);

            return new List<ModuleResult>
            {
                new ModuleResult("AboutADRecon", cols, rows)
            };
        }
    }
}
