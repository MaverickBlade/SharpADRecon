// AdExporter.cs - 导出协调器，负责将模块结果分派到各格式导出器
// 本文件提供统一入口，根据输出类型标志调度到 CSV/XML/JSON/HTML 导出方法

using System;
using System.Collections.Generic;
using System.IO;
using AdRecon.Core;

namespace AdRecon.Export
{
    /// <summary>Dispatcher mirroring Export-ADR: writes a module result to each selected
    /// file format folder and/or stdout.</summary>
    // 导出协调器：根据 OutputTypeFlag 将结果写入对应格式的文件夹及标准输出
    public static class AdExporter
    {
        // 主导出方法：根据标志位将结果分发到各格式导出器
        public static void Export(ModuleResult result, string outputDir, OutputTypeFlag type,
            bool suppressStdoutForAbout = false)
        {
            // 处理标准输出（可选）
            if ((type & OutputTypeFlag.STDOUT) != 0 && !suppressStdoutForAbout)
                PrintStdout(result);

            // CSV 导出
            if ((type & OutputTypeFlag.CSV) != 0)
                Exporters.ToCsv(result, FileFor(outputDir, "CSV-Files", result.ModuleName, ".csv"));

            // XML 导出
            if ((type & OutputTypeFlag.XML) != 0)
                Exporters.ToXml(result, FileFor(outputDir, "XML-Files", result.ModuleName, ".xml"));

            // JSON 导出
            if ((type & OutputTypeFlag.JSON) != 0)
                Exporters.ToJson(result, FileFor(outputDir, "JSON-Files", result.ModuleName, ".json"));

            // HTML 导出
            if ((type & OutputTypeFlag.HTML) != 0)
                Exporters.ToHtml(result, FileFor(outputDir, "HTML-Files", result.ModuleName, ".html"));
        }

        // 构造模块输出文件的完整路径：outputDir/folder/moduleName.ext
        public static string FileFor(string outputDir, string folder, string moduleName, string ext)
        {
            return Path.Combine(outputDir, folder, moduleName + ext);
        }

        // 如果启用了 HTML 输出，则生成索引页面
        public static void WriteHtmlIndexIfSelected(string outputDir, OutputTypeFlag type)
        {
            if ((type & OutputTypeFlag.HTML) == 0) return;
            string htmlDir = Path.Combine(outputDir, "HTML-Files");
            Exporters.WriteHtmlIndex(htmlDir, FileFor(outputDir, "HTML-Files", "Index", ".html"));
        }

        // 将模块结果以文本形式输出到控制台
        private static void PrintStdout(ModuleResult result)
        {
            // AboutADRecon 模块不输出到控制台
            if (result.ModuleName.Equals("AboutADRecon", StringComparison.OrdinalIgnoreCase)) return;
            Log.WriteLine("- " + result.ModuleName);
            // 遍历每一行数据并输出列名=值的格式
            foreach (AdRow row in result.Rows)
            {
                foreach (string col in result.Columns)
                {
                    string v = row.GetString(col);
                    if (v.Length == 0) continue;
                    Log.WriteLine("  " + col + " = " + v);
                }
                Log.WriteLine("");
            }
        }
    }
}
