using System;
using System.IO;
using System.Linq;
using AdRecon.Core;

// 文件作用：定义报表生成器接口及工厂类，为 ADRecon 报表提供统一的生成入口。
// Interface and factory for ADRecon report generation.
namespace AdRecon.Report
{
    /// <summary>Generates the ADRecon-Report.xlsx workbook from the CSV-Files folder.
    /// The implementation is intentionally behind an interface so the Excel backend can be
    /// swapped (ClosedXML/EPPlus when package restore is available, or the offline OpenXML
    /// writer). Report name: <DomainName>-ADRecon-Report.xlsx.</summary>
    // 报表生成器接口，所有报表实现都必须遵循此契约。
    public interface IReportGenerator
    {
        // 生成报表文件，返回输出文件的完整路径；失败时返回空字符串。
        string Generate(string csvDir, string outputDir, string logo);
    }

    // 报表工厂：负责创建具体的报表生成器实例。
    public static class ReportFactory
    {
        // 创建默认的报表生成器（当前为 OpenXML Excel 生成器）。
        public static IReportGenerator Create()
        {
            return new OpenXmlReportGenerator();
        }

        /// <summary>Derives the report file name from Domain.csv first row "Value"
        /// (mirrors $DomainName = "$($DomainObj[0].Value)-").</summary>
        // 从 Domain.csv 中读取域名，用于构造输出文件名。
        public static string DomainNameFromCsv(string csvDir)
        {
            string domainCsv = Path.Combine(csvDir, "Domain.csv");
            if (File.Exists(domainCsv))
            {
                try
                {
                    using (var r = new StreamReader(domainCsv))
                    {
                        string header = r.ReadLine();
                        if (header == null) return "";
                        string line;
                        while ((line = r.ReadLine()) != null)
                        {
                            if (line.Length == 0) continue;
                            // First column is "Category", second "Value".
                            // 解析 CSV 行，查找 Name 字段对应的值。
                            string[] parts = SplitCsvLine(line);
                            if (parts.Length >= 2 &&
                                parts[0].Trim().Equals("Name", StringComparison.OrdinalIgnoreCase))
                            {
                                return parts[1].Trim();
                            }
                        }
                    }
                }
                catch { }
            }
            return "";
        }

        private static string[] SplitCsvLine(string line)
        {
            // Minimal quoted-CSV tokenizer sufficient for the Domain.csv rows (no embedded commas)
            // but handles quotes defensively.
            // 简单的 CSV 分词器，支持引号内的逗号和转义引号。
            var list = new System.Collections.Generic.List<string>();
            bool inQ = false;
            string cur = "";
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '"')
                {
                    if (inQ && i + 1 < line.Length && line[i + 1] == '"') { cur += '"'; i++; }
                    else inQ = !inQ;
                }
                else if (c == ',' && !inQ)
                {
                    list.Add(cur); cur = "";
                }
                else cur += c;
            }
            list.Add(cur);
            return list.ToArray();
        }
    }
}