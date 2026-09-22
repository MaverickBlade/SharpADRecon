// Exporters.cs - 各格式导出器实现
// 提供 CSV、XML、JSON、HTML 四种格式的文件导出功能

using System;
using System.IO;
using System.Linq;
using System.Text;

namespace AdRecon.Export
{
    /// <summary>Writes a ModuleResult to CSV / XML / JSON / HTML mirroring the semantics of
    /// Export-ADRCSV/XML/JSON/HTML. Column order = file <header>. Encoding is UTF-8 (the
    /// original used ANSI CSVs; UTF-8 is consistent and Excel-safe).</summary>
    // 各格式导出器：将 ModuleResult 写入对应格式的文件
    public static class Exporters
    {
        // 导出为 CSV 格式文件
        public static void ToCsv(ModuleResult result, string filePath)
        {
            var sb = new StringBuilder();
            // 写入表头行
            if (result.Columns.Count > 0)
                sb.AppendLine(string.Join(",", result.Columns.Select(CsvEscape)));
            // 写入数据行
            foreach (AdRow row in result.Rows)
            {
                var vals = new string[result.Columns.Count];
                for (int i = 0; i < result.Columns.Count; i++)
                    vals[i] = CsvEscape(Convert.ToString(row.Get(result.Columns[i])));
                sb.AppendLine(string.Join(",", vals));
            }
            File.WriteAllText(filePath, sb.ToString(), new UTF8Encoding(true));
        }

        // CSV 字段转义：处理逗号、引号和换行符
        private static string CsvEscape(string s)
        {
            if (s == null) s = "";
            if (s.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0)
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        // 导出为 JSON 格式文件
        public static void ToJson(ModuleResult result, string filePath)
        {
            // 构建 JSON 数组，每个对象对应一行数据
            var sb = new StringBuilder();
            sb.Append('[');
            for (int i = 0; i < result.Rows.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append('\n');
                sb.Append(rowToJson(result, i));
            }
            if (result.Rows.Count > 0) sb.Append('\n');
            sb.Append(']');
            File.WriteAllText(filePath, sb.ToString(), new UTF8Encoding(false));
        }

        // 将单行数据转换为 JSON 对象字符串
        private static string rowToJson(ModuleResult result, int idx)
        {
            var row = result.Rows[idx];
            var sb = new StringBuilder();
            sb.Append('{');
            bool first = true;
            foreach (string col in result.Columns)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append(JsonEscape(col)).Append(':').Append(JsonEscape(Convert.ToString(row.Get(col))));
            }
            sb.Append('}');
            return sb.ToString();
        }

        // JSON 字符串转义：处理特殊字符和控制字符
        private static string JsonEscape(string s)
        {
            if (s == null) return "\"\"";
            var sb = new StringBuilder(s.Length + 8);
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        /// <summary>Produces an XML shape similar to ConvertTo-Xml -NoTypeInformation.</summary>
        // 导出为 XML 格式文件
        public static void ToXml(ModuleResult result, string filePath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<?xml version=\"1.0\"?>");
            sb.AppendLine("<Objects>");
            // 每行数据作为一个 Object 元素
            foreach (AdRow row in result.Rows)
            {
                sb.AppendLine("  <Object>");
                // 每列作为 Property 元素
                foreach (string col in result.Columns)
                {
                    sb.Append("    <Property Name=\"").Append(XmlEscape(col)).Append("\">")
                      .Append(XmlEscape(Convert.ToString(row.Get(col)))).AppendLine("</Property>");
                }
                sb.AppendLine("  </Object>");
            }
            sb.AppendLine("</Objects>");
            File.WriteAllText(filePath, sb.ToString(), new UTF8Encoding(true));
        }

        // XML 字符串转义：处理特殊 XML 字符
        private static string XmlEscape(string s)
        {
            if (s == null) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
                    .Replace("\"", "&quot;").Replace("'", "&apos;");
        }

        // 内联 CSS 样式表，定义 HTML 报告的外观样式
        public static readonly string HtmlHeader =
            "<style>" +
            "body{font-family:Calibri,Arial,sans-serif;margin:0;padding:12px}" +
            "h1{color:#2b579a;border-bottom:2px solid #2b579a;padding-bottom:4px}" +
            "table{border-collapse:collapse;width:100%;font-size:11pt}" +
            "th{position:sticky;top:0;background:#2b579a;color:#fff;padding:6px 8px;text-align:left;border:1px solid #1e3f70}" +
            "td{border:1px solid #ccc;padding:4px 8px;vertical-align:top;white-space:pre}" +
            "tr:nth-child(2n+1){background:#f2f6fb}" +
            "tr:hover{background:#dce9ff}" +
            "</style>";

        // 导出为 HTML 格式文件
        public static void ToHtml(ModuleResult result, string filePath)
        {
            var sb = new StringBuilder();
            // HTML 文档结构：DOCTYPE、head、body
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html><head><meta charset=\"utf-8\"><title>ADRecon</title>");
            sb.AppendLine(HtmlHeader);
            sb.AppendLine("</head><body>");
            // 模块名称作为标题
            sb.Append("<h1>").Append(XmlEscape(result.ModuleName)).AppendLine("</h1>");
            sb.AppendLine("<table>");
            // 表头行
            if (result.Columns.Count > 0)
            {
                sb.AppendLine("  <thead><tr>");
                foreach (string col in result.Columns)
                    sb.Append("    <th>").Append(XmlEscape(col)).AppendLine("</th>");
                sb.AppendLine("  </tr></thead>");
            }
            // 表格数据行
            sb.AppendLine("  <tbody>");
            foreach (AdRow row in result.Rows)
            {
                sb.AppendLine("    <tr>");
                foreach (string col in result.Columns)
                    sb.Append("      <td>").Append(XmlEscape(Convert.ToString(row.Get(col)))).AppendLine("</td>");
                sb.AppendLine("    </tr>");
            }
            sb.AppendLine("  </tbody>");
            sb.AppendLine("</table>");
            sb.AppendLine("</body></html>");
            File.WriteAllText(filePath, sb.ToString(), new UTF8Encoding(true));
        }

        /// <summary>Builds the HTML index/table-of-contents page from the HTML-Files folder.</summary>
        // 生成 HTML 索引页面，列出所有 HTML 报告文件的链接
        public static void WriteHtmlIndex(string htmlDir, string indexPath)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html><head><meta charset=\"utf-8\"><title>ADRecon</title>");
            sb.AppendLine(HtmlHeader);
            sb.AppendLine("</head><body>");
            sb.AppendLine("<h1>ADRecon Report</h1><ul>");
            // 扫描目录下所有 HTML 文件并生成链接列表
            if (Directory.Exists(htmlDir))
            {
                string[] files = Directory.GetFiles(htmlDir, "*.html");
                Array.Sort(files);
                foreach (string f in files)
                {
                    string name = Path.GetFileNameWithoutExtension(f);
                    // 跳过索引页面自身
                    if (name.Equals("Index", StringComparison.OrdinalIgnoreCase)) continue;
                    sb.Append("  <li><a href=\"").Append(XmlEscape(name + ".html")).Append("\">")
                      .Append(XmlEscape(name)).AppendLine("</a></li>");
                }
            }
            sb.AppendLine("</ul></body></html>");
            File.WriteAllText(indexPath, sb.ToString(), new UTF8Encoding(true));
        }
    }
}