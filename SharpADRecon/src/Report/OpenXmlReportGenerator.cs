using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using AdRecon.Core;

// 文件作用：基于 OpenXML 格式生成 Excel (.xlsx) 报表，无需第三方 NuGet 依赖。
// 通过手动构建 XLSX 包的各个部件，将 CSV 数据写入独立的工作表。
namespace AdRecon.Report
{
    /// <summary>Raw OpenXML XLSX writer: one worksheet per CSV artifact, all cells as
    /// inline strings. No NuGet dependency - uses ZipArchive + hand-built package parts.
    /// Report name: &lt;DomainName&gt;-ADRecon-Report.xlsx.</summary>
    // OpenXML 报表生成器：将 ADRecon 采集的 CSV 数据转换为 Excel 工作簿。
    public sealed class OpenXmlReportGenerator : IReportGenerator
    {
        // OpenXML 所需的 XML 命名空间常量。
        private const string NS_SPREADSHEET = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
        private const string NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
        private const string NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships";
        private const string NS_CONTENT_TYPES = "http://schemas.openxmlformats.org/package/2006/content-types";

        // 主入口：加载 CSV 文件，构建 XLSX 包并写入磁盘。
        public string Generate(string csvDir, string outputDir, string logo)
        {
            if (!Directory.Exists(csvDir))
            {
                Log.Warning("[Export-ADRExcel] Could not locate the CSV-Files directory: " + csvDir + " Exiting");
                return "";
            }

            // 读取并解析所有 CSV 文件为内部数据结构。
            List<CsvSheet> sheets;
            try { sheets = LoadSheets(csvDir); }
            catch (Exception ex)
            {
                Log.Warning("[Export-ADRExcel] Failed to read CSV artifacts: " + ex.Message);
                return "";
            }
            if (sheets.Count == 0)
            {
                Log.Warning("[Export-ADRExcel] No CSV artifacts found in " + csvDir + "; no workbook generated.");
                return "";
            }

            // 从 Domain.csv 提取域名，构造输出文件名。
            string domain = ReportFactory.DomainNameFromCsv(csvDir);
            string fileName = (domain.Length > 0 ? domain + "-" : "") + "ADRecon-Report.xlsx";
            string full = Path.Combine(outputDir, fileName);

            try
            {
                // 使用 ZipArchive 创建 XLSX 包（本质是 ZIP 文件）。
                using (var fs = new FileStream(full, FileMode.Create, FileAccess.Write))
                using (var zip = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    WriteParts(zip, sheets);
                }
                Log.Success("Excelsheet Saved to: " + full + " (" + sheets.Count + " worksheets)");
                return full;
            }
            catch (Exception ex)
            {
                Log.Warning("[Export-ADRExcel] Failed to generate Excel report: " + ex.Message);
                try { if (File.Exists(full)) File.Delete(full); } catch { }
                return "";
            }
        }

        // ---------- Sheet model ----------

        // 内部数据结构：表示一个工作表，包含名称和所有行数据。
        private sealed class CsvSheet
        {
            public string Name;
            public List<string[]> Rows;
        }

        // 加载目录下所有 CSV 文件，每个文件转换为一个工作表。
        private static List<CsvSheet> LoadSheets(string csvDir)
        {
            var sheets = new List<CsvSheet>();
            string[] files = Directory.GetFiles(csvDir, "*.csv");
            Array.Sort(files);
            var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string f in files)
            {
                List<string[]> rows = ParseCsv(f);
                if (rows.Count == 0) continue;
                // 确保工作表名称唯一（Excel 不允许重复）。
                string name = UniqueSheetName(Path.GetFileNameWithoutExtension(f), used);
                used.Add(name);
                var s = new CsvSheet();
                s.Name = name;
                s.Rows = rows;
                sheets.Add(s);
            }
            return sheets;
        }

        // 生成唯一的工作表名称，若重复则追加序号。
        private static string UniqueSheetName(string raw, HashSet<string> used)
        {
            string name = SanitizeSheetName(raw);
            if (!used.Contains(name)) return name;
            int n = 2;
            while (used.Contains(name + " (" + n + ")")) n++;
            string s = name + " (" + n + ")";
            return SanitizeSheetName(s);
        }

        // 清理工作表名称中的非法字符并截断到 31 字符。
        private static string SanitizeSheetName(string s)
        {
            var sb = new StringBuilder(s.Length);
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '[' || c == ']' || c == ':' || c == '*' || c == '?' || c == '/' || c == '\\') continue;
                sb.Append(c);
            }
            if (sb.Length == 0) sb.Append("Sheet");
            if (sb.Length > 31) sb.Length = 31;
            return sb.ToString();
        }

        // ---------- CSV parsing (RFC-4180 with quoted newlines) ----------

        // 解析单个 CSV 文件，支持 RFC 4180 格式（引号内的换行和转义引号）。
        private static List<string[]> ParseCsv(string path)
        {
            var rows = new List<string[]>();
            string text = File.ReadAllText(path);
            var row = new List<string>();
            var cur = new StringBuilder();
            bool inQ = false;
            int i = 0, n = text.Length;
            while (i < n)
            {
                char c = text[i];
                if (inQ)
                {
                    if (c == '"')
                    {
                        // 处理转义的双引号 ("")。
                        if (i + 1 < n && text[i + 1] == '"') { cur.Append('"'); i += 2; continue; }
                        inQ = false; i++; continue;
                    }
                    cur.Append(c); i++; continue;
                }
                if (c == '"') { inQ = true; i++; }
                else if (c == ',') { row.Add(cur.ToString()); cur.Length = 0; i++; }
                else if (c == '\r') { i++; }
                else if (c == '\n')
                {
                    row.Add(cur.ToString()); cur.Length = 0;
                    rows.Add(row.ToArray()); row.Clear();
                    i++;
                }
                else { cur.Append(c); i++; }
            }
            if (cur.Length > 0 || row.Count > 0)
            {
                row.Add(cur.ToString());
                rows.Add(row.ToArray());
            }
            return rows;
        }

        // ---------- XLSX package parts ----------

        // 写入 XLSX 包的所有必要部件到 ZIP 归档中。
        private static void WriteParts(ZipArchive zip, List<CsvSheet> sheets)
        {
            WriteEntry(zip, "[Content_Types].xml", BuildContentTypes(sheets.Count));
            WriteEntry(zip, "_rels/.rels", BuildRootRels());
            WriteEntry(zip, "xl/workbook.xml", BuildWorkbook(sheets));
            WriteEntry(zip, "xl/_rels/workbook.xml.rels", BuildWorkbookRels(sheets.Count));
            WriteEntry(zip, "xl/styles.xml", BuildStyles());
            for (int i = 0; i < sheets.Count; i++)
                WriteEntry(zip, "xl/worksheets/sheet" + (i + 1) + ".xml", BuildSheetXml(sheets[i]));
        }

        // 向 ZIP 归档中写入单个条目（XML 文件）。
        private static void WriteEntry(ZipArchive zip, string name, string content)
        {
            ZipArchiveEntry e = zip.CreateEntry(name, CompressionLevel.Optimal);
            using (Stream s = e.Open())
            using (var w = new StreamWriter(s, new UTF8Encoding(false)))
                w.Write(content);
        }

        // 构建 [Content_Types].xml，定义包中各部件的 MIME 类型。
        private static string BuildContentTypes(int sheetCount)
        {
            var sb = new StringBuilder();
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            sb.Append("<Types xmlns=\"").Append(NS_CONTENT_TYPES).Append("\">");
            sb.Append("<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>");
            sb.Append("<Default Extension=\"xml\" ContentType=\"application/xml\"/>");
            sb.Append("<Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/>");
            sb.Append("<Override PartName=\"/xl/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml\"/>");
            for (int i = 1; i <= sheetCount; i++)
                sb.Append("<Override PartName=\"/xl/worksheets/sheet").Append(i)
                  .Append(".xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/>");
            sb.Append("</Types>");
            return sb.ToString();
        }

        // 构建根关系文件 _rels/.rels。
        private static string BuildRootRels()
        {
            var sb = new StringBuilder();
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            sb.Append("<Relationships xmlns=\"").Append(NS_PKG_REL).Append("\">");
            sb.Append("<Relationship Id=\"rId1\" Type=\"").Append(NS_REL)
              .Append("/officeDocument\" Target=\"xl/workbook.xml\"/>");
            sb.Append("</Relationships>");
            return sb.ToString();
        }

        // 构建工作簿 XML，列出所有工作表及其关系 ID。
        private static string BuildWorkbook(List<CsvSheet> sheets)
        {
            var sb = new StringBuilder();
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            sb.Append("<workbook xmlns=\"").Append(NS_SPREADSHEET)
              .Append("\" xmlns:r=\"").Append(NS_REL).Append("\">");
            sb.Append("<sheets>");
            for (int i = 0; i < sheets.Count; i++)
                sb.Append("<sheet name=\"").Append(XmlEscape(sheets[i].Name))
                  .Append("\" sheetId=\"").Append(i + 1)
                  .Append("\" r:id=\"rId").Append(i + 1).Append("\"/>");
            sb.Append("</sheets></workbook>");
            return sb.ToString();
        }

        // 构建工作簿关系文件，将工作表与样式关联到工作簿。
        private static string BuildWorkbookRels(int sheetCount)
        {
            var sb = new StringBuilder();
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            sb.Append("<Relationships xmlns=\"").Append(NS_PKG_REL).Append("\">");
            for (int i = 1; i <= sheetCount; i++)
                sb.Append("<Relationship Id=\"rId").Append(i)
                  .Append("\" Type=\"").Append(NS_REL).Append("/worksheet\" Target=\"worksheets/sheet")
                  .Append(i).Append(".xml\"/>");
            // Styles relationship must be last to keep rId numbering simple.
            // 样式关系必须放在最后，以简化 rId 编号。
            sb.Append("<Relationship Id=\"rId").Append(sheetCount + 1)
              .Append("\" Type=\"").Append(NS_REL).Append("/styles\" Target=\"styles.xml\"/>");
            sb.Append("</Relationships>");
            return sb.ToString();
        }

        // 构建基本样式定义（字体、填充、边框等）。
        private static string BuildStyles()
        {
            return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
                "<styleSheet xmlns=\"" + NS_SPREADSHEET + "\">" +
                "<fonts count=\"1\"><font><sz val=\"11\"/><name val=\"Calibri\"/></font></fonts>" +
                "<fills count=\"2\"><fill><patternFill patternType=\"none\"/></fill>" +
                "<fill><patternFill patternType=\"gray125\"/></fill></fills>" +
                "<borders count=\"1\"><border/></borders>" +
                "<cellStyleXfs count=\"1\"><xf/></cellStyleXfs>" +
                "<cellXfs count=\"1\"><xf/></cellXfs>" +
                "</styleSheet>";
        }

        // 构建单个工作表的 XML，将所有行作为内联字符串单元格写入。
        private static string BuildSheetXml(CsvSheet sheet)
        {
            var sb = new StringBuilder();
            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
            sb.Append("<worksheet xmlns=\"").Append(NS_SPREADSHEET).Append("\"><sheetData>");
            for (int r = 0; r < sheet.Rows.Count; r++)
            {
                string[] row = sheet.Rows[r];
                sb.Append("<row r=\"").Append(r + 1).Append("\">");
                for (int c = 0; c < row.Length; c++)
                {
                    sb.Append("<c r=\"").Append(ColRef(c)).Append(r + 1)
                      .Append("\" t=\"inlineStr\"><is><t xml:space=\"preserve\">")
                      .Append(XmlEscape(row[c]))
                      .Append("</t></is></c>");
                }
                sb.Append("</row>");
            }
            sb.Append("</sheetData></worksheet>");
            return sb.ToString();
        }

        // 将列索引（0-based）转换为 Excel 列字母（A, B, ... Z, AA, AB, ...）。
        private static string ColRef(int col)
        {
            string r = "";
            int v = col + 1;
            while (v > 0)
            {
                int m = (v - 1) % 26;
                r = (char)('A' + m) + r;
                v = (v - 1) / 26;
            }
            return r;
        }

        // 转义 XML 特殊字符以确保生成的 XML 合法。
        private static string XmlEscape(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder(s.Length);
            foreach (char c in s)
            {
                if (c == '&') sb.Append("&amp;");
                else if (c == '<') sb.Append("&lt;");
                else if (c == '>') sb.Append("&gt;");
                else if (c == '"') sb.Append("&quot;");
                else if (c == '\'') sb.Append("&apos;");
                else if (c == '\t' || c == '\n' || c == '\r' || c >= ' ')
                    sb.Append(c);
            }
            return sb.ToString();
        }
    }
}