using System;
using System.IO;
using System.Collections.Generic;

// Log.cs - 日志和控制台输出工具
// Provides centralized logging to console and optional transcript file.
// Mirrors ADRecon's banner conventions: "[*]" notice, "[-]" module, "[+]" success, "WARNING:".

namespace AdRecon.Core
{
    /// <summary>Console output + optional transcript logging. Mirrors ADRecon's banner
    /// conventions: "[*]" notice, "[-]" module banners, "[+]" success, "WARNING:" prefix.</summary>
    public static class Log
    {
        // When true, verbose and exception details are emitted
        public static bool Verbose = false;
        // Optional transcript writer (null when not logging to file)
        private static StreamWriter _transcript;

        // Starts logging to a file at the given path
        public static void StartTranscript(string path)
        {
            try
            {
                _transcript = new StreamWriter(path, false, System.Text.Encoding.UTF8);
                _transcript.AutoFlush = true;
                WriteLine("[*] Transcript started: " + path);
            }
            catch { _transcript = null; }
        }

        // Stops transcript logging and closes the file
        public static void StopTranscript()
        {
            if (_transcript != null)
            {
                _transcript.WriteLine("[*] Transcript stopped.");
                _transcript.Close();
                _transcript = null;
            }
        }

        // Internal: writes text to console and optionally to transcript
        private static void Emit(string text)
        {
            Console.Out.WriteLine(text);
            if (_transcript != null)
            {
                try { _transcript.WriteLine(DateTime.Now.ToString("HH:mm:ss ") + text); }
                catch { }
            }
        }

        // Plain line output
        public static void WriteLine(string text) { Emit(text); }
        // Notice prefix [*]
        public static void Notice(string text) { Emit("[*] " + text); }
        // Module banner prefix [-]
        public static void Module(string text) { Emit("[-] " + text); }
        // Success prefix [+]
        public static void Success(string text) { Emit("[+] " + text); }
        // Warning prefix WARNING:
        public static void Warning(string text) { Emit("WARNING: [*] " + text); }

        // Verbose output, only emitted when Verbose flag is true
        public static void VerboseLine(string text)
        {
            if (Verbose) Emit("[verbose] " + text);
        }

        // Logs exception details when verbose mode is enabled
        public static void Exception(string context, Exception ex)
        {
            if (Verbose)
            {
                Emit("[EXCEPTION] " + context + " :: " + ex.Message);
                if (ex.InnerException != null) Emit("[EXCEPTION] inner :: " + ex.InnerException.Message);
            }
        }
    }

    /// <summary>Small helper: unique timestamped output directory name, mirroring
    /// 'ADRecon-Report-<yyyyMMddHHmmss>' created in the current working directory.</summary>
    public static class OutputDirHelper
    {
        // Creates a timestamped output directory name under baseDir
        public static string CreateTimestampName(string baseDir, DateTime now)
        {
            string ts = now.ToString("yyyyMMddHHmmss");
            return Path.Combine(baseDir, "ADRecon-Report-" + ts);
        }

        /// <summary>Deletes an empty per-format sub-folder then the parent dir if empty.
        /// Mirrors Remove-EmptyADROutputDir.</summary>
        public static void RemoveEmpty(string outputDir, OutputTypeFlag types)
        {
            if (outputDir == null || outputDir.Length == 0 || !Directory.Exists(outputDir)) return;
            try
            {
                // Build list of format-specific subfolder names
                var subs = new List<string>();
                if ((types & OutputTypeFlag.CSV) != 0) subs.Add("CSV-Files");
                if ((types & OutputTypeFlag.XML) != 0) subs.Add("XML-Files");
                if ((types & OutputTypeFlag.JSON) != 0) subs.Add("JSON-Files");
                if ((types & OutputTypeFlag.HTML) != 0) subs.Add("HTML-Files");

                // Remove empty format subfolders
                foreach (string s in subs)
                {
                    string p = Path.Combine(outputDir, s);
                    if (Directory.Exists(p) &&
                        (Directory.GetFiles(p).Length == 0) &&
                        (Directory.GetDirectories(p).Length == 0))
                    {
                        Directory.Delete(p);
                    }
                }

                // Remove parent dir if also empty
                if (Directory.GetFiles(outputDir).Length == 0 &&
                    Directory.GetDirectories(outputDir).Length == 0)
                {
                    Directory.Delete(outputDir);
                }
            }
            catch { }
        }
    }
}