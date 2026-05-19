using System;
using System.IO;

namespace AnyWhere.Telemetry
{
    internal static class KernelPathNormalizer
    {
        public static string NormalizeDriverPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return null;
            }

            string cleaned = ExtractImagePath(path.Trim());
            cleaned = Environment.ExpandEnvironmentVariables(cleaned);

            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string systemRootPrefix = "\\SystemRoot\\";
            if (cleaned.StartsWith(systemRootPrefix, StringComparison.OrdinalIgnoreCase))
            {
                cleaned = Path.Combine(windows, cleaned.Substring(systemRootPrefix.Length));
            }
            else if (cleaned.StartsWith("System32\\", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = Path.Combine(windows, cleaned);
            }
            else if (cleaned.StartsWith("\\??\\", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(4);
            }
            else if (cleaned.StartsWith("\\\\?\\", StringComparison.OrdinalIgnoreCase))
            {
                cleaned = cleaned.Substring(4);
            }

            try
            {
                return Path.GetFullPath(cleaned);
            }
            catch
            {
                return cleaned;
            }
        }

        public static string NormalizeFileName(string path)
        {
            string normalized = NormalizeDriverPath(path);
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return null;
            }

            try
            {
                return Path.GetFileName(normalized);
            }
            catch
            {
                return normalized;
            }
        }

        private static string ExtractImagePath(string path)
        {
            if (path.StartsWith("\"", StringComparison.Ordinal))
            {
                int endQuote = path.IndexOf('"', 1);
                if (endQuote > 1)
                {
                    return path.Substring(1, endQuote - 1);
                }
            }

            int sysIndex = path.IndexOf(".sys", StringComparison.OrdinalIgnoreCase);
            if (sysIndex >= 0)
            {
                return path.Substring(0, sysIndex + 4).Trim('"');
            }

            int firstSpace = path.IndexOf(' ');
            if (firstSpace > 0)
            {
                return path.Substring(0, firstSpace).Trim('"');
            }

            return path.Trim('"');
        }
    }
}
