using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace AnyWhere.Telemetry
{
    internal static class TargetProcessMatcher
    {
        public static bool IsProtectedProcessName(string processName, IEnumerable<string> patterns)
        {
            if (string.IsNullOrWhiteSpace(processName) || patterns == null)
            {
                return false;
            }

            string name = Path.GetFileName(processName);
            string withoutExtension = Path.GetFileNameWithoutExtension(name);

            foreach (string rawPattern in patterns)
            {
                if (string.IsNullOrWhiteSpace(rawPattern))
                {
                    continue;
                }

                string pattern = Path.GetFileName(rawPattern.Trim());
                if (Matches(name, pattern) || Matches(withoutExtension, pattern) || Matches(name, Path.GetFileNameWithoutExtension(pattern)))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool Matches(string value, string wildcardPattern)
        {
            if (string.IsNullOrWhiteSpace(value) || string.IsNullOrWhiteSpace(wildcardPattern))
            {
                return false;
            }

            string regex = "^" + Regex.Escape(wildcardPattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
            return Regex.IsMatch(value, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }
    }
}
