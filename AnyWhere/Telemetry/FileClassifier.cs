using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal static class FileClassifier
    {
        private static readonly HashSet<string> ExecutableExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".msi", ".msp", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".wsh", ".hta", ".jar", ".lnk", ".cpl", ".ocx", ".drv"
        };

        public static bool IsLikelyExecutable(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            return ExecutableExtensions.Contains(Path.GetExtension(path));
        }

        public static bool IsLikelyDriver(string path)
        {
            return !string.IsNullOrWhiteSpace(path) &&
                   string.Equals(Path.GetExtension(path), ".sys", StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsLikelyDownloadLocation(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            return IsUnder(path, Path.Combine(userProfile, "Downloads")) ||
                   IsUnder(path, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), "..", "Downloads")) ||
                   IsUnder(path, Path.Combine(localAppData, "Temp")) ||
                   IsUnder(path, Path.Combine(localAppData, "Microsoft", "Windows", "INetCache")) ||
                   IsUnder(path, Path.Combine(localAppData, "Microsoft", "Edge", "User Data")) ||
                   IsUnder(path, Path.Combine(localAppData, "Google", "Chrome", "User Data")) ||
                   IsUnder(path, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), ""));
        }

        public static bool IsHighValuePersistencePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
            string commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            return IsUnder(path, startup) ||
                   IsUnder(path, commonStartup) ||
                   IsUnder(path, Path.Combine(programData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")) ||
                   IsUnder(path, Path.Combine(windows, "System32", "drivers")) ||
                   IsUnder(path, Path.Combine(windows, "Tasks")) ||
                   IsUnder(path, Path.Combine(windows, "System32", "Tasks"));
        }

        public static Dictionary<string, string> BuildFileDetails(string path, MonitorOptions options, bool includeHash)
        {
            Dictionary<string, string> details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(path))
            {
                return details;
            }

            details["extension"] = Path.GetExtension(path);
            details["is_executable_or_script"] = IsLikelyExecutable(path).ToString();
            details["is_download_location"] = IsLikelyDownloadLocation(path).ToString();
            details["is_persistence_location"] = IsHighValuePersistencePath(path).ToString();

            try
            {
                if (File.Exists(path))
                {
                    FileInfo info = new FileInfo(path);
                    details["size_bytes"] = info.Length.ToString(CultureInfo.InvariantCulture);
                    details["created_utc"] = info.CreationTimeUtc.ToString("o", CultureInfo.InvariantCulture);
                    details["modified_utc"] = info.LastWriteTimeUtc.ToString("o", CultureInfo.InvariantCulture);

                    if (includeHash && info.Length <= options.MaxHashBytes)
                    {
                        string hash = TrySha256(path);
                        if (!string.IsNullOrWhiteSpace(hash))
                        {
                            details["sha256"] = hash;
                        }
                    }

                    AddZoneIdentifierDetails(path, details);

                    if (IsLikelyExecutable(path))
                    {
                        string signer = TryGetSigner(path);
                        if (!string.IsNullOrWhiteSpace(signer))
                        {
                            details["signature_subject"] = signer;
                        }
                    }
                }
                else if (Directory.Exists(path))
                {
                    details["object_type"] = "directory";
                }
                else
                {
                    details["object_type"] = "missing";
                }
            }
            catch (Exception ex)
            {
                details["file_detail_error"] = ex.Message;
            }

            return details;
        }

        public static string TryCopyEvidence(string path, string logRoot, string bucket)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    return null;
                }

                FileInfo info = new FileInfo(path);
                if (info.Length > 250L * 1024L * 1024L)
                {
                    return null;
                }

                string evidenceRoot = Path.Combine(logRoot, "Evidence", SanitizeFileName(bucket));
                Directory.CreateDirectory(evidenceRoot);

                string stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff", CultureInfo.InvariantCulture);
                string destination = Path.Combine(evidenceRoot, stamp + "-" + SanitizeFileName(Path.GetFileName(path)));
                File.Copy(path, destination, false);
                return destination;
            }
            catch
            {
                return null;
            }
        }

        public static void AddZoneIdentifierDetails(string path, IDictionary<string, string> details)
        {
            string zoneText = TryReadAlternateDataStream(path, "Zone.Identifier");
            if (string.IsNullOrWhiteSpace(zoneText))
            {
                return;
            }

            details["has_mark_of_the_web"] = "True";
            string[] lines = zoneText.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string rawLine in lines)
            {
                int separator = rawLine.IndexOf('=');
                if (separator <= 0)
                {
                    continue;
                }

                string key = rawLine.Substring(0, separator).Trim();
                string value = rawLine.Substring(separator + 1).Trim();
                if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase))
                {
                    details["motw_zone_id"] = value;
                }
                else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase))
                {
                    details["motw_referrer_url"] = value;
                }
                else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase))
                {
                    details["motw_host_url"] = value;
                }
            }
        }

        public static bool HasMarkOfTheWeb(string path)
        {
            Dictionary<string, string> details = new Dictionary<string, string>();
            AddZoneIdentifierDetails(path, details);
            return details.ContainsKey("has_mark_of_the_web");
        }

        public static bool IsUnder(string path, string possibleParent)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(possibleParent))
                {
                    return false;
                }

                string fullPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string parent = Path.GetFullPath(possibleParent).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                if (fullPath.Equals(parent, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                parent += Path.DirectorySeparatorChar;
                return fullPath.StartsWith(parent, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private static string TrySha256(string path)
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        byte[] hash = sha256.ComputeHash(stream);
                        StringBuilder builder = new StringBuilder(hash.Length * 2);
                        foreach (byte b in hash)
                        {
                            builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                        }

                        return builder.ToString();
                    }
                }
                catch (IOException)
                {
                    Thread.Sleep(150);
                }
                catch
                {
                    return null;
                }
            }

            return null;
        }

        private static string TryReadAlternateDataStream(string path, string streamName)
        {
            try
            {
                if (!File.Exists(path))
                {
                    return null;
                }

                string adsPath = path + ":" + streamName;
                using (FileStream stream = new FileStream(adsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8, true))
                {
                    return reader.ReadToEnd();
                }
            }
            catch
            {
                return null;
            }
        }

        private static string TryGetSigner(string path)
        {
            try
            {
                X509Certificate certificate = X509Certificate.CreateFromSignedFile(path);
                return certificate == null ? null : certificate.Subject;
            }
            catch
            {
                return null;
            }
        }

        private static string SanitizeFileName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "unknown";
            }

            char[] invalid = Path.GetInvalidFileNameChars();
            StringBuilder builder = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                builder.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
            }

            return builder.ToString();
        }
    }
}
