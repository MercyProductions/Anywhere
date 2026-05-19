using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal static class CaseIntegrityManifestWriter
    {
        public static string WriteManifest(string folder)
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
            {
                return null;
            }

            string manifestPath = Path.Combine(folder, "case-integrity-manifest.json");
            List<FileManifestRecord> records = new List<FileManifestRecord>();
            string rollingHash = new string('0', 64);

            foreach (string path in Directory.EnumerateFiles(folder, "*", SearchOption.AllDirectories))
            {
                if (path.Equals(manifestPath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                FileInfo info;
                try
                {
                    info = new FileInfo(path);
                }
                catch
                {
                    continue;
                }

                string relativePath = MakeRelativePath(folder, path);
                string sha256 = TrySha256(path) ?? string.Empty;
                rollingHash = Sha256Hex(rollingHash + "|" + relativePath + "|" + sha256 + "|" + info.Length.ToString(CultureInfo.InvariantCulture));
                records.Add(new FileManifestRecord
                {
                    RelativePath = relativePath,
                    SizeBytes = info.Length,
                    ModifiedUtc = info.LastWriteTimeUtc,
                    Sha256 = sha256,
                    RollingHash = rollingHash
                });
            }

            StringBuilder builder = new StringBuilder();
            builder.Append("{");
            bool first = true;
            JsonUtilities.AppendStringProperty(builder, "created_utc", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "folder", folder, ref first);
            JsonUtilities.AppendStringProperty(builder, "file_count", records.Count.ToString(CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "folder_chain_sha256", rollingHash, ref first);
            builder.Append(",\"files\":[");

            bool firstFile = true;
            foreach (FileManifestRecord record in records)
            {
                if (!firstFile)
                {
                    builder.Append(",");
                }

                builder.Append("{");
                bool firstProperty = true;
                JsonUtilities.AppendStringProperty(builder, "relative_path", record.RelativePath, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "size_bytes", record.SizeBytes.ToString(CultureInfo.InvariantCulture), ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "modified_utc", record.ModifiedUtc.ToString("o", CultureInfo.InvariantCulture), ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "sha256", record.Sha256, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "rolling_hash", record.RollingHash, ref firstProperty);
                builder.Append("}");
                firstFile = false;
            }

            builder.Append("]}");
            File.WriteAllText(manifestPath, builder.ToString(), Encoding.UTF8);
            return manifestPath;
        }

        public static string TryCreateArchive(string folder)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
                {
                    return null;
                }

                string archivePath = folder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + ".zip";
                if (File.Exists(archivePath))
                {
                    archivePath = folder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + "-" +
                                  DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + ".zip";
                }

                ZipFile.CreateFromDirectory(folder, archivePath, CompressionLevel.Optimal, false);
                return archivePath;
            }
            catch
            {
                return null;
            }
        }

        public static string TryMirrorFolder(string sourceFolder, string mirrorRoot)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sourceFolder) ||
                    string.IsNullOrWhiteSpace(mirrorRoot) ||
                    !Directory.Exists(sourceFolder))
                {
                    return null;
                }

                Directory.CreateDirectory(mirrorRoot);
                string destination = Path.Combine(mirrorRoot, Path.GetFileName(sourceFolder));
                if (Directory.Exists(destination))
                {
                    destination = destination + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
                }

                CopyDirectory(sourceFolder, destination);
                return destination;
            }
            catch
            {
                return null;
            }
        }

        private static void CopyDirectory(string source, string destination)
        {
            Directory.CreateDirectory(destination);

            foreach (string directory in Directory.EnumerateDirectories(source, "*", SearchOption.AllDirectories))
            {
                string relative = MakeRelativePath(source, directory);
                Directory.CreateDirectory(Path.Combine(destination, relative));
            }

            foreach (string file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
            {
                string relative = MakeRelativePath(source, file);
                string target = Path.Combine(destination, relative);
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                File.Copy(file, target, false);
            }
        }

        private static string TrySha256(string path)
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
            catch
            {
                return null;
            }
        }

        private static string Sha256Hex(string value)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(value ?? string.Empty));
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                }

                return builder.ToString();
            }
        }

        private static string MakeRelativePath(string root, string path)
        {
            Uri rootUri = new Uri(AppendDirectorySeparator(Path.GetFullPath(root)));
            Uri pathUri = new Uri(Path.GetFullPath(path));
            return Uri.UnescapeDataString(rootUri.MakeRelativeUri(pathUri).ToString()).Replace('/', Path.DirectorySeparatorChar);
        }

        private static string AppendDirectorySeparator(string path)
        {
            return path.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.OrdinalIgnoreCase)
                ? path
                : path + Path.DirectorySeparatorChar;
        }

        private sealed class FileManifestRecord
        {
            public string RelativePath { get; set; }

            public long SizeBytes { get; set; }

            public DateTime ModifiedUtc { get; set; }

            public string Sha256 { get; set; }

            public string RollingHash { get; set; }
        }
    }
}
