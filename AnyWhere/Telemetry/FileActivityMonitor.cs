using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal sealed class FileActivityMonitor : IDetectionMonitor
    {
        private static readonly TimeSpan ShortLivedArtifactWindow = TimeSpan.FromMinutes(15);
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private readonly ConcurrentDictionary<string, DateTime> _recentEvents = new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, StagedArtifactRecord> _stagedArtifacts = new ConcurrentDictionary<string, StagedArtifactRecord>(StringComparer.OrdinalIgnoreCase);
        private bool _disposed;

        public FileActivityMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
        }

        public string Name
        {
            get { return "File Activity"; }
        }

        public void Start()
        {
            List<string> roots = BuildWatchRoots();
            foreach (string root in roots)
            {
                TryAddWatcher(root);
            }

            _logger.Log(DetectionEvent.Create(
                "File",
                "Baseline",
                EventSeverity.Low,
                "File monitor started with " + _watchers.Count.ToString(CultureInfo.InvariantCulture) + " watched roots.",
                null,
                null,
                new Dictionary<string, string> { { "watched_roots", string.Join(";", roots.ToArray()) } }));
        }

        private List<string> BuildWatchRoots()
        {
            List<string> roots = new List<string>();

            AddIfExists(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            AddIfExists(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"));
            AddIfExists(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"));
            AddIfExists(roots, Path.GetTempPath());
            AddIfExists(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Windows", "INetCache"));
            AddIfExists(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Edge", "User Data"));
            AddIfExists(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Google", "Chrome", "User Data"));
            AddIfExists(roots, Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            AddIfExists(roots, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
            AddIfExists(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"));
            AddIfExists(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
            AddIfExists(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks"));
            AddIfExists(roots, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Tasks"));

            if (_options.WatchAllFixedDrives)
            {
                foreach (DriveInfo drive in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (drive.IsReady && drive.DriveType == DriveType.Fixed)
                        {
                            AddIfExists(roots, drive.RootDirectory.FullName);
                        }
                    }
                    catch
                    {
                    }
                }
            }

            return RemoveNestedRoots(roots);
        }

        private void TryAddWatcher(string root)
        {
            try
            {
                FileSystemWatcher watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = true,
                    InternalBufferSize = 64 * 1024,
                    NotifyFilter = NotifyFilters.FileName |
                                   NotifyFilters.DirectoryName |
                                   NotifyFilters.CreationTime |
                                   NotifyFilters.LastWrite |
                                   NotifyFilters.Size |
                                   NotifyFilters.Security
                };

                watcher.Created += OnCreated;
                watcher.Deleted += OnDeleted;
                watcher.Changed += OnChanged;
                watcher.Renamed += OnRenamed;
                watcher.Error += OnError;
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogException("File", "WatcherFailed", ex, root);
            }
        }

        private void OnCreated(object sender, FileSystemEventArgs eventArgs)
        {
            QueueFileEvent("Created", eventArgs.FullPath, null);
        }

        private void OnDeleted(object sender, FileSystemEventArgs eventArgs)
        {
            QueueFileEvent("Deleted", eventArgs.FullPath, null);
        }

        private void OnChanged(object sender, FileSystemEventArgs eventArgs)
        {
            if (FileClassifier.IsLikelyExecutable(eventArgs.FullPath) || FileClassifier.IsHighValuePersistencePath(eventArgs.FullPath))
            {
                QueueFileEvent("Changed", eventArgs.FullPath, null);
            }
        }

        private void OnRenamed(object sender, RenamedEventArgs eventArgs)
        {
            QueueFileEvent("Renamed", eventArgs.FullPath, eventArgs.OldFullPath);
        }

        private void OnError(object sender, ErrorEventArgs eventArgs)
        {
            _logger.Log(DetectionEvent.Create(
                "File",
                "WatcherError",
                EventSeverity.Medium,
                "A file watcher reported an error. Some rapid file events may have been dropped.",
                null,
                null,
                new Dictionary<string, string> { { "exception", eventArgs.GetException().Message } }));
        }

        private void QueueFileEvent(string action, string path, string oldPath)
        {
            if (_disposed || ShouldSuppress(action, path))
            {
                return;
            }

            ThreadPool.QueueUserWorkItem(delegate
            {
                if (action.Equals("Created", StringComparison.OrdinalIgnoreCase) ||
                    action.Equals("Changed", StringComparison.OrdinalIgnoreCase) ||
                    action.Equals("Renamed", StringComparison.OrdinalIgnoreCase))
                {
                    Thread.Sleep(300);
                }

                LogFileEvent(action, path, oldPath);
            });
        }

        private void LogFileEvent(string action, string path, string oldPath)
        {
            try
            {
                bool includeHash = action.Equals("Created", StringComparison.OrdinalIgnoreCase) ||
                                   action.Equals("Renamed", StringComparison.OrdinalIgnoreCase);

                Dictionary<string, string> details = FileClassifier.BuildFileDetails(path, _options, includeHash);
                if (!string.IsNullOrWhiteSpace(oldPath))
                {
                    details["old_path"] = oldPath;
                }

                bool likelyDownload = IsLikelyDownloadEvent(action, path, details);
                bool executable = FileClassifier.IsLikelyExecutable(path);
                bool persistence = FileClassifier.IsHighValuePersistencePath(path);
                bool shortLivedStagingDelete = false;

                EventSeverity severity = EventSeverity.Low;
                string normalizedAction = action;
                if (likelyDownload)
                {
                    normalizedAction = "Downloaded";
                    severity = executable ? EventSeverity.High : EventSeverity.Medium;
                }
                else if (persistence && (action.Equals("Created", StringComparison.OrdinalIgnoreCase) ||
                                         action.Equals("Renamed", StringComparison.OrdinalIgnoreCase) ||
                                         action.Equals("Changed", StringComparison.OrdinalIgnoreCase)))
                {
                    severity = EventSeverity.High;
                }
                else if (executable || action.Equals("Deleted", StringComparison.OrdinalIgnoreCase))
                {
                    severity = EventSeverity.Medium;
                }

                ApplyShortLivedArtifactTracking(action, path, details, ref normalizedAction, ref severity, ref shortLivedStagingDelete);

                if (likelyDownload && executable && File.Exists(path))
                {
                    string evidencePath = FileClassifier.TryCopyEvidence(path, Path.GetDirectoryName(_logger.JsonLogPath), "Downloaded");
                    if (!string.IsNullOrWhiteSpace(evidencePath))
                    {
                        details["evidence_copy"] = evidencePath;
                    }
                }

                _logger.Log(DetectionEvent.Create(
                    "File",
                    normalizedAction,
                    severity,
                    shortLivedStagingDelete ? "Short-lived staging artifact deleted: " + path : BuildDescription(normalizedAction, path, oldPath),
                    path,
                    null,
                    details));
            }
            catch (Exception ex)
            {
                _logger.LogException("File", "EventFailed", ex, path);
            }
        }

        private void ApplyShortLivedArtifactTracking(
            string action,
            string path,
            Dictionary<string, string> details,
            ref string normalizedAction,
            ref EventSeverity severity,
            ref bool shortLivedStagingDelete)
        {
            DateTime now = DateTime.UtcNow;
            CleanupStagedArtifacts(now);

            if (action.Equals("Created", StringComparison.OrdinalIgnoreCase) ||
                action.Equals("Renamed", StringComparison.OrdinalIgnoreCase))
            {
                if (IsPotentialSpoofingStagingArtifact(path, details))
                {
                    _stagedArtifacts[path] = new StagedArtifactRecord
                    {
                        Path = path,
                        CreatedUtc = now,
                        Details = new Dictionary<string, string>(details, StringComparer.OrdinalIgnoreCase)
                    };
                }

                return;
            }

            if (!action.Equals("Deleted", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            StagedArtifactRecord record;
            if (!_stagedArtifacts.TryRemove(path, out record))
            {
                return;
            }

            TimeSpan lifetime = now.Subtract(record.CreatedUtc);
            if (lifetime > ShortLivedArtifactWindow)
            {
                return;
            }

            foreach (KeyValuePair<string, string> pair in record.Details)
            {
                if (!details.ContainsKey(pair.Key) && !string.IsNullOrWhiteSpace(pair.Value))
                {
                    details[pair.Key] = pair.Value;
                }
            }

            details["short_lived"] = "True";
            details["artifact_lifetime_seconds"] = Math.Max(0, lifetime.TotalSeconds).ToString("0", CultureInfo.InvariantCulture);
            details["short_lived_window_seconds"] = ShortLivedArtifactWindow.TotalSeconds.ToString("0", CultureInfo.InvariantCulture);
            details["cleanup_indicator"] = "short_lived_staging_artifact_deleted";
            normalizedAction = "ShortLivedStagingFileDeleted";
            severity = EventSeverity.High;
            shortLivedStagingDelete = true;
        }

        private void CleanupStagedArtifacts(DateTime now)
        {
            if (_stagedArtifacts.Count < 2048)
            {
                return;
            }

            foreach (KeyValuePair<string, StagedArtifactRecord> pair in _stagedArtifacts.ToArray())
            {
                if (now.Subtract(pair.Value.CreatedUtc) > ShortLivedArtifactWindow)
                {
                    StagedArtifactRecord ignored;
                    _stagedArtifacts.TryRemove(pair.Key, out ignored);
                }
            }
        }

        private static bool IsPotentialSpoofingStagingArtifact(string path, IDictionary<string, string> details)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            if (FileClassifier.IsLikelyExecutable(path))
            {
                return FileClassifier.IsLikelyDownloadLocation(path) ||
                       FileClassifier.IsHighValuePersistencePath(path);
            }

            string extension = Path.GetExtension(path);
            bool configLike = extension.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
                              extension.Equals(".ini", StringComparison.OrdinalIgnoreCase) ||
                              extension.Equals(".cfg", StringComparison.OrdinalIgnoreCase) ||
                              extension.Equals(".conf", StringComparison.OrdinalIgnoreCase) ||
                              extension.Equals(".toml", StringComparison.OrdinalIgnoreCase) ||
                              extension.Equals(".yaml", StringComparison.OrdinalIgnoreCase) ||
                              extension.Equals(".yml", StringComparison.OrdinalIgnoreCase) ||
                              extension.Equals(".dat", StringComparison.OrdinalIgnoreCase) ||
                              extension.Equals(".bin", StringComparison.OrdinalIgnoreCase);

            if (!configLike)
            {
                return false;
            }

            return FileClassifier.IsLikelyDownloadLocation(path) ||
                   ContainsAny(path, "\\temp\\", "\\appdata\\", "\\downloads\\", "\\desktop\\", "spoof", "hwid", "mapper", "serial", "mac");
        }

        private static bool IsLikelyDownloadEvent(string action, string path, IDictionary<string, string> details)
        {
            if (!action.Equals("Created", StringComparison.OrdinalIgnoreCase) &&
                !action.Equals("Renamed", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            bool motw = details.ContainsKey("has_mark_of_the_web");
            bool downloadLocation = details.ContainsKey("is_download_location") &&
                                    details["is_download_location"].Equals("True", StringComparison.OrdinalIgnoreCase);
            return motw || downloadLocation;
        }

        private static string BuildDescription(string action, string path, string oldPath)
        {
            string fileName = string.IsNullOrWhiteSpace(path) ? "unknown" : Path.GetFileName(path);
            if (action.Equals("Renamed", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(oldPath))
            {
                return "File renamed from " + oldPath + " to " + path;
            }

            return "File " + action.ToLowerInvariant() + ": " + fileName;
        }

        private bool ShouldSuppress(string action, string path)
        {
            string key = action + "|" + path;
            DateTime now = DateTime.UtcNow;
            DateTime previous;
            if (_recentEvents.TryGetValue(key, out previous) && (now - previous).TotalMilliseconds < 750)
            {
                return true;
            }

            _recentEvents[key] = now;

            if (_recentEvents.Count > 5000)
            {
                foreach (KeyValuePair<string, DateTime> pair in _recentEvents.ToArray())
                {
                    if ((now - pair.Value).TotalSeconds > 30)
                    {
                        DateTime removed;
                        _recentEvents.TryRemove(pair.Key, out removed);
                    }
                }
            }

            return false;
        }

        private static void AddIfExists(ICollection<string> roots, string path)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
                {
                    string fullPath = Path.GetFullPath(path);
                    if (!roots.Contains(fullPath, StringComparer.OrdinalIgnoreCase))
                    {
                        roots.Add(fullPath);
                    }
                }
            }
            catch
            {
            }
        }

        private static List<string> RemoveNestedRoots(IEnumerable<string> roots)
        {
            List<string> ordered = roots
                .Where(r => !string.IsNullOrWhiteSpace(r))
                .Select(r => Path.GetFullPath(r).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(r => r.Length)
                .ToList();

            List<string> result = new List<string>();
            foreach (string root in ordered)
            {
                bool nested = false;
                foreach (string existing in result)
                {
                    if (FileClassifier.IsUnder(root, existing))
                    {
                        nested = true;
                        break;
                    }
                }

                if (!nested)
                {
                    result.Add(root);
                }
            }

            return result;
        }

        private static bool ContainsAny(string value, params string[] terms)
        {
            if (string.IsNullOrWhiteSpace(value) || terms == null)
            {
                return false;
            }

            foreach (string term in terms)
            {
                if (!string.IsNullOrWhiteSpace(term) && value.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        public void Dispose()
        {
            _disposed = true;
            foreach (FileSystemWatcher watcher in _watchers)
            {
                try
                {
                    watcher.EnableRaisingEvents = false;
                    watcher.Dispose();
                }
                catch
                {
                }
            }

            _watchers.Clear();
        }

        private sealed class StagedArtifactRecord
        {
            public string Path { get; set; }
            public DateTime CreatedUtc { get; set; }
            public Dictionary<string, string> Details { get; set; }
        }
    }
}
