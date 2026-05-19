using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal sealed class TransientDriverMappingDetector : IDetectionMonitor
    {
        private static readonly TimeSpan ShortLivedWindow = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(15);
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly List<FileSystemWatcher> _watchers = new List<FileSystemWatcher>();
        private readonly ConcurrentDictionary<string, DriverStagingRecord> _records = new ConcurrentDictionary<string, DriverStagingRecord>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentQueue<RelatedSignal> _recentSignals = new ConcurrentQueue<RelatedSignal>();
        private readonly HashSet<string> _reportedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly string _root;
        private readonly string _caseRoot;
        private volatile bool _disposed;

        public TransientDriverMappingDetector(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _root = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Transient Driver Mapping");
            _caseRoot = Path.Combine(_root, "Cases");
        }

        public string Name
        {
            get { return "Transient Driver Mapping"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_root);
            Directory.CreateDirectory(_caseRoot);
            foreach (string root in BuildWatchRoots())
            {
                TryAddWatcher(root);
            }

            _logger.EventLogged += OnEventLogged;
            _logger.Log(DetectionEvent.Create(
                "TransientDriverMapping",
                "Started",
                EventSeverity.Low,
                "Transient driver mapping detector started in evidence-only mode.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "case_root", _caseRoot },
                    { "watch_roots", string.Join(";", BuildWatchRoots().ToArray()) },
                    { "short_lived_window_seconds", ShortLivedWindow.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) },
                    { "correlation_window_minutes", CorrelationWindow.TotalMinutes.ToString("0", CultureInfo.InvariantCulture) },
                    { "safety_rule", "Defensive evidence collection only; no driver unloading, patching, blocking, bypassing, or stealth behavior." }
                }));
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed ||
                detectionEvent == null ||
                detectionEvent.Category.StartsWith("TransientDriverMapping", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            RelatedSignal signal = RelatedSignal.FromEvent(detectionEvent);
            if (IsRelevant(signal))
            {
                _recentSignals.Enqueue(signal);
                CleanupRecentSignals();
            }

            if (signal.IsHardwareIdentityChange || signal.IsProtectedLaunch || signal.IsHiddenKernelIndicator)
            {
                CorrelateOpenRecords(signal);
            }
        }

        private void TryAddWatcher(string root)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
                {
                    return;
                }

                FileSystemWatcher watcher = new FileSystemWatcher(root, "*.sys")
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
                watcher.Changed += OnChanged;
                watcher.Renamed += OnRenamed;
                watcher.Deleted += OnDeleted;
                watcher.Error += OnError;
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                _logger.LogException("TransientDriverMapping", "WatcherFailed", ex, root);
            }
        }

        private void OnCreated(object sender, FileSystemEventArgs eventArgs)
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                Thread.Sleep(150);
                CaptureAppeared(eventArgs.FullPath, "Created", null);
            });
        }

        private void OnChanged(object sender, FileSystemEventArgs eventArgs)
        {
            DriverStagingRecord record;
            if (!_records.TryGetValue(eventArgs.FullPath, out record))
            {
                return;
            }

            record.LastWriteUtc = DateTimeOffset.UtcNow;
            record.WasWritten = true;
            EmitRecordEvent(record, "TransientDriverFileWritten", EventSeverity.Medium, "Recently staged driver file was written: " + eventArgs.FullPath, null);
        }

        private void OnRenamed(object sender, RenamedEventArgs eventArgs)
        {
            DriverStagingRecord record;
            if (_records.TryRemove(eventArgs.OldFullPath, out record))
            {
                record.RenamedFrom = eventArgs.OldFullPath;
                record.Path = eventArgs.FullPath;
                record.WasRenamed = true;
                _records[eventArgs.FullPath] = record;
                EmitRecordEvent(record, "TransientDriverFileRenamed", EventSeverity.High, "Transient driver file renamed from " + eventArgs.OldFullPath + " to " + eventArgs.FullPath, null);
                return;
            }

            CaptureAppeared(eventArgs.FullPath, "Renamed", eventArgs.OldFullPath);
        }

        private void OnDeleted(object sender, FileSystemEventArgs eventArgs)
        {
            DriverStagingRecord record;
            if (!_records.TryRemove(eventArgs.FullPath, out record))
            {
                record = new DriverStagingRecord
                {
                    Path = eventArgs.FullPath,
                    CreatedUtc = DateTimeOffset.UtcNow,
                    CaseId = BuildCaseId(eventArgs.FullPath),
                    DeletedUtc = DateTimeOffset.UtcNow
                };
            }

            record.DeletedUtc = DateTimeOffset.UtcNow;
            BuildAndEmitCase(record, "Deleted");
        }

        private void OnError(object sender, ErrorEventArgs eventArgs)
        {
            _logger.Log(DetectionEvent.Create(
                "TransientDriverMapping",
                "WatcherError",
                EventSeverity.Medium,
                "Transient driver watcher reported an error.",
                null,
                null,
                new Dictionary<string, string> { { "exception", eventArgs.GetException().Message } }));
        }

        private void CaptureAppeared(string path, string sourceAction, string oldPath)
        {
            if (_disposed || string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            DriverStagingRecord record = BuildRecord(path);
            if (record == null)
            {
                return;
            }

            if (!string.IsNullOrWhiteSpace(oldPath))
            {
                record.RenamedFrom = oldPath;
                record.WasRenamed = true;
            }

            _records[path] = record;
            EmitRecordEvent(
                record,
                "TransientDriverFileAppeared",
                IsUntrusted(record.SignatureStatus) ? EventSeverity.High : EventSeverity.Medium,
                "Transient driver file appeared in a high-risk staging path: " + path,
                null);
        }

        private DriverStagingRecord BuildRecord(string path)
        {
            try
            {
                if (!File.Exists(path))
                {
                    return null;
                }

                FileInfo info = new FileInfo(path);
                Dictionary<string, string> fileDetails = FileClassifier.BuildFileDetails(path, _options, includeHash: true);
                SignatureVerificationResult signature = AuthenticodeVerifier.VerifyFile(path);
                string evidencePath = FileClassifier.TryCopyEvidence(path, Path.GetDirectoryName(_logger.JsonLogPath), "TransientDrivers");
                PeMetadata metadata = PeMetadata.Read(path);

                DriverStagingRecord record = new DriverStagingRecord
                {
                    CaseId = BuildCaseId(path),
                    Path = path,
                    CreatedUtc = DateTimeOffset.UtcNow,
                    OriginalCreatedUtc = info.CreationTimeUtc,
                    LastWriteUtc = info.LastWriteTimeUtc,
                    SizeBytes = info.Length,
                    Sha256 = Detail(fileDetails, "sha256"),
                    EvidenceCopyPath = evidencePath,
                    SignatureStatus = signature.Status,
                    SignatureSubject = signature.Subject,
                    WinVerifyTrustStatus = signature.WinVerifyTrustStatus,
                    Entropy = CalculateEntropy(path, 4L * 1024L * 1024L),
                    PeSummary = metadata.Summary,
                    ImportSummary = metadata.ImportSummary,
                    ParentProcess = FindLikelyParentProcess(path)
                };

                foreach (KeyValuePair<string, string> pair in fileDetails)
                {
                    record.FileDetails[pair.Key] = pair.Value;
                }

                return record;
            }
            catch (Exception ex)
            {
                _logger.LogException("TransientDriverMapping", "DriverCaptureFailed", ex, path);
                return null;
            }
        }

        private void CorrelateOpenRecords(RelatedSignal signal)
        {
            foreach (DriverStagingRecord record in _records.Values.ToList())
            {
                if (signal.TimestampUtc.Subtract(record.CreatedUtc) < TimeSpan.Zero ||
                    signal.TimestampUtc.Subtract(record.CreatedUtc) > CorrelationWindow)
                {
                    continue;
                }

                record.RelatedSignals.Add(signal);
                if (signal.IsHardwareIdentityChange)
                {
                    EmitRecordEvent(record, "TransientDriverNearHwidChange", EventSeverity.High, "Transient driver staging appeared shortly before hardware identity activity.", signal);
                }
                else if (signal.IsProtectedLaunch)
                {
                    EmitRecordEvent(record, "TransientDriverNearProtectedLaunch", EventSeverity.High, "Transient driver staging appeared shortly before protected game launch.", signal);
                }
                else if (signal.IsHiddenKernelIndicator)
                {
                    EmitRecordEvent(record, "TransientDriverNearHiddenKernelIndicator", EventSeverity.Critical, "Transient driver staging appeared shortly before hidden-kernel indicators.", signal);
                }
            }
        }

        private void BuildAndEmitCase(DriverStagingRecord record, string reason)
        {
            List<RelatedSignal> related = RecentSignals(record.CreatedUtc.Subtract(TimeSpan.FromMinutes(2)), DateTimeOffset.UtcNow)
                .Where(s => IsRelatedToRecord(record, s))
                .Take(80)
                .ToList();
            foreach (RelatedSignal signal in related)
            {
                record.RelatedSignals.Add(signal);
            }

            TransientDriverCase driverCase = BuildCase(record, reason);
            string reportPath = WriteCaseReport(driverCase);
            EventSeverity severity = SeverityForCase(driverCase);
            string summary = BuildSummary(driverCase);

            _logger.Log(DetectionEvent.Create(
                "TransientDriverMapping",
                "TransientDriverMappingSuspected",
                severity,
                summary,
                record.Path,
                null,
                CaseDetails(driverCase, reportPath)));

            EmitKernelFollowUp(driverCase, reportPath);
        }

        private TransientDriverCase BuildCase(DriverStagingRecord record, string reason)
        {
            TransientDriverCase driverCase = new TransientDriverCase
            {
                CaseId = record.CaseId,
                Reason = reason,
                Record = record
            };

            double score = 0.20;
            TimeSpan lifetime = record.DeletedUtc.HasValue ? record.DeletedUtc.Value.Subtract(record.CreatedUtc) : TimeSpan.Zero;
            if (record.DeletedUtc.HasValue && lifetime <= ShortLivedWindow)
            {
                score += 0.24;
                driverCase.MatchedSignals.Add("sys_appeared_briefly_and_disappeared");
            }

            if (record.WasRenamed)
            {
                score += 0.08;
                driverCase.MatchedSignals.Add("sys_renamed_before_delete");
            }

            if (record.WasWritten)
            {
                score += 0.05;
                driverCase.MatchedSignals.Add("sys_written_after_create");
            }

            if (IsUntrusted(record.SignatureStatus))
            {
                score += 0.18;
                driverCase.MatchedSignals.Add("unsigned_or_untrusted_sys");
            }

            if (!string.IsNullOrWhiteSpace(record.ParentProcess))
            {
                score += 0.10;
                driverCase.MatchedSignals.Add("likely_loader_process");
            }

            AddRelatedScore(driverCase, record.RelatedSignals, ref score);
            driverCase.ConfidenceScore = Math.Min(0.99, score);
            return driverCase;
        }

        private static void AddRelatedScore(TransientDriverCase driverCase, IEnumerable<RelatedSignal> related, ref double score)
        {
            if (related.Any(s => s.IsSuspiciousLoader))
            {
                score += 0.12;
                driverCase.MatchedSignals.Add("suspicious_loader_process");
            }

            if (related.Any(s => s.IsVulnerableDriver))
            {
                score += 0.12;
                driverCase.MatchedSignals.Add("vulnerable_driver_usage");
            }

            if (related.Any(s => s.IsServiceActivity))
            {
                score += 0.10;
                driverCase.MatchedSignals.Add("driver_service_activity");
            }

            if (related.Any(s => s.IsCodeIntegrity))
            {
                score += 0.08;
                driverCase.MatchedSignals.Add("code_integrity_event");
            }

            if (related.Any(s => s.IsHiddenKernelIndicator))
            {
                score += 0.16;
                driverCase.MatchedSignals.Add("hidden_kernel_indicator_after_sys");
            }

            if (related.Any(s => s.IsDeviceOrCommunication))
            {
                score += 0.10;
                driverCase.MatchedSignals.Add("unknown_device_or_shared_memory_surface");
            }

            if (related.Any(s => s.IsTargetGameInteraction))
            {
                score += 0.12;
                driverCase.MatchedSignals.Add("game_process_interaction_after_sys");
            }

            if (related.Any(s => s.IsHardwareIdentityChange))
            {
                score += 0.16;
                driverCase.MatchedSignals.Add("hardware_identifier_changed_after_sys");
            }

            if (related.Any(s => s.IsCleanup))
            {
                score += 0.08;
                driverCase.MatchedSignals.Add("cleanup_after_session");
            }
        }

        private void EmitKernelFollowUp(TransientDriverCase driverCase, string reportPath)
        {
            _logger.Log(DetectionEvent.Create(
                "TransientDriverMapping",
                "KernelMemoryFollowUpRequested",
                driverCase.ConfidenceScore >= 0.70 ? EventSeverity.High : EventSeverity.Medium,
                "Transient driver deletion requests deeper defensive hidden-kernel follow-up scans.",
                reportPath,
                null,
                new Dictionary<string, string>
                {
                    { "case_id", driverCase.CaseId },
                    { "deleted_original_path", driverCase.Record.Path ?? string.Empty },
                    { "evidence_copy", driverCase.Record.EvidenceCopyPath ?? string.Empty },
                    { "requested_checks", "executable_kernel_memory_outside_known_modules;pe_like_kernel_headers;system_thread_starts_outside_modules;device_objects_without_backing_module;callbacks_outside_known_modules;dispatch_tables_to_unknown_memory" },
                    { "available_mode", "User-mode emits follow-up request and correlates visible evidence; kernel-only checks require signed defensive sensor." },
                    { "confidence_score", driverCase.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) },
                    { "evidence_report", reportPath ?? string.Empty },
                    { "safety_rule", "Read-only follow-up request; no unloading, patching, hooking, blocking, or stealth." }
                }));
        }

        private void EmitRecordEvent(DriverStagingRecord record, string action, EventSeverity severity, string description, RelatedSignal relatedSignal)
        {
            string key = action + "|" + record.Path + "|" + record.Sha256 + "|" + (relatedSignal == null ? string.Empty : relatedSignal.EventKey);
            lock (_reportedKeys)
            {
                if (!_reportedKeys.Add(key))
                {
                    return;
                }
            }

            Dictionary<string, string> details = RecordDetails(record);
            if (relatedSignal != null)
            {
                details["related_signal"] = relatedSignal.Category + "/" + relatedSignal.Action + " " + relatedSignal.Description;
                details["related_case_id"] = relatedSignal.CaseId ?? string.Empty;
            }

            _logger.Log(DetectionEvent.Create(
                "TransientDriverMapping",
                action,
                severity,
                description,
                record.Path,
                null,
                details));
        }

        private Dictionary<string, string> RecordDetails(DriverStagingRecord record)
        {
            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "case_id", record.CaseId ?? string.Empty },
                { "driver_path", record.Path ?? string.Empty },
                { "deleted_original_path", record.DeletedUtc.HasValue ? record.Path ?? string.Empty : string.Empty },
                { "renamed_from", record.RenamedFrom ?? string.Empty },
                { "evidence_copy", record.EvidenceCopyPath ?? string.Empty },
                { "sha256", record.Sha256 ?? string.Empty },
                { "size_bytes", record.SizeBytes.ToString(CultureInfo.InvariantCulture) },
                { "created_utc", record.CreatedUtc.ToString("o", CultureInfo.InvariantCulture) },
                { "deleted_utc", record.DeletedUtc.HasValue ? record.DeletedUtc.Value.ToString("o", CultureInfo.InvariantCulture) : string.Empty },
                { "lifetime_seconds", record.DeletedUtc.HasValue ? Math.Max(0, record.DeletedUtc.Value.Subtract(record.CreatedUtc).TotalSeconds).ToString("0", CultureInfo.InvariantCulture) : string.Empty },
                { "signature_status", record.SignatureStatus ?? string.Empty },
                { "signature_subject", record.SignatureSubject ?? string.Empty },
                { "winverifytrust_status", record.WinVerifyTrustStatus.ToString(CultureInfo.InvariantCulture) },
                { "entropy", record.Entropy.ToString("0.000", CultureInfo.InvariantCulture) },
                { "pe_metadata", record.PeSummary ?? string.Empty },
                { "import_summary", record.ImportSummary ?? string.Empty },
                { "likely_parent_process", record.ParentProcess ?? string.Empty },
                { "was_renamed", record.WasRenamed.ToString() },
                { "was_written", record.WasWritten.ToString() }
            };

            foreach (KeyValuePair<string, string> pair in record.FileDetails)
            {
                details[pair.Key] = pair.Value ?? string.Empty;
            }

            return details;
        }

        private static Dictionary<string, string> CaseDetails(TransientDriverCase driverCase, string reportPath)
        {
            DriverStagingRecord record = driverCase.Record;
            return new Dictionary<string, string>
            {
                { "case_id", driverCase.CaseId ?? string.Empty },
                { "driver_path", record.Path ?? string.Empty },
                { "deleted_original_path", record.Path ?? string.Empty },
                { "evidence_copy", record.EvidenceCopyPath ?? string.Empty },
                { "sha256", record.Sha256 ?? string.Empty },
                { "signature_status", record.SignatureStatus ?? string.Empty },
                { "signature_subject", record.SignatureSubject ?? string.Empty },
                { "lifetime_seconds", record.DeletedUtc.HasValue ? Math.Max(0, record.DeletedUtc.Value.Subtract(record.CreatedUtc).TotalSeconds).ToString("0", CultureInfo.InvariantCulture) : string.Empty },
                { "likely_parent_process", record.ParentProcess ?? string.Empty },
                { "matched_signals", string.Join(";", driverCase.MatchedSignals.OrderBy(v => v).ToArray()) },
                { "related_timeline", FormatRelatedTimeline(record.RelatedSignals) },
                { "confidence_score", driverCase.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) },
                { "evidence_report", reportPath ?? string.Empty },
                { "safety_rule", "Evidence-only transient-driver mapping detection; no unload, patch, block, hook, hide, or bypass behavior." }
            };
        }

        private string WriteCaseReport(TransientDriverCase driverCase)
        {
            string folder = Path.Combine(_caseRoot, SanitizeFileName(driverCase.CaseId));
            Directory.CreateDirectory(folder);
            string path = Path.Combine(folder, "transient-driver-report.json");
            StringBuilder builder = new StringBuilder();
            bool first = true;
            DriverStagingRecord record = driverCase.Record;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "case_id", driverCase.CaseId, ref first);
            JsonUtilities.AppendStringProperty(builder, "summary", BuildSummary(driverCase), ref first);
            JsonUtilities.AppendNumberProperty(builder, "confidence_score", driverCase.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "matched_signals", string.Join(";", driverCase.MatchedSignals.OrderBy(v => v).ToArray()), ref first);
            JsonUtilities.AppendStringProperty(builder, "driver_path", record.Path, ref first);
            JsonUtilities.AppendStringProperty(builder, "renamed_from", record.RenamedFrom, ref first);
            JsonUtilities.AppendStringProperty(builder, "deleted_original_path", record.DeletedUtc.HasValue ? record.Path : string.Empty, ref first);
            JsonUtilities.AppendStringProperty(builder, "evidence_copy", record.EvidenceCopyPath, ref first);
            JsonUtilities.AppendStringProperty(builder, "sha256", record.Sha256, ref first);
            JsonUtilities.AppendStringProperty(builder, "signature_status", record.SignatureStatus, ref first);
            JsonUtilities.AppendStringProperty(builder, "signature_subject", record.SignatureSubject, ref first);
            JsonUtilities.AppendNumberProperty(builder, "size_bytes", record.SizeBytes.ToString(CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendNumberProperty(builder, "entropy", record.Entropy.ToString("0.000", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "pe_metadata", record.PeSummary, ref first);
            JsonUtilities.AppendStringProperty(builder, "import_summary", record.ImportSummary, ref first);
            JsonUtilities.AppendStringProperty(builder, "created_utc", record.CreatedUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "deleted_utc", record.DeletedUtc.HasValue ? record.DeletedUtc.Value.ToString("o", CultureInfo.InvariantCulture) : string.Empty, ref first);
            JsonUtilities.AppendStringProperty(builder, "likely_parent_process", record.ParentProcess, ref first);
            AppendRelatedSignals(builder, record.RelatedSignals, ref first);
            builder.Append("}");
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
            CaseIntegrityManifestWriter.WriteManifest(folder);
            return path;
        }

        private static void AppendRelatedSignals(StringBuilder builder, IEnumerable<RelatedSignal> signals, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"related_signals\":[");
            bool firstSignal = true;
            foreach (RelatedSignal signal in signals.OrderBy(s => s.TimestampUtc).Take(100))
            {
                if (!firstSignal) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "timestamp_utc", signal.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref child);
                JsonUtilities.AppendStringProperty(builder, "category", signal.Category, ref child);
                JsonUtilities.AppendStringProperty(builder, "action", signal.Action, ref child);
                JsonUtilities.AppendStringProperty(builder, "severity", signal.Severity.ToString(), ref child);
                JsonUtilities.AppendStringProperty(builder, "description", signal.Description, ref child);
                JsonUtilities.AppendStringProperty(builder, "path", signal.Path, ref child);
                JsonUtilities.AppendStringProperty(builder, "process_name", signal.ProcessName, ref child);
                JsonUtilities.AppendStringProperty(builder, "case_id", signal.CaseId, ref child);
                builder.Append("}");
                firstSignal = false;
            }

            builder.Append("]");
            first = false;
        }

        private static string BuildSummary(TransientDriverCase driverCase)
        {
            DriverStagingRecord record = driverCase.Record;
            string lifetime = record.DeletedUtc.HasValue
                ? Math.Max(0, record.DeletedUtc.Value.Subtract(record.CreatedUtc).TotalSeconds).ToString("0", CultureInfo.InvariantCulture)
                : "unknown";
            List<string> parts = new List<string>
            {
                "Transient driver file appeared at " + record.Path,
                "copied to evidence " + (record.EvidenceCopyPath ?? "unavailable"),
                "deleted after " + lifetime + " seconds"
            };

            if (driverCase.MatchedSignals.Contains("hardware_identifier_changed_after_sys"))
            {
                parts.Add("followed by HWID changes");
            }

            if (driverCase.MatchedSignals.Contains("hidden_kernel_indicator_after_sys"))
            {
                parts.Add("followed by hidden-kernel indicators");
            }

            if (driverCase.MatchedSignals.Contains("game_process_interaction_after_sys"))
            {
                parts.Add("followed by protected game process interaction");
            }

            return string.Join(", ", parts.ToArray()) + ".";
        }

        private static EventSeverity SeverityForCase(TransientDriverCase driverCase)
        {
            if (driverCase.ConfidenceScore >= 0.86) return EventSeverity.Critical;
            if (driverCase.ConfidenceScore >= 0.62) return EventSeverity.High;
            if (driverCase.ConfidenceScore >= 0.40) return EventSeverity.Medium;
            return EventSeverity.Low;
        }

        private string FindLikelyParentProcess(string path)
        {
            string directory = Path.GetDirectoryName(path) ?? string.Empty;
            RelatedSignal best = RecentSignals(DateTimeOffset.UtcNow.Subtract(TimeSpan.FromMinutes(2)), DateTimeOffset.UtcNow)
                .Where(s => s.IsProcessStart)
                .OrderByDescending(s => ScoreParentProcess(path, directory, s))
                .FirstOrDefault(s => ScoreParentProcess(path, directory, s) > 0);

            if (best != null)
            {
                return best.ProcessName + " pid=" + (best.ProcessId.HasValue ? best.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : string.Empty) + " path=" + best.Path;
            }

            return string.Empty;
        }

        private static int ScoreParentProcess(string driverPath, string driverDirectory, RelatedSignal signal)
        {
            string text = (signal.Description + " " + signal.Path + " " + signal.CommandLine).ToLowerInvariant();
            int score = 0;
            if (!string.IsNullOrWhiteSpace(driverPath) && text.IndexOf(driverPath.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase) >= 0) score += 5;
            if (!string.IsNullOrWhiteSpace(driverDirectory) && text.IndexOf(driverDirectory.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase) >= 0) score += 3;
            if (signal.IsSuspiciousLoader) score += 3;
            if (FileClassifier.IsLikelyDownloadLocation(signal.Path)) score += 2;
            return score;
        }

        private List<RelatedSignal> RecentSignals(DateTimeOffset fromUtc, DateTimeOffset toUtc)
        {
            return _recentSignals
                .ToArray()
                .Where(s => s.TimestampUtc >= fromUtc && s.TimestampUtc <= toUtc)
                .OrderBy(s => s.TimestampUtc)
                .ToList();
        }

        private void CleanupRecentSignals()
        {
            DateTimeOffset cutoff = DateTimeOffset.UtcNow.Subtract(CorrelationWindow.Add(TimeSpan.FromMinutes(5)));
            while (_recentSignals.TryPeek(out RelatedSignal signal) && signal.TimestampUtc < cutoff)
            {
                RelatedSignal ignored;
                _recentSignals.TryDequeue(out ignored);
            }
        }

        private static bool IsRelevant(RelatedSignal signal)
        {
            return signal.IsProcessStart ||
                   signal.IsSuspiciousLoader ||
                   signal.IsVulnerableDriver ||
                   signal.IsServiceActivity ||
                   signal.IsCodeIntegrity ||
                   signal.IsHiddenKernelIndicator ||
                   signal.IsDeviceOrCommunication ||
                   signal.IsTargetGameInteraction ||
                   signal.IsHardwareIdentityChange ||
                   signal.IsProtectedLaunch ||
                   signal.IsCleanup ||
                   signal.Severity >= EventSeverity.High;
        }

        private static bool IsRelatedToRecord(DriverStagingRecord record, RelatedSignal signal)
        {
            if (signal.TimestampUtc.Subtract(record.CreatedUtc) < TimeSpan.FromMinutes(-2) ||
                signal.TimestampUtc.Subtract(record.CreatedUtc) > CorrelationWindow)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(record.Sha256) && signal.Text.IndexOf(record.Sha256, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            if (!string.IsNullOrWhiteSpace(record.Path) && signal.Text.IndexOf(record.Path, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return signal.IsSuspiciousLoader ||
                   signal.IsVulnerableDriver ||
                   signal.IsServiceActivity ||
                   signal.IsCodeIntegrity ||
                   signal.IsHiddenKernelIndicator ||
                   signal.IsDeviceOrCommunication ||
                   signal.IsTargetGameInteraction ||
                   signal.IsHardwareIdentityChange ||
                   signal.IsProtectedLaunch ||
                   signal.IsCleanup;
        }

        private static string FormatRelatedTimeline(IEnumerable<RelatedSignal> signals)
        {
            return string.Join(" || ", signals
                .OrderBy(s => s.TimestampUtc)
                .Take(40)
                .Select(s => s.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + " " + s.Category + "/" + s.Action + " " + Trim(s.Description, 140))
                .ToArray());
        }

        private static bool IsUntrusted(string status)
        {
            return string.IsNullOrWhiteSpace(status) ||
                   !status.Equals("Trusted", StringComparison.OrdinalIgnoreCase);
        }

        private static IEnumerable<string> BuildWatchRoots()
        {
            string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            yield return Path.GetTempPath();
            yield return Path.Combine(user, "Downloads");
            yield return Path.Combine(user, "Desktop");
            yield return local;
            yield return roaming;
            yield return programData;
            yield return Path.Combine(windows, "Temp");
            yield return Path.Combine(windows, "System32", "drivers");
            yield return Path.Combine(windows, "System32", "DriverStore", "FileRepository");
            yield return Path.Combine(windows, "System32", "config", "systemprofile", "AppData", "Local", "Temp");
        }

        private static double CalculateEntropy(string path, long maxBytes)
        {
            try
            {
                long[] counts = new long[256];
                long total = 0;
                byte[] buffer = new byte[8192];
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    int read;
                    while (total < maxBytes && (read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, maxBytes - total))) > 0)
                    {
                        total += read;
                        for (int i = 0; i < read; i++)
                        {
                            counts[buffer[i]]++;
                        }
                    }
                }

                if (total == 0) return 0;
                double entropy = 0;
                foreach (long count in counts)
                {
                    if (count == 0) continue;
                    double p = (double)count / total;
                    entropy -= p * (Math.Log(p) / Math.Log(2));
                }

                return entropy;
            }
            catch
            {
                return 0;
            }
        }

        private static string Detail(IDictionary<string, string> details, string key)
        {
            string value;
            return details != null && details.TryGetValue(key, out value) ? value ?? string.Empty : string.Empty;
        }

        private static string BuildCaseId(string value)
        {
            return "TDRV-" + DateTime.UtcNow.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + "-" +
                   HashText(value ?? string.Empty).Substring(0, 8).ToUpperInvariant();
        }

        private static string HashText(string text)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(text ?? string.Empty);
                byte[] hash = sha.ComputeHash(bytes);
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                }

                return builder.ToString();
            }
        }

        private static string Trim(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            {
                return value ?? string.Empty;
            }

            return value.Substring(0, Math.Max(0, maxLength - 3)) + "...";
        }

        private static string SanitizeFileName(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "case";
            char[] invalid = Path.GetInvalidFileNameChars();
            StringBuilder builder = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                builder.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
            }

            return builder.ToString();
        }

        public void Dispose()
        {
            _disposed = true;
            _logger.EventLogged -= OnEventLogged;
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

        private sealed class DriverStagingRecord
        {
            public DriverStagingRecord()
            {
                FileDetails = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                RelatedSignals = new List<RelatedSignal>();
            }

            public string CaseId { get; set; }
            public string Path { get; set; }
            public string RenamedFrom { get; set; }
            public DateTimeOffset CreatedUtc { get; set; }
            public DateTimeOffset? DeletedUtc { get; set; }
            public DateTimeOffset OriginalCreatedUtc { get; set; }
            public DateTimeOffset LastWriteUtc { get; set; }
            public long SizeBytes { get; set; }
            public string Sha256 { get; set; }
            public string EvidenceCopyPath { get; set; }
            public string SignatureStatus { get; set; }
            public string SignatureSubject { get; set; }
            public int WinVerifyTrustStatus { get; set; }
            public double Entropy { get; set; }
            public string PeSummary { get; set; }
            public string ImportSummary { get; set; }
            public string ParentProcess { get; set; }
            public bool WasRenamed { get; set; }
            public bool WasWritten { get; set; }
            public Dictionary<string, string> FileDetails { get; private set; }
            public List<RelatedSignal> RelatedSignals { get; private set; }
        }

        private sealed class TransientDriverCase
        {
            public TransientDriverCase()
            {
                MatchedSignals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            public string CaseId { get; set; }
            public string Reason { get; set; }
            public DriverStagingRecord Record { get; set; }
            public double ConfidenceScore { get; set; }
            public HashSet<string> MatchedSignals { get; private set; }
        }

        private sealed class RelatedSignal
        {
            public DateTimeOffset TimestampUtc { get; private set; }
            public string EventKey { get; private set; }
            public string Category { get; private set; }
            public string Action { get; private set; }
            public EventSeverity Severity { get; private set; }
            public string Description { get; private set; }
            public string Path { get; private set; }
            public int? ProcessId { get; private set; }
            public string ProcessName { get; private set; }
            public string CommandLine { get; private set; }
            public string CaseId { get; private set; }
            public string Text { get; private set; }
            public bool IsProcessStart { get; private set; }
            public bool IsSuspiciousLoader { get; private set; }
            public bool IsVulnerableDriver { get; private set; }
            public bool IsServiceActivity { get; private set; }
            public bool IsCodeIntegrity { get; private set; }
            public bool IsHiddenKernelIndicator { get; private set; }
            public bool IsDeviceOrCommunication { get; private set; }
            public bool IsTargetGameInteraction { get; private set; }
            public bool IsHardwareIdentityChange { get; private set; }
            public bool IsProtectedLaunch { get; private set; }
            public bool IsCleanup { get; private set; }

            public static RelatedSignal FromEvent(DetectionEvent detectionEvent)
            {
                string details = detectionEvent.Details == null
                    ? string.Empty
                    : string.Join(" ", detectionEvent.Details.Select(p => p.Key + " " + p.Value).ToArray());
                string text = ((detectionEvent.Category ?? string.Empty) + " " +
                               (detectionEvent.Action ?? string.Empty) + " " +
                               (detectionEvent.Description ?? string.Empty) + " " +
                               (detectionEvent.Path ?? string.Empty) + " " +
                               (detectionEvent.ProcessName ?? string.Empty) + " " +
                               details).ToLowerInvariant();
                string action = detectionEvent.Action ?? string.Empty;
                string category = detectionEvent.Category ?? string.Empty;

                return new RelatedSignal
                {
                    TimestampUtc = detectionEvent.TimestampUtc,
                    Category = category,
                    Action = action,
                    Severity = detectionEvent.Severity,
                    Description = detectionEvent.Description ?? string.Empty,
                    Path = detectionEvent.Path ?? string.Empty,
                    ProcessId = detectionEvent.ProcessId,
                    ProcessName = detectionEvent.ProcessName ?? Detail(detectionEvent.Details, "process_name"),
                    CommandLine = Detail(detectionEvent.Details, "command_line"),
                    CaseId = FirstNonEmpty(Detail(detectionEvent.Details, "case_id"), Detail(detectionEvent.Details, "behavior_case_id"), Detail(detectionEvent.Details, "launch_session_case_id")),
                    Text = text,
                    EventKey = detectionEvent.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + "|" + category + "|" + action + "|" + detectionEvent.Path,
                    IsProcessStart = category.Equals("Process", StringComparison.OrdinalIgnoreCase) && ContainsAny(action, "Executed", "Created", "Started"),
                    IsSuspiciousLoader = ContainsAny(text, "suspiciousdriverloaderprocess", "kdmapper", "drvmap", "mapper", "vulnerable-driver-loader", "iqvw", "gdrv", "capcom", "rtcore", "winio", "type= kernel"),
                    IsVulnerableDriver = ContainsAny(text, "vulnerable driver", "iqvw", "gdrv", "capcom", "dbutil", "rtcore", "winio", "kdu"),
                    IsServiceActivity = ContainsAny(action, "ServiceInstalled", "ServiceControlStateChange", "ServiceRunningModuleMissing", "ServiceRemoved") || ContainsAny(text, "service", "scm", "7045"),
                    IsCodeIntegrity = category.IndexOf("CodeIntegrity", StringComparison.OrdinalIgnoreCase) >= 0 || ContainsAny(action, "CodeIntegrity"),
                    IsHiddenKernelIndicator = category.StartsWith("HiddenKernel", StringComparison.OrdinalIgnoreCase) || ContainsAny(text, "hidden kernel", "hiddenkernel", "loadedmodulenoservice", "servicerunningmodulemissing"),
                    IsDeviceOrCommunication = category.StartsWith("KernelComm", StringComparison.OrdinalIgnoreCase) || ContainsAny(text, "device object", "\\device\\", "shared section", "named pipe", "communicationchain"),
                    IsTargetGameInteraction = category.StartsWith("TargetInteraction", StringComparison.OrdinalIgnoreCase) || ContainsAny(text, "protected target", "game process", "vm_write", "processopenedprotectedtarget"),
                    IsHardwareIdentityChange = category.StartsWith("HardwareIdentity", StringComparison.OrdinalIgnoreCase) && ContainsAny(action, "HardwareIdentifier", "HwidSpooferProfile", "HardwareChangeAttributed", "SpooferCleanupTraceDetected"),
                    IsProtectedLaunch = ContainsAny(action, "PreLaunchIdentityAudit", "ProtectedGameLaunchBoundary") || ContainsAny(text, "protected process", "protected game"),
                    IsCleanup = ContainsAny(action, "SpooferCleanupTraceDetected", "ShortLivedStagingFileDeleted", "AuditLogCleared", "DriverFileDeleted") || ContainsAny(text, "cleanup", "deleted after", "reverted_identifiers")
                };
            }
        }

        private sealed class PeMetadata
        {
            public string Summary { get; private set; }
            public string ImportSummary { get; private set; }

            public static PeMetadata Read(string path)
            {
                PeMetadata metadata = new PeMetadata { Summary = "unavailable", ImportSummary = string.Empty };
                try
                {
                    byte[] bytes = File.ReadAllBytes(path);
                    if (bytes.Length < 0x100 || ReadUInt16(bytes, 0) != 0x5A4D)
                    {
                        metadata.Summary = "not_pe";
                        return metadata;
                    }

                    int peOffset = ReadInt32(bytes, 0x3C);
                    if (peOffset <= 0 || peOffset + 0x108 >= bytes.Length || ReadUInt32(bytes, peOffset) != 0x00004550)
                    {
                        metadata.Summary = "invalid_pe";
                        return metadata;
                    }

                    ushort machine = ReadUInt16(bytes, peOffset + 4);
                    ushort sections = ReadUInt16(bytes, peOffset + 6);
                    uint timestamp = ReadUInt32(bytes, peOffset + 8);
                    ushort optionalSize = ReadUInt16(bytes, peOffset + 20);
                    int optionalOffset = peOffset + 24;
                    ushort magic = ReadUInt16(bytes, optionalOffset);
                    bool pe32Plus = magic == 0x20b;
                    ushort subsystem = ReadUInt16(bytes, optionalOffset + (pe32Plus ? 0x5C : 0x44));
                    uint importRva = ReadUInt32(bytes, optionalOffset + (pe32Plus ? 0x70 : 0x60) + 8);
                    int sectionOffset = optionalOffset + optionalSize;
                    List<SectionInfo> sectionInfos = ReadSections(bytes, sectionOffset, sections);
                    metadata.ImportSummary = ReadImports(bytes, importRva, sectionInfos);
                    metadata.Summary = "machine=0x" + machine.ToString("X", CultureInfo.InvariantCulture) +
                                       ";sections=" + sections.ToString(CultureInfo.InvariantCulture) +
                                       ";timestamp=" + timestamp.ToString(CultureInfo.InvariantCulture) +
                                       ";subsystem=" + subsystem.ToString(CultureInfo.InvariantCulture) +
                                       ";pe32_plus=" + pe32Plus.ToString();
                }
                catch
                {
                    metadata.Summary = "parse_failed";
                }

                return metadata;
            }

            private static List<SectionInfo> ReadSections(byte[] bytes, int offset, int count)
            {
                List<SectionInfo> sections = new List<SectionInfo>();
                for (int i = 0; i < count; i++)
                {
                    int p = offset + i * 40;
                    if (p + 40 > bytes.Length) break;
                    sections.Add(new SectionInfo
                    {
                        VirtualAddress = ReadUInt32(bytes, p + 12),
                        VirtualSize = ReadUInt32(bytes, p + 8),
                        RawPointer = ReadUInt32(bytes, p + 20),
                        RawSize = ReadUInt32(bytes, p + 16)
                    });
                }

                return sections;
            }

            private static string ReadImports(byte[] bytes, uint importRva, List<SectionInfo> sections)
            {
                if (importRva == 0) return string.Empty;
                int importOffset = RvaToOffset(importRva, sections);
                if (importOffset <= 0 || importOffset >= bytes.Length) return string.Empty;
                List<string> imports = new List<string>();
                for (int i = 0; i < 24 && importOffset + i * 20 + 20 <= bytes.Length; i++)
                {
                    int descriptor = importOffset + i * 20;
                    uint nameRva = ReadUInt32(bytes, descriptor + 12);
                    if (nameRva == 0) break;
                    int nameOffset = RvaToOffset(nameRva, sections);
                    string name = ReadAscii(bytes, nameOffset, 96);
                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        imports.Add(name);
                    }
                }

                return string.Join(";", imports.Take(24).ToArray());
            }

            private static int RvaToOffset(uint rva, IEnumerable<SectionInfo> sections)
            {
                foreach (SectionInfo section in sections)
                {
                    uint size = Math.Max(section.VirtualSize, section.RawSize);
                    if (rva >= section.VirtualAddress && rva < section.VirtualAddress + size)
                    {
                        return (int)(section.RawPointer + (rva - section.VirtualAddress));
                    }
                }

                return -1;
            }

            private static string ReadAscii(byte[] bytes, int offset, int max)
            {
                if (offset < 0 || offset >= bytes.Length) return string.Empty;
                int end = offset;
                while (end < bytes.Length && end - offset < max && bytes[end] != 0) end++;
                return Encoding.ASCII.GetString(bytes, offset, end - offset);
            }

            private static ushort ReadUInt16(byte[] bytes, int offset)
            {
                return offset + 2 <= bytes.Length ? BitConverter.ToUInt16(bytes, offset) : (ushort)0;
            }

            private static uint ReadUInt32(byte[] bytes, int offset)
            {
                return offset + 4 <= bytes.Length ? BitConverter.ToUInt32(bytes, offset) : 0;
            }

            private static int ReadInt32(byte[] bytes, int offset)
            {
                return offset + 4 <= bytes.Length ? BitConverter.ToInt32(bytes, offset) : 0;
            }
        }

        private sealed class SectionInfo
        {
            public uint VirtualAddress { get; set; }
            public uint VirtualSize { get; set; }
            public uint RawPointer { get; set; }
            public uint RawSize { get; set; }
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

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return string.Empty;
        }
    }
}
