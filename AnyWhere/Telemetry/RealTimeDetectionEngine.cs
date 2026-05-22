using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal sealed class RealTimeDetectionEngine : IDetectionMonitor
    {
        private static readonly TimeSpan DetectionWindow = TimeSpan.FromMinutes(20);
        private static readonly TimeSpan BurstWindow = TimeSpan.FromMinutes(2);

        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly DetectionProfileSettings _profile;
        private readonly ConcurrentQueue<DetectionSignal> _recentSignals = new ConcurrentQueue<DetectionSignal>();
        private readonly ConcurrentDictionary<string, DetectionCase> _cases = new ConcurrentDictionary<string, DetectionCase>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _writeLock = new object();
        private readonly string _caseRoot;
        private bool _disposed;

        public RealTimeDetectionEngine(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _profile = DetectionProfileSettings.FromName(options.DetectionProfileName);
            _caseRoot = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Detection Engine Cases");
        }

        public string Name
        {
            get { return "Real-Time Detection Engine"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_caseRoot);
            _logger.EventLogged += OnEventLogged;

            _logger.Log(DetectionEvent.Create(
                "DetectionEngine",
                "Started",
                EventSeverity.Low,
                "Real-time detection engine started.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "profile", _profile.Name },
                    { "rule_match_threshold", _profile.RuleMatchThreshold.ToString("0.00", CultureInfo.InvariantCulture) },
                    { "high_confidence_threshold", _profile.HighConfidenceThreshold.ToString("0.00", CultureInfo.InvariantCulture) },
                    { "critical_confidence_threshold", _profile.CriticalConfidenceThreshold.ToString("0.00", CultureInfo.InvariantCulture) },
                    { "case_root", _caseRoot },
                    { "safety_rule", "Detection, scoring, suppression, and evidence correlation only." }
                }));
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed ||
                detectionEvent == null ||
                IsAnalysisFeedbackEvent(detectionEvent.Category))
            {
                return;
            }

            DetectionSignal signal = DetectionSignal.FromEvent(detectionEvent);
            signal.Tags = DeriveTags(signal);

            if (ShouldSuppress(signal))
            {
                return;
            }

            _recentSignals.Enqueue(signal);
            CleanupRecentSignals(signal.TimestampUtc);

            EvaluateBurstAnomaly(signal);
            EvaluateRules(signal);
        }

        private static bool IsAnalysisFeedbackEvent(string category)
        {
            if (string.IsNullOrWhiteSpace(category))
            {
                return false;
            }

            return category.StartsWith("DetectionEngine", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("Reputation", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("BehaviorProfile", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("BehavioralProfile", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("BaselineLearning", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("SessionReplay", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("ActiveCapture", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("EvidenceDatabase", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("Monitor", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("Replay", StringComparison.OrdinalIgnoreCase);
        }

        private bool ShouldSuppress(DetectionSignal signal)
        {
            if (!_profile.SuppressKnownGoodLowSignals || signal.Severity >= EventSeverity.Medium)
            {
                return false;
            }

            string text = signal.Text;
            if (ContainsAny(text, "started", "baseline", "scancomplete", "subscribed") ||
                ContainsAny(text, "microsoft corporation", "\\windows\\system32", "\\windows\\syswow64"))
            {
                return true;
            }

            return false;
        }

        private void EvaluateBurstAnomaly(DetectionSignal current)
        {
            DateTime cutoff = current.TimestampUtc.Subtract(BurstWindow);
            List<DetectionSignal> burst = _recentSignals
                .Where(s => s.TimestampUtc >= cutoff && s.Severity >= EventSeverity.High)
                .ToList();

            if (burst.Count < 18)
            {
                return;
            }

            string key = "burst|" + current.TimestampUtc.ToString("yyyyMMddHHmm", CultureInfo.InvariantCulture);
            if (!RememberReportedKey(key))
            {
                return;
            }

            string caseId = GetOrCreateCase("burst|" + current.CaseKey, "burst_anomaly");
            Dictionary<string, string> details = BuildCaseDetails(caseId, "burst_anomaly", 0.72, burst, "High-severity telemetry burst detected.");
            details["burst_window_seconds"] = BurstWindow.TotalSeconds.ToString("0", CultureInfo.InvariantCulture);
            details["burst_event_count"] = burst.Count.ToString(CultureInfo.InvariantCulture);

            DetectionEvent detectionEvent = DetectionEvent.Create(
                "DetectionEngine",
                "AnomalyDetected",
                EventSeverity.High,
                "High-severity telemetry burst detected across the investigation stream.",
                null,
                null,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
        }

        private void EvaluateRules(DetectionSignal current)
        {
            List<DetectionSignal> window = BuildWindow(current);
            List<RuleResult> results = new List<RuleResult>
            {
                EvaluateTransientDriverMapper(window),
                EvaluateHiddenDriverController(window),
                EvaluateManualMapTarget(window),
                EvaluateHwidSpoofingSession(window),
                EvaluateTrustedProcessAbuse(window),
                EvaluateLolbinNativeLoader(window),
                EvaluateTelemetryTamperDuringCase(window),
                EvaluateCleanupAfterGame(window)
            };

            foreach (RuleResult result in results.Where(r => r != null && r.Score >= _profile.RuleMatchThreshold))
            {
                EmitRuleResult(current, result);
            }
        }

        private List<DetectionSignal> BuildWindow(DetectionSignal current)
        {
            DateTime cutoff = current.TimestampUtc.Subtract(DetectionWindow);
            string caseId = current.CaseId;
            int processId = current.ProcessId;
            string target = current.TargetProcessName;
            string device = current.ObjectName;

            return _recentSignals
                .Where(s => s.TimestampUtc >= cutoff &&
                            (string.IsNullOrWhiteSpace(caseId) || string.Equals(s.CaseId, caseId, StringComparison.OrdinalIgnoreCase) ||
                             processId > 0 && s.ProcessId == processId ||
                             !string.IsNullOrWhiteSpace(target) && string.Equals(s.TargetProcessName, target, StringComparison.OrdinalIgnoreCase) ||
                             !string.IsNullOrWhiteSpace(device) && string.Equals(s.ObjectName, device, StringComparison.OrdinalIgnoreCase) ||
                             s.Severity >= EventSeverity.High))
                .OrderBy(s => s.TimestampUtc)
                .Take(250)
                .ToList();
        }

        private RuleResult EvaluateTransientDriverMapper(List<DetectionSignal> signals)
        {
            bool transientDriver = HasTag(signals, "transient_driver") || HasTag(signals, "driver_deleted");
            bool loader = HasTag(signals, "loader") || HasTag(signals, "lolbin");
            bool hidden = HasTag(signals, "hidden_kernel");
            bool hwid = HasTag(signals, "hardware_identity");
            bool game = HasTag(signals, "game_interaction");
            bool cleanup = HasTag(signals, "cleanup");

            double score = 0;
            if (transientDriver) score += 0.30 * _profile.DriverWeight;
            if (loader) score += 0.16;
            if (hidden) score += 0.18 * _profile.DriverWeight;
            if (hwid) score += 0.15 * _profile.SpooferWeight;
            if (game) score += 0.12;
            if (cleanup) score += 0.10;

            return BuildRule("transient_driver_mapper_chain", score, signals,
                "Transient driver staging correlated with loader, hidden-kernel, HWID, game, or cleanup evidence.");
        }

        private RuleResult EvaluateHiddenDriverController(List<DetectionSignal> signals)
        {
            bool hidden = HasTag(signals, "hidden_kernel");
            bool comm = HasTag(signals, "kernel_comm");
            bool target = HasTag(signals, "game_interaction");
            bool memory = HasTag(signals, "memory_anomaly");
            bool driver = HasTag(signals, "driver_activity");

            double score = 0;
            if (hidden) score += 0.28 * _profile.DriverWeight;
            if (driver) score += 0.12 * _profile.DriverWeight;
            if (comm) score += 0.22;
            if (target) score += 0.16;
            if (memory) score += 0.18 * _profile.MemoryWeight;

            return BuildRule("hidden_driver_controller_chain", score, signals,
                "Hidden-driver indicators correlated with communication surfaces and target or memory anomalies.");
        }

        private RuleResult EvaluateManualMapTarget(List<DetectionSignal> signals)
        {
            bool targetWrite = HasTag(signals, "target_write");
            bool memory = HasTag(signals, "memory_anomaly");
            bool unsignedDll = HasTag(signals, "unsigned_module");
            bool moduleMismatch = HasTag(signals, "module_mismatch");
            bool loader = HasTag(signals, "loader") || HasTag(signals, "lolbin");

            double score = 0;
            if (targetWrite) score += 0.24;
            if (memory) score += 0.26 * _profile.MemoryWeight;
            if (unsignedDll) score += 0.18;
            if (moduleMismatch) score += 0.16;
            if (loader) score += 0.10;

            return BuildRule("manual_map_target_chain", score, signals,
                "Target access and memory anomalies resemble manual-map or injected component behavior.");
        }

        private RuleResult EvaluateHwidSpoofingSession(List<DetectionSignal> signals)
        {
            bool hwid = HasTag(signals, "hardware_identity");
            bool spoofer = HasTag(signals, "spoofer_profile");
            bool driver = HasTag(signals, "driver_activity") || HasTag(signals, "hidden_kernel");
            bool game = HasTag(signals, "game_interaction");
            bool cleanup = HasTag(signals, "cleanup");

            double score = 0;
            if (hwid) score += 0.24 * _profile.SpooferWeight;
            if (spoofer) score += 0.22 * _profile.SpooferWeight;
            if (driver) score += 0.16 * _profile.DriverWeight;
            if (game) score += 0.14;
            if (cleanup) score += 0.16;

            return BuildRule("hwid_spoofer_session_chain", score, signals,
                "Hardware identity drift correlated with driver, protected-game, or cleanup behavior.");
        }

        private RuleResult EvaluateTrustedProcessAbuse(List<DetectionSignal> signals)
        {
            bool trusted = HasTag(signals, "trusted_process_abuse");
            bool memory = HasTag(signals, "memory_anomaly");
            bool comm = HasTag(signals, "kernel_comm");
            bool target = HasTag(signals, "game_interaction");
            bool unsigned = HasTag(signals, "unsigned_module");

            double score = 0;
            if (trusted) score += 0.30 * _profile.TrustedProcessWeight;
            if (memory) score += 0.18 * _profile.MemoryWeight;
            if (comm) score += 0.16;
            if (target) score += 0.18;
            if (unsigned) score += 0.12;

            return BuildRule("trusted_process_abuse_chain", score, signals,
                "Trusted application behavior correlated with memory, communication, or protected-game anomalies.");
        }

        private RuleResult EvaluateLolbinNativeLoader(List<DetectionSignal> signals)
        {
            bool lolbin = HasTag(signals, "lolbin");
            bool driver = HasTag(signals, "driver_activity") || HasTag(signals, "transient_driver");
            bool hwid = HasTag(signals, "hardware_identity");
            bool telemetry = HasTag(signals, "telemetry_tamper");
            bool cleanup = HasTag(signals, "cleanup");
            bool localController = HasTag(signals, "local_controller");

            double score = 0;
            if (lolbin) score += 0.26;
            if (driver) score += 0.20 * _profile.DriverWeight;
            if (hwid) score += 0.16 * _profile.SpooferWeight;
            if (telemetry) score += 0.14;
            if (cleanup) score += 0.10;
            if (localController) score += 0.10;

            return BuildRule("lolbin_native_abuse_chain", score, signals,
                "Native Windows tooling correlated with driver, HWID, telemetry, cleanup, or controller activity.");
        }

        private RuleResult EvaluateTelemetryTamperDuringCase(List<DetectionSignal> signals)
        {
            bool telemetry = HasTag(signals, "telemetry_tamper");
            bool driver = HasTag(signals, "driver_activity") || HasTag(signals, "hidden_kernel");
            bool target = HasTag(signals, "game_interaction");
            bool hwid = HasTag(signals, "hardware_identity");

            double score = 0;
            if (telemetry) score += 0.32;
            if (driver) score += 0.18 * _profile.DriverWeight;
            if (target) score += 0.14;
            if (hwid) score += 0.14 * _profile.SpooferWeight;

            return BuildRule("telemetry_tamper_during_suspicious_case", score, signals,
                "Telemetry tamper behavior occurred near driver, target, or HWID evidence.");
        }

        private RuleResult EvaluateCleanupAfterGame(List<DetectionSignal> signals)
        {
            bool game = HasTag(signals, "game_interaction");
            bool cleanup = HasTag(signals, "cleanup");
            bool transient = HasTag(signals, "transient_driver") || HasTag(signals, "loader");
            bool hwid = HasTag(signals, "hardware_identity");

            double score = 0;
            if (game) score += 0.18;
            if (cleanup) score += 0.28;
            if (transient) score += 0.18;
            if (hwid) score += 0.14 * _profile.SpooferWeight;

            return BuildRule("post_game_cleanup_chain", score, signals,
                "Cleanup or revert behavior correlated with protected game activity and transient artifacts.");
        }

        private RuleResult BuildRule(string ruleId, double score, List<DetectionSignal> signals, string summary)
        {
            if (signals.Any(s => s.Severity >= EventSeverity.Critical)) score += 0.06;
            if (signals.SelectMany(s => s.Tags).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 5) score += 0.05;
            score = Math.Min(0.99, score);

            return new RuleResult
            {
                RuleId = ruleId,
                Score = score,
                Summary = summary,
                Signals = signals
            };
        }

        private void EmitRuleResult(DetectionSignal current, RuleResult result)
        {
            string caseKey = result.RuleId + "|" + FirstNonEmpty(current.CaseId, current.CaseKey, current.ProcessId.ToString(CultureInfo.InvariantCulture));
            string caseId = GetOrCreateCase(caseKey, result.RuleId);
            DetectionCase detectionCase = _cases[caseKey];

            bool escalated = result.Score > detectionCase.ConfidenceScore + 0.08 ||
                             result.Score >= _profile.HighConfidenceThreshold && detectionCase.LastEmittedScore < _profile.HighConfidenceThreshold ||
                             result.Score >= _profile.CriticalConfidenceThreshold && detectionCase.LastEmittedScore < _profile.CriticalConfidenceThreshold;

            if (!escalated && !_profile.EmitMediumRuleMatches)
            {
                return;
            }

            string key = result.RuleId + "|" + caseId + "|" + Math.Floor(result.Score * 20).ToString(CultureInfo.InvariantCulture);
            if (!RememberReportedKey(key))
            {
                return;
            }

            detectionCase.ConfidenceScore = Math.Max(detectionCase.ConfidenceScore, result.Score);
            detectionCase.LastEmittedScore = result.Score;
            detectionCase.LastUpdatedUtc = DateTime.UtcNow;
            detectionCase.Summary = result.Summary;

            Dictionary<string, string> details = BuildCaseDetails(caseId, result.RuleId, result.Score, result.Signals, result.Summary);
            details["profile"] = _profile.Name;
            details["confidence_escalated"] = escalated.ToString();
            details["case_summary"] = BuildNarrative(result);

            EventSeverity severity = result.Score >= _profile.CriticalConfidenceThreshold ? EventSeverity.Critical :
                result.Score >= _profile.HighConfidenceThreshold ? EventSeverity.High : EventSeverity.Medium;

            DetectionEvent detectionEvent = DetectionEvent.Create(
                "DetectionEngine",
                escalated ? "ConfidenceEscalated" : "RuleMatched",
                severity,
                result.Summary,
                current.Path,
                null,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
        }

        private Dictionary<string, string> BuildCaseDetails(string caseId, string ruleId, double score, List<DetectionSignal> signals, string summary)
        {
            List<DetectionSignal> selected = signals.OrderBy(s => s.TimestampUtc).Take(30).ToList();
            HashSet<string> tags = new HashSet<string>(selected.SelectMany(s => s.Tags), StringComparer.OrdinalIgnoreCase);

            return new Dictionary<string, string>
            {
                { "case_id", caseId },
                { "rule_id", ruleId },
                { "confidence_score", score.ToString("0.00", CultureInfo.InvariantCulture) },
                { "case_summary", summary ?? string.Empty },
                { "matched_tags", string.Join(";", tags.OrderBy(t => t).ToArray()) },
                { "matched_event_count", selected.Count.ToString(CultureInfo.InvariantCulture) },
                { "timeline_summary", string.Join(" || ", selected.Select(s => s.Summary).ToArray()) },
                { "involved_processes", string.Join(";", selected.Select(s => s.ProcessName).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).Take(25).ToArray()) },
                { "involved_files", string.Join(";", selected.Select(s => s.Path).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).Take(25).ToArray()) },
                { "involved_devices", string.Join(";", selected.Select(s => s.ObjectName).Where(v => !string.IsNullOrWhiteSpace(v)).Distinct(StringComparer.OrdinalIgnoreCase).Take(25).ToArray()) },
                { "evidence_folder_path", GetCaseFolder(caseId) },
                { "detection_profile", _profile.Name },
                { "safety_rule", "Rule matched using defensive telemetry correlation only." }
            };
        }

        private static string BuildNarrative(RuleResult result)
        {
            List<string> parts = new List<string>();
            HashSet<string> tags = new HashSet<string>(result.Signals.SelectMany(s => s.Tags), StringComparer.OrdinalIgnoreCase);

            if (tags.Contains("loader") || tags.Contains("lolbin")) parts.Add("a loader or native Windows tool appeared");
            if (tags.Contains("transient_driver") || tags.Contains("driver_activity")) parts.Add("driver or transient SYS activity followed");
            if (tags.Contains("hidden_kernel")) parts.Add("hidden-kernel indicators appeared");
            if (tags.Contains("kernel_comm") || tags.Contains("local_controller")) parts.Add("communication surfaces were used");
            if (tags.Contains("hardware_identity") || tags.Contains("spoofer_profile")) parts.Add("hardware identity drift or spoofing profile evidence appeared");
            if (tags.Contains("game_interaction") || tags.Contains("target_write")) parts.Add("a protected game process was accessed");
            if (tags.Contains("memory_anomaly")) parts.Add("memory anomalies were observed");
            if (tags.Contains("cleanup")) parts.Add("cleanup or revert behavior followed");

            return parts.Count == 0 ? result.Summary : string.Join(", then ", parts.ToArray()) + ".";
        }

        private string GetOrCreateCase(string caseKey, string ruleId)
        {
            DetectionCase existing;
            if (_cases.TryGetValue(caseKey, out existing) && DateTime.UtcNow.Subtract(existing.LastUpdatedUtc) <= DetectionWindow)
            {
                existing.LastUpdatedUtc = DateTime.UtcNow;
                return existing.CaseId;
            }

            string caseId = "DCASE-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            DetectionCase created = new DetectionCase
            {
                CaseId = caseId,
                CaseKey = caseKey,
                RuleId = ruleId,
                CreatedUtc = DateTime.UtcNow,
                LastUpdatedUtc = DateTime.UtcNow
            };
            Directory.CreateDirectory(GetCaseFolder(caseId));
            _cases[caseKey] = created;
            return caseId;
        }

        private string GetCaseFolder(string caseId)
        {
            return Path.Combine(_caseRoot, caseId);
        }

        private void AppendCaseEvent(string caseId, DetectionEvent detectionEvent)
        {
            try
            {
                string folder = GetCaseFolder(caseId);
                Directory.CreateDirectory(folder);
                string path = Path.Combine(folder, "detection-engine-case.jsonl");
                lock (_writeLock)
                {
                    File.AppendAllText(path, CaseEventToJson(detectionEvent) + Environment.NewLine, Encoding.UTF8);
                    CaseIntegrityManifestWriter.WriteManifest(folder);
                }
            }
            catch
            {
            }
        }

        private static string CaseEventToJson(DetectionEvent detectionEvent)
        {
            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "timestamp_utc", detectionEvent.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "category", detectionEvent.Category, ref first);
            JsonUtilities.AppendStringProperty(builder, "action", detectionEvent.Action, ref first);
            JsonUtilities.AppendStringProperty(builder, "severity", detectionEvent.Severity.ToString(), ref first);
            JsonUtilities.AppendStringProperty(builder, "description", detectionEvent.Description, ref first);
            JsonUtilities.AppendStringProperty(builder, "path", detectionEvent.Path, ref first);
            builder.Append(",\"details\":{");
            bool firstDetail = true;
            foreach (KeyValuePair<string, string> pair in detectionEvent.Details)
            {
                JsonUtilities.AppendStringProperty(builder, pair.Key, pair.Value, ref firstDetail);
            }
            builder.Append("}}");
            return builder.ToString();
        }

        private static HashSet<string> DeriveTags(DetectionSignal signal)
        {
            HashSet<string> tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string text = signal.Text;

            if (ContainsAny(text, "transientdrivermapping", "transient driver", "short-lived .sys", "shortliveddriver", "driverfileappeared")) tags.Add("transient_driver");
            if (ContainsAny(text, "driverloaded", "serviceinstalled", ".sys", "kernel driver", "vulnerable")) tags.Add("driver_activity");
            if (ContainsAny(text, "hiddenkernel", "hidden kernel", "unlinked", "kernelassist", "loadedmodulenoservice")) tags.Add("hidden_kernel");
            if (ContainsAny(text, "loader", "mapper", "kdmapper", "inject", "nativeabuse", "suspiciouslolbin")) tags.Add("loader");
            if (ContainsAny(text, "lolbin", "powershell", "rundll32", "regsvr32", "mshta", "schtasks", "sc.exe", "wevtutil")) tags.Add("lolbin");
            if (ContainsAny(text, "targetinteraction", "protected target", "processopenedprotectedtarget", "game.exe", "shipping.exe")) tags.Add("game_interaction");
            if (ContainsAny(text, "process_vm_write", "process_vm_operation", "process_create_thread", "suspicioustargethandle")) tags.Add("target_write");
            if (ContainsAny(text, "privateexecutable", "rwx", "privatepeheader", "threadstartoutside", "memory anomaly")) tags.Add("memory_anomaly");
            if (ContainsAny(text, "unsignedmapped", "unsigned mapped", "untrustedorinvalid", "unsignedorcatalogonlyuntrusted")) tags.Add("unsigned_module");
            if (ContainsAny(text, "mappedimagenotinmodulelist", "module list mismatch")) tags.Add("module_mismatch");
            if (ContainsAny(text, "kernelcomm", "\\device\\", "namedpipe", "section", "alpc", "communicationchain")) tags.Add("kernel_comm");
            if (ContainsAny(text, "localhost", "127.0.0.1", "::1", "websocket", "localcontroller")) tags.Add("local_controller");
            if (ContainsAny(text, "hardwareidentity", "hwid", "smbios", "mac", "disk serial", "uuid", "spoofer")) tags.Add("hardware_identity");
            if (ContainsAny(text, "hwidspooferprofilematched", "temporary_session_spoofer", "driver_backed_spoofer")) tags.Add("spoofer_profile");
            if (ContainsAny(text, "cleanup", "revert", "deleted", "auditlogcleared", "trace", "self-delete", "event log cleared")) tags.Add("cleanup");
            if (ContainsAny(text, "telemetry", "auditlogcleared", "auditpolicy", "sysmon", "defender exclusion", "powershelllogging")) tags.Add("telemetry_tamper");
            if (ContainsAny(text, "trustedprocessabuse", "trusted application")) tags.Add("trusted_process_abuse");

            return tags;
        }

        private static bool HasTag(IEnumerable<DetectionSignal> signals, string tag)
        {
            return signals.Any(s => s.Tags.Contains(tag));
        }

        private bool RememberReportedKey(string key)
        {
            lock (_reportedKeys)
            {
                return _reportedKeys.Add(key);
            }
        }

        private void CleanupRecentSignals(DateTime currentTimestampUtc)
        {
            DateTime cutoff = currentTimestampUtc.Subtract(DetectionWindow);
            while (_recentSignals.TryPeek(out DetectionSignal signal) && signal.TimestampUtc < cutoff)
            {
                DetectionSignal ignored;
                _recentSignals.TryDequeue(out ignored);
            }
        }

        private static bool ContainsAny(string text, params string[] terms)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            foreach (string term in terms)
            {
                if (text.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
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

        public void Dispose()
        {
            _disposed = true;
            _logger.EventLogged -= OnEventLogged;
        }

        private sealed class DetectionCase
        {
            public string CaseId;
            public string CaseKey;
            public string RuleId;
            public DateTime CreatedUtc;
            public DateTime LastUpdatedUtc;
            public double ConfidenceScore;
            public double LastEmittedScore;
            public string Summary;
        }

        private sealed class RuleResult
        {
            public string RuleId;
            public double Score;
            public string Summary;
            public List<DetectionSignal> Signals;
        }

        private sealed class DetectionSignal
        {
            public DateTime TimestampUtc;
            public string Category;
            public string Action;
            public EventSeverity Severity;
            public string Description;
            public string Path;
            public int ProcessId;
            public string ProcessName;
            public string TargetProcessName;
            public string ObjectName;
            public string CaseId;
            public string CaseKey;
            public string Summary;
            public string Text;
            public HashSet<string> Tags;

            public static DetectionSignal FromEvent(DetectionEvent detectionEvent)
            {
                string caseId = Detail(detectionEvent, "case_id");
                if (string.IsNullOrWhiteSpace(caseId)) caseId = Detail(detectionEvent, "behavior_case_id");
                if (string.IsNullOrWhiteSpace(caseId)) caseId = Detail(detectionEvent, "session_id");

                string target = FirstNonEmpty(Detail(detectionEvent, "target_process_name"), Detail(detectionEvent, "TargetImage"));
                string objectName = FirstNonEmpty(Detail(detectionEvent, "object_name"), Detail(detectionEvent, "device_name"), Detail(detectionEvent, "section_name"));
                string text = detectionEvent.Category + " " + detectionEvent.Action + " " + detectionEvent.Description + " " +
                              detectionEvent.Path + " " + detectionEvent.ProcessName + " " +
                              string.Join(" ", detectionEvent.Details.Select(p => p.Key + "=" + p.Value).ToArray());

                return new DetectionSignal
                {
                    TimestampUtc = detectionEvent.TimestampUtc.UtcDateTime,
                    Category = detectionEvent.Category ?? string.Empty,
                    Action = detectionEvent.Action ?? string.Empty,
                    Severity = detectionEvent.Severity,
                    Description = detectionEvent.Description ?? string.Empty,
                    Path = detectionEvent.Path ?? string.Empty,
                    ProcessId = detectionEvent.ProcessId.GetValueOrDefault(0),
                    ProcessName = detectionEvent.ProcessName ?? FirstNonEmpty(Detail(detectionEvent, "source_process_name"), Detail(detectionEvent, "process_name")),
                    TargetProcessName = target,
                    ObjectName = objectName,
                    CaseId = caseId,
                    CaseKey = FirstNonEmpty(caseId, target, objectName, detectionEvent.ProcessName, detectionEvent.Path, detectionEvent.Category),
                    Summary = detectionEvent.Category + "/" + detectionEvent.Action + " " + detectionEvent.Description,
                    Text = text.ToLowerInvariant()
                };
            }

            private static string Detail(DetectionEvent detectionEvent, string key)
            {
                if (detectionEvent == null || detectionEvent.Details == null)
                {
                    return string.Empty;
                }

                string value;
                return detectionEvent.Details.TryGetValue(key, out value) ? value : string.Empty;
            }
        }
    }
}
