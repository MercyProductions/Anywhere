using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal sealed class BaselineLearningMonitor : IDetectionMonitor
    {
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly ConcurrentDictionary<string, BaselineRecord> _records = new ConcurrentDictionary<string, BaselineRecord>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedDrift = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _writeLock = new object();
        private readonly string _baselineRoot;
        private readonly string _baselinePath;
        private bool _disposed;

        public BaselineLearningMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _baselineRoot = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Baseline Learning");
            _baselinePath = Path.Combine(_baselineRoot, "trusted-state-baseline.tsv");
        }

        public string Name
        {
            get { return "Baseline Learning"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_baselineRoot);
            LoadBaseline();
            _logger.EventLogged += OnEventLogged;

            _logger.Log(DetectionEvent.Create(
                "BaselineLearning",
                "Started",
                EventSeverity.Low,
                "Baseline learning monitor started.",
                _baselinePath,
                null,
                new Dictionary<string, string>
                {
                    { "baseline_path", _baselinePath },
                    { "record_count", _records.Count.ToString(CultureInfo.InvariantCulture) },
                    { "learning_policy", "Learns low-risk trusted signers, process behavior, and stable artifact context; high-risk drift is alerted, not auto-trusted." }
                }));
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed ||
                detectionEvent == null ||
                detectionEvent.Category.StartsWith("BaselineLearning", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            bool trusted = IsTrustedSignal(detectionEvent);
            bool highRisk = IsHighRiskSignal(detectionEvent);

            if (trusted && detectionEvent.Severity <= EventSeverity.Medium && !highRisk)
            {
                LearnTrustedSignal(detectionEvent);
                return;
            }

            if (highRisk)
            {
                DetectBaselineDrift(detectionEvent);
            }
        }

        private void LearnTrustedSignal(DetectionEvent detectionEvent)
        {
            List<BaselineObservation> observations = BuildObservations(detectionEvent);
            bool changed = false;
            foreach (BaselineObservation observation in observations)
            {
                BaselineRecord record = _records.AddOrUpdate(
                    observation.Key,
                    delegate
                    {
                        changed = true;
                        return new BaselineRecord
                        {
                            Key = observation.Key,
                            Type = observation.Type,
                            Value = observation.Value,
                            FirstSeenUtc = DateTime.UtcNow,
                            LastSeenUtc = DateTime.UtcNow,
                            SeenCount = 1,
                            Notes = observation.Notes
                        };
                    },
                    delegate(string key, BaselineRecord existing)
                    {
                        existing.LastSeenUtc = DateTime.UtcNow;
                        existing.SeenCount++;
                        return existing;
                    });

                if (record.SeenCount == 3)
                {
                    EmitCandidateLearned(record, detectionEvent);
                }
            }

            if (changed)
            {
                SaveBaseline();
            }
        }

        private void DetectBaselineDrift(DetectionEvent detectionEvent)
        {
            string processName = FirstNonEmpty(detectionEvent.ProcessName, Detail(detectionEvent, "source_process_name"), Detail(detectionEvent, "process_name"));
            string signer = FirstNonEmpty(Detail(detectionEvent, "source_signature_subject"), Detail(detectionEvent, "signature_subject"), Detail(detectionEvent, "file_signature_subject"));
            string processKey = BuildKey("process_behavior", processName);
            string signerKey = BuildKey("signer_subject", signer);

            bool knownProcess = !string.IsNullOrWhiteSpace(processName) && _records.ContainsKey(processKey);
            bool knownSigner = !string.IsNullOrWhiteSpace(signer) && _records.ContainsKey(signerKey);
            if (!knownProcess && !knownSigner)
            {
                return;
            }

            string driftClass = ClassifyDrift(detectionEvent);
            string reportKey = processKey + "|" + signerKey + "|" + driftClass + "|" + DateTime.UtcNow.ToString("yyyyMMddHH", CultureInfo.InvariantCulture);
            lock (_reportedDrift)
            {
                if (!_reportedDrift.Add(reportKey))
                {
                    return;
                }
            }

            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "process_name", processName ?? string.Empty },
                { "signer_subject", signer ?? string.Empty },
                { "known_process_baseline", knownProcess.ToString() },
                { "known_signer_baseline", knownSigner.ToString() },
                { "drift_class", driftClass },
                { "source_category", detectionEvent.Category ?? string.Empty },
                { "source_action", detectionEvent.Action ?? string.Empty },
                { "source_path", detectionEvent.Path ?? string.Empty },
                { "baseline_path", _baselinePath },
                { "confidence_score", (knownProcess && knownSigner ? 0.78 : 0.64).ToString("0.00", CultureInfo.InvariantCulture) }
            };

            _logger.Log(DetectionEvent.Create(
                "BaselineLearning",
                "BaselineDriftObserved",
                knownProcess && knownSigner ? EventSeverity.High : EventSeverity.Medium,
                "Known trusted baseline entity showed new high-risk behavior: " + driftClass,
                detectionEvent.Path,
                null,
                details));
        }

        private void EmitCandidateLearned(BaselineRecord record, DetectionEvent source)
        {
            _logger.Log(DetectionEvent.Create(
                "BaselineLearning",
                "BaselineCandidateLearned",
                EventSeverity.Low,
                "Trusted-state baseline candidate learned: " + record.Type,
                source.Path,
                null,
                new Dictionary<string, string>
                {
                    { "baseline_type", record.Type },
                    { "baseline_value", record.Value },
                    { "seen_count", record.SeenCount.ToString(CultureInfo.InvariantCulture) },
                    { "baseline_path", _baselinePath }
                }));
        }

        private List<BaselineObservation> BuildObservations(DetectionEvent detectionEvent)
        {
            List<BaselineObservation> observations = new List<BaselineObservation>();
            string processName = FirstNonEmpty(detectionEvent.ProcessName, Detail(detectionEvent, "source_process_name"), Detail(detectionEvent, "process_name"));
            string signer = FirstNonEmpty(Detail(detectionEvent, "source_signature_subject"), Detail(detectionEvent, "signature_subject"), Detail(detectionEvent, "file_signature_subject"));
            string path = FirstNonEmpty(detectionEvent.Path, Detail(detectionEvent, "source_path"), Detail(detectionEvent, "executable_path"));

            if (!string.IsNullOrWhiteSpace(processName))
            {
                observations.Add(new BaselineObservation("process_behavior", processName, "low-risk trusted process behavior"));
            }

            if (!string.IsNullOrWhiteSpace(signer))
            {
                observations.Add(new BaselineObservation("signer_subject", signer, "trusted signer baseline"));
            }

            if (!string.IsNullOrWhiteSpace(path) && !FileClassifier.IsLikelyDownloadLocation(path))
            {
                observations.Add(new BaselineObservation("trusted_path", path, "stable trusted path baseline"));
            }

            return observations;
        }

        private static bool IsTrustedSignal(DetectionEvent detectionEvent)
        {
            string text = (Detail(detectionEvent, "source_signature_status") + " " +
                           Detail(detectionEvent, "signature_status") + " " +
                           Detail(detectionEvent, "file_signature_status") + " " +
                           Detail(detectionEvent, "source_signature_subject") + " " +
                           Detail(detectionEvent, "signature_subject") + " " +
                           detectionEvent.Path).ToLowerInvariant();

            return text.IndexOf("trusted", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   text.IndexOf("microsoft corporation", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   text.IndexOf("\\windows\\system32", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsHighRiskSignal(DetectionEvent detectionEvent)
        {
            if (detectionEvent.Severity >= EventSeverity.High)
            {
                return true;
            }

            string text = (detectionEvent.Category + " " + detectionEvent.Action + " " + detectionEvent.Description + " " + detectionEvent.Path).ToLowerInvariant();
            return ContainsAny(text, "kernelcomm", "targetinteraction", "privateexecutable", "rwx", "driver", ".sys", "hwid", "spoof", "telemetry", "tamper", "cleanup");
        }

        private static string ClassifyDrift(DetectionEvent detectionEvent)
        {
            string text = (detectionEvent.Category + " " + detectionEvent.Action + " " + detectionEvent.Description + " " + detectionEvent.Path).ToLowerInvariant();
            if (ContainsAny(text, "targetinteraction", "process_vm_write", "protected target")) return "trusted_process_target_interaction";
            if (ContainsAny(text, "kernelcomm", "\\device\\", "section", "namedpipe")) return "trusted_process_communication_surface";
            if (ContainsAny(text, "privateexecutable", "rwx", "memory")) return "trusted_process_memory_anomaly";
            if (ContainsAny(text, "driver", ".sys", "hiddenkernel")) return "trusted_driver_or_kernel_context";
            if (ContainsAny(text, "hwid", "spoof", "serial", "mac")) return "trusted_identity_context_change";
            if (ContainsAny(text, "telemetry", "tamper", "auditlogcleared")) return "trusted_telemetry_tamper_context";
            return "trusted_high_risk_context";
        }

        private void LoadBaseline()
        {
            if (!File.Exists(_baselinePath))
            {
                return;
            }

            foreach (string line in File.ReadAllLines(_baselinePath, Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                string[] parts = line.Split('\t');
                if (parts.Length < 6)
                {
                    continue;
                }

                DateTime first;
                DateTime last;
                int count;
                DateTime.TryParse(parts[2], CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out first);
                DateTime.TryParse(parts[3], CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out last);
                int.TryParse(parts[4], NumberStyles.Integer, CultureInfo.InvariantCulture, out count);

                BaselineRecord record = new BaselineRecord
                {
                    Type = parts[0],
                    Value = FromBase64(parts[1]),
                    FirstSeenUtc = first == DateTime.MinValue ? DateTime.UtcNow : first,
                    LastSeenUtc = last == DateTime.MinValue ? DateTime.UtcNow : last,
                    SeenCount = Math.Max(1, count),
                    Notes = FromBase64(parts[5])
                };
                record.Key = BuildKey(record.Type, record.Value);
                _records[record.Key] = record;
            }
        }

        private void SaveBaseline()
        {
            try
            {
                lock (_writeLock)
                {
                    using (StreamWriter writer = new StreamWriter(new FileStream(_baselinePath, FileMode.Create, FileAccess.Write, FileShare.Read), Encoding.UTF8))
                    {
                        writer.WriteLine("# type\tvalue_b64\tfirst_seen_utc\tlast_seen_utc\tseen_count\tnotes_b64");
                        foreach (BaselineRecord record in _records.Values.OrderBy(r => r.Type).ThenBy(r => r.Value))
                        {
                            writer.Write(record.Type);
                            writer.Write('\t');
                            writer.Write(ToBase64(record.Value));
                            writer.Write('\t');
                            writer.Write(record.FirstSeenUtc.ToString("o", CultureInfo.InvariantCulture));
                            writer.Write('\t');
                            writer.Write(record.LastSeenUtc.ToString("o", CultureInfo.InvariantCulture));
                            writer.Write('\t');
                            writer.Write(record.SeenCount.ToString(CultureInfo.InvariantCulture));
                            writer.Write('\t');
                            writer.Write(ToBase64(record.Notes));
                            writer.WriteLine();
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private static string BuildKey(string type, string value)
        {
            return (type ?? string.Empty).Trim().ToLowerInvariant() + "|" + ReputationStore.NormalizeArtifactValue(type, value);
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

        private static string ToBase64(string value)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(value ?? string.Empty));
        }

        private static string FromBase64(string value)
        {
            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(value ?? string.Empty));
            }
            catch
            {
                return value ?? string.Empty;
            }
        }

        public void Dispose()
        {
            _disposed = true;
            _logger.EventLogged -= OnEventLogged;
            SaveBaseline();
        }

        private sealed class BaselineObservation
        {
            public BaselineObservation(string type, string value, string notes)
            {
                Type = type;
                Value = value;
                Notes = notes;
                Key = BuildKey(type, value);
            }

            public string Type;
            public string Value;
            public string Notes;
            public string Key;
        }

        private sealed class BaselineRecord
        {
            public string Key;
            public string Type;
            public string Value;
            public DateTime FirstSeenUtc;
            public DateTime LastSeenUtc;
            public int SeenCount;
            public string Notes;
        }
    }
}
