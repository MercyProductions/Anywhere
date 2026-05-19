using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal sealed class BehavioralProfileMonitor : IDetectionMonitor
    {
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly ConcurrentDictionary<string, BehavioralCase> _cases = new ConcurrentDictionary<string, BehavioralCase>(StringComparer.OrdinalIgnoreCase);
        private readonly List<PersistedFingerprint> _previousFingerprints = new List<PersistedFingerprint>();
        private readonly HashSet<string> _reportedSimilarityKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _writeLock = new object();
        private readonly object _previousLock = new object();
        private readonly string _profileRoot;
        private readonly string _caseRoot;
        private readonly string _fingerprintPath;
        private bool _disposed;

        public BehavioralProfileMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _profileRoot = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Behavioral Profiles");
            _caseRoot = Path.Combine(_profileRoot, "Cases");
            _fingerprintPath = Path.Combine(_profileRoot, "behavior-fingerprints.jsonl");
        }

        public string Name
        {
            get { return "Behavioral Profiling"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_profileRoot);
            Directory.CreateDirectory(_caseRoot);
            LoadPreviousFingerprints();
            _logger.EventLogged += OnEventLogged;

            _logger.Log(DetectionEvent.Create(
                "BehaviorProfile",
                _options.BehavioralProfilingEnabled ? "Started" : "Disabled",
                EventSeverity.Low,
                _options.BehavioralProfilingEnabled
                    ? "Behavioral profiling and fingerprinting monitor started."
                    : "Behavioral profiling is disabled by configuration.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "profile_root", _profileRoot },
                    { "previous_fingerprint_count", _previousFingerprints.Count.ToString(CultureInfo.InvariantCulture) },
                    { "correlation_window_minutes", _options.BehavioralProfileWindow.TotalMinutes.ToString("0", CultureInfo.InvariantCulture) },
                    { "similarity_threshold", _options.BehavioralSimilarityThreshold.ToString("0.00", CultureInfo.InvariantCulture) },
                    { "safety_rule", "Defensive behavioral recognition only; no bypass, evasion, injection, or interference logic." }
                }));
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed ||
                detectionEvent == null ||
                detectionEvent.Category.StartsWith("BehaviorProfile", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (!_options.BehavioralProfilingEnabled)
            {
                return;
            }

            BehavioralSignal signal = BehavioralSignal.FromEvent(detectionEvent);
            List<string> tags = DeriveTags(signal);
            if (tags.Count == 0 && signal.Severity < EventSeverity.High && !IsCaseBearing(signal))
            {
                return;
            }

            string caseKey = BuildCaseKey(signal);
            BehavioralCase behaviorCase = _cases.GetOrAdd(caseKey, delegate
            {
                return new BehavioralCase
                {
                    CaseKey = caseKey,
                    CaseId = BuildBehaviorCaseId(signal),
                    FirstSeenUtc = signal.TimestampUtc,
                    LastSeenUtc = signal.TimestampUtc
                };
            });

            lock (behaviorCase.SyncRoot)
            {
                UpdateCase(behaviorCase, signal, tags);
                RecalculateCase(behaviorCase);
                if (ShouldEmitProfile(behaviorCase))
                {
                    EmitProfile(behaviorCase);
                }
            }

            CleanupExpiredCases();
        }

        private void UpdateCase(BehavioralCase behaviorCase, BehavioralSignal signal, IEnumerable<string> tags)
        {
            behaviorCase.LastSeenUtc = signal.TimestampUtc;
            behaviorCase.Signals.Add(signal);
            if (behaviorCase.Signals.Count > 250)
            {
                behaviorCase.Signals.RemoveAt(0);
            }

            if (signal.Severity > behaviorCase.MaxSeverity)
            {
                behaviorCase.MaxSeverity = signal.Severity;
            }

            foreach (string tag in tags)
            {
                behaviorCase.Tags.Add(tag);
            }

            AddFeatures(behaviorCase, signal);
            AddArtifacts(behaviorCase, signal);
        }

        private void RecalculateCase(BehavioralCase behaviorCase)
        {
            behaviorCase.Profiles.Clear();
            AddProfileScore(behaviorCase, "suspicious_kernel_mapper", ScoreKernelMapper(behaviorCase));
            AddProfileScore(behaviorCase, "hidden_driver_controller", ScoreHiddenDriverController(behaviorCase));
            AddProfileScore(behaviorCase, "manual_map_injector", ScoreManualMapInjector(behaviorCase));
            AddProfileScore(behaviorCase, "transient_bootstrap_loader", ScoreTransientBootstrap(behaviorCase));
            AddProfileScore(behaviorCase, "unsigned_target_manipulator", ScoreUnsignedTargetManipulator(behaviorCase));
            AddProfileScore(behaviorCase, "telemetry_tamper_utility", ScoreTelemetryTamperUtility(behaviorCase));
            AddProfileScore(behaviorCase, "trusted_process_abuse", ScoreTrustedProcessAbuse(behaviorCase));
            AddProfileScore(behaviorCase, "lolbin_native_loader", ScoreLolbinNativeLoader(behaviorCase));
            AddProfileScore(behaviorCase, "local_controller_workflow", ScoreLocalControllerWorkflow(behaviorCase));

            behaviorCase.FingerprintFeatures.Clear();
            foreach (string feature in behaviorCase.Features)
            {
                behaviorCase.FingerprintFeatures.Add(feature);
            }

            foreach (string tag in behaviorCase.Tags)
            {
                behaviorCase.FingerprintFeatures.Add("tag:" + tag);
            }

            foreach (KeyValuePair<string, double> profile in behaviorCase.Profiles)
            {
                if (profile.Value >= 0.55)
                {
                    behaviorCase.FingerprintFeatures.Add("profile:" + profile.Key);
                }
            }

            behaviorCase.FingerprintSha256 = HashFeatureSet(behaviorCase.FingerprintFeatures);
            behaviorCase.ConfidenceScore = CalculateConfidence(behaviorCase);
            behaviorCase.SimilarCases = FindSimilarCases(behaviorCase);
            behaviorCase.Narrative = BuildNarrative(behaviorCase);
        }

        private bool ShouldEmitProfile(BehavioralCase behaviorCase)
        {
            int tagCount = behaviorCase.Tags.Count;
            int featureCount = behaviorCase.FingerprintFeatures.Count;
            bool strongProfile = behaviorCase.Profiles.Any(p => p.Value >= 0.70);
            bool similarPrior = behaviorCase.SimilarCases.Any(s => s.Score >= _options.BehavioralSimilarityThreshold);
            int version = tagCount + featureCount + behaviorCase.Profiles.Count(p => p.Value >= 0.55) + behaviorCase.Signals.Count / 4;

            if (behaviorCase.ConfidenceScore < 0.55 && !strongProfile && !similarPrior)
            {
                return false;
            }

            if (version <= behaviorCase.LastEmittedVersion && DateTime.UtcNow.Subtract(behaviorCase.LastEmittedUtc) < TimeSpan.FromMinutes(5))
            {
                return false;
            }

            behaviorCase.LastEmittedVersion = version;
            behaviorCase.LastEmittedUtc = DateTime.UtcNow;
            return true;
        }

        private void EmitProfile(BehavioralCase behaviorCase)
        {
            string folder = Path.Combine(_caseRoot, SanitizeFileName(behaviorCase.CaseId));
            Directory.CreateDirectory(folder);

            string profilePath = Path.Combine(folder, "behavior-profile.json");
            string narrativePath = Path.Combine(folder, "behavior-narrative.txt");
            WriteCaseProfile(profilePath, behaviorCase);
            File.WriteAllText(narrativePath, behaviorCase.Narrative ?? string.Empty, Encoding.UTF8);
            string manifestPath = CaseIntegrityManifestWriter.WriteManifest(folder);
            AppendFingerprint(behaviorCase);

            EventSeverity severity = behaviorCase.ConfidenceScore >= 0.85 ? EventSeverity.Critical :
                behaviorCase.ConfidenceScore >= 0.68 ? EventSeverity.High : EventSeverity.Medium;

            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "behavior_case_id", behaviorCase.CaseId },
                { "case_key", behaviorCase.CaseKey },
                { "behavior_tags", string.Join(";", behaviorCase.Tags.OrderBy(t => t).ToArray()) },
                { "behavior_profiles", FormatProfiles(behaviorCase.Profiles) },
                { "fingerprint_sha256", behaviorCase.FingerprintSha256 ?? string.Empty },
                { "fingerprint_features", string.Join(";", behaviorCase.FingerprintFeatures.OrderBy(f => f).Take(80).ToArray()) },
                { "confidence_score", behaviorCase.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) },
                { "similar_cases", FormatSimilarCases(behaviorCase.SimilarCases) },
                { "profile_path", profilePath },
                { "narrative_path", narrativePath },
                { "integrity_manifest_path", manifestPath ?? string.Empty },
                { "narrative", behaviorCase.Narrative ?? string.Empty },
                { "cluster_hashes", string.Join(";", behaviorCase.Hashes.Take(25).ToArray()) },
                { "cluster_paths", string.Join(";", behaviorCase.Paths.Take(25).ToArray()) },
                { "cluster_signers", string.Join(";", behaviorCase.Signers.Take(25).ToArray()) },
                { "cluster_process_names", string.Join(";", behaviorCase.ProcessNames.Take(25).ToArray()) },
                { "cluster_devices", string.Join(";", behaviorCase.DeviceNames.Take(25).ToArray()) },
                { "cluster_sections", string.Join(";", behaviorCase.SectionNames.Take(25).ToArray()) },
                { "safe_mode", "Defensive recognition only; no bypass logic or offensive action generated." }
            };

            DetectionEvent profileEvent = DetectionEvent.Create(
                "BehaviorProfile",
                "BehavioralCaseProfiled",
                severity,
                "Behavioral profile generated: " + TopProfileName(behaviorCase),
                profilePath,
                null,
                details);

            _logger.Log(profileEvent);
            EmitSimilarityEventIfNeeded(behaviorCase);
        }

        private void EmitSimilarityEventIfNeeded(BehavioralCase behaviorCase)
        {
            SimilarCase match = behaviorCase.SimilarCases.FirstOrDefault(s => s.Score >= _options.BehavioralSimilarityThreshold);
            if (match == null)
            {
                return;
            }

            string key = behaviorCase.CaseId + "|" + match.FingerprintSha256 + "|" + match.Score.ToString("0.00", CultureInfo.InvariantCulture);
            lock (_reportedSimilarityKeys)
            {
                if (!_reportedSimilarityKeys.Add(key))
                {
                    return;
                }
            }

            _logger.Log(DetectionEvent.Create(
                "BehaviorProfile",
                "SimilarBehaviorObserved",
                match.Score >= 0.80 ? EventSeverity.High : EventSeverity.Medium,
                "Current behavior resembles a previous case fingerprint.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "behavior_case_id", behaviorCase.CaseId },
                    { "current_fingerprint_sha256", behaviorCase.FingerprintSha256 ?? string.Empty },
                    { "matched_case_id", match.CaseId ?? string.Empty },
                    { "matched_fingerprint_sha256", match.FingerprintSha256 ?? string.Empty },
                    { "similarity_score", match.Score.ToString("0.00", CultureInfo.InvariantCulture) },
                    { "matched_tags", string.Join(";", match.SharedTags.ToArray()) },
                    { "matched_features", string.Join(";", match.SharedFeatures.Take(40).ToArray()) }
                }));
        }

        private List<string> DeriveTags(BehavioralSignal signal)
        {
            HashSet<string> tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string text = signal.Text;

            if (ContainsAny(text, "manualmap", "manual map", "mappedimagenotinmodulelist", "privatepeheader", "unsignedmappeddllintarget"))
            {
                tags.Add("manual_map_behavior");
            }

            if (ContainsAny(text, "hiddenkernel", "servicerunningmodulemissing", "loadedmodulenoservice", "hidden kernel", "kernelassist"))
            {
                tags.Add("hidden_driver_pattern");
            }

            if (ContainsAny(text, "kdmapper", "iqvw", "vulnerable", "capcom", "dbutil", "gdrv", "rtcore", "winio", "mhyprot", "suspiciousdriverloaderprocess"))
            {
                tags.Add("vulnerable_driver_loader");
            }

            if ((ContainsAny(text, "vm_write", "vm_operation", "create_thread", "suspicioustargethandle", "processopenedprotectedtarget") &&
                 ContainsAny(text, "unsigned", "untrusted", "missing")) ||
                signal.Detail("source_signature_status").IndexOf("Trusted", StringComparison.OrdinalIgnoreCase) < 0 &&
                !string.IsNullOrWhiteSpace(signal.Detail("target_process_id")))
            {
                tags.Add("unsigned_game_access");
            }

            if (ContainsAny(text, "device", "\\device\\", "namedpipe", "alpc", "suspiciousdevice", "communicationchain", "sharedsection"))
            {
                tags.Add("suspicious_device_channel");
            }

            if (ContainsAny(text, "privateexecutablememory", "rwxprivatememory", "privatepeheader", "threadstartoutside", "memory_patch_or_injection", "process_create_thread"))
            {
                tags.Add("memory_injection_pattern");
            }

            if (ContainsAny(text, "shortlived", "transient", "deleted", "renamed", "driverfiledeleted", "shortlivedsuspiciousprocess"))
            {
                tags.Add("transient_loader_behavior");
            }

            if (ContainsAny(text, "debug", "anti_debug", "process tampering", "suspend", "terminate", "handle to anywhere"))
            {
                tags.Add("anti_debug_behavior");
            }

            if (signal.Category.StartsWith("DefensiveIntegrity", StringComparison.OrdinalIgnoreCase) ||
                ContainsAny(text, "telemetry", "tamper", "auditlogcleared", "auditpolicy", "defender exclusion", "powershelllogging", "sysmon", "codeintegritypolicychanged"))
            {
                tags.Add("telemetry_tamper_behavior");
            }

            if (signal.Category.StartsWith("TrustedProcessAbuse", StringComparison.OrdinalIgnoreCase) ||
                ContainsAny(text, "trustedprocessabuse", "trustedprocesskernelchannel", "trustedprocesstargetinteraction", "trustedprocessunsigned", "trustedprocessprivate", "trusted application"))
            {
                tags.Add("trusted_process_abuse");
            }

            if (signal.Category.StartsWith("NativeAbuse", StringComparison.OrdinalIgnoreCase) ||
                ContainsAny(text, "suspiciouslolbinexecution", "suspiciouspowershellactivity", "nativeabusechain", "rundll32", "regsvr32", "mshta", "wscript", "cscript", "installutil", "schtasks", "sc.exe", "wevtutil"))
            {
                tags.Add("lolbin_native_abuse");
            }

            if (ContainsAny(text, "localcontrollerchannel", "localhost", "127.0.0.1", "::1", "websocket", "ws://", "wss://"))
            {
                tags.Add("local_controller_channel");
            }

            return tags.OrderBy(t => t).ToList();
        }

        private void AddFeatures(BehavioralCase behaviorCase, BehavioralSignal signal)
        {
            string text = signal.Text;
            behaviorCase.Features.Add("event:" + signal.Category + "/" + signal.Action);

            if (signal.Severity >= EventSeverity.High)
            {
                behaviorCase.Features.Add("severity:high_or_above");
            }

            string path = FirstNonEmpty(signal.Path, signal.Detail("source_path"), signal.Detail("mapped_path"), signal.Detail("driver_path"), signal.Detail("target_path"));
            if (!string.IsNullOrWhiteSpace(path))
            {
                string extension = Path.GetExtension(path).ToLowerInvariant();
                if (!string.IsNullOrWhiteSpace(extension))
                {
                    behaviorCase.Features.Add("file_ext:" + extension);
                }

                behaviorCase.Features.Add("stage:" + ClassifyPathLocation(path));
            }

            string parentChain = signal.Detail("parent_process_chain");
            if (!string.IsNullOrWhiteSpace(parentChain))
            {
                behaviorCase.Features.Add("process_tree:" + NormalizePattern(parentChain));
            }

            string parent = signal.Detail("parent_process_name");
            if (!string.IsNullOrWhiteSpace(parent))
            {
                behaviorCase.Features.Add("parent:" + NormalizeName(parent));
            }

            string processName = FirstNonEmpty(signal.Detail("source_process_name"), signal.ProcessName, signal.Detail("process_name"));
            if (!string.IsNullOrWhiteSpace(processName))
            {
                behaviorCase.Features.Add("process:" + NormalizeName(processName));
            }

            string targetName = signal.Detail("target_process_name");
            if (!string.IsNullOrWhiteSpace(targetName))
            {
                behaviorCase.Features.Add("target:" + NormalizeName(targetName));
            }

            string access = signal.Detail("decoded_access") + " " + signal.Detail("granted_access") + " " + signal.Detail("access_rights");
            if (ContainsAny(access, "PROCESS_VM_WRITE", "PROCESS_VM_OPERATION", "PROCESS_CREATE_THREAD"))
            {
                behaviorCase.Features.Add("target_access:write_or_thread");
            }
            else if (ContainsAny(access, "PROCESS_VM_READ", "PROCESS_QUERY_INFORMATION"))
            {
                behaviorCase.Features.Add("target_access:read_or_query");
            }

            string objectName = signal.Detail("object_name");
            if (!string.IsNullOrWhiteSpace(objectName))
            {
                if (objectName.IndexOf("\\Device\\", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    behaviorCase.Features.Add("device_pattern:" + ClassifyObjectName(objectName));
                }
                if (objectName.IndexOf("Section", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    signal.Detail("object_type").IndexOf("Section", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    behaviorCase.Features.Add("section_pattern:" + ClassifyObjectName(objectName));
                }
            }

            if (ContainsAny(text, "privateexecutablememory")) behaviorCase.Features.Add("memory:private_execute");
            if (ContainsAny(text, "rwxprivatememory")) behaviorCase.Features.Add("memory:rwx_private");
            if (ContainsAny(text, "privatepeheader")) behaviorCase.Features.Add("memory:private_pe_header");
            if (ContainsAny(text, "threadstartoutsideknownmodule")) behaviorCase.Features.Add("memory:thread_outside_module");
            if (ContainsAny(text, "unsignedmappeddllintarget")) behaviorCase.Features.Add("memory:unsigned_mapped_image");
            if (ContainsAny(text, "mappedimagenotinmodulelist")) behaviorCase.Features.Add("memory:image_not_in_module_list");

            if (ContainsAny(text, "serviceinstalled", "services\\", "runonce", "\\run", "image file execution options"))
            {
                behaviorCase.Features.Add("registry:persistence_or_service");
            }
            if (ContainsAny(text, "codeintegrity", "\\control\\ci")) behaviorCase.Features.Add("registry:code_integrity");
            if (ContainsAny(text, "defender exclusion")) behaviorCase.Features.Add("registry:defender_exclusion");
            if (ContainsAny(text, "powershelllogging")) behaviorCase.Features.Add("registry:powershell_logging");
            if (ContainsAny(text, "auditlogcleared", "auditpolicy")) behaviorCase.Features.Add("telemetry:eventlog_or_audit_tamper");

            if (ContainsAny(text, "trustedprocessabuse")) behaviorCase.Features.Add("trust:trusted_process_abuse");
            if (ContainsAny(text, "trustedprocesskernelchannel")) behaviorCase.Features.Add("trust:trusted_kernel_channel");
            if (ContainsAny(text, "trustedprocesstargetinteraction")) behaviorCase.Features.Add("trust:trusted_target_access");
            if (ContainsAny(text, "trustedprocessunsigned", "trustedprocesssuspiciousmappedimage")) behaviorCase.Features.Add("trust:trusted_unsigned_module");

            if (ContainsAny(text, "nativeabuse", "suspiciouslolbinexecution", "suspiciouspowershellactivity")) behaviorCase.Features.Add("native:lolbin_abuse");
            if (ContainsAny(text, "service_or_driver_control", "driver_or_filter_control")) behaviorCase.Features.Add("native:driver_control");
            if (ContainsAny(text, "registry_identity_or_service_edit", "network_adapter_or_stack_reset")) behaviorCase.Features.Add("native:identity_control");
            if (ContainsAny(text, "localcontrollerchannel", "localhost", "127.0.0.1", "::1", "websocket")) behaviorCase.Features.Add("native:local_controller");

            AddTimingFeatures(behaviorCase);
        }

        private void AddTimingFeatures(BehavioralCase behaviorCase)
        {
            List<BehavioralSignal> ordered = behaviorCase.Signals.OrderBy(s => s.TimestampUtc).ToList();
            if (ordered.Count < 2)
            {
                return;
            }

            TimeSpan span = ordered[ordered.Count - 1].TimestampUtc.Subtract(ordered[0].TimestampUtc);
            if (span.TotalSeconds <= 5) behaviorCase.Features.Add("timing:burst_under_5s");
            else if (span.TotalSeconds <= 30) behaviorCase.Features.Add("timing:burst_under_30s");
            else if (span.TotalMinutes <= 5) behaviorCase.Features.Add("timing:sequence_under_5m");

            if (HasOrderedTags(behaviorCase, "vulnerable_driver_loader", "suspicious_device_channel", "unsigned_game_access"))
            {
                behaviorCase.Features.Add("sequence:loader_device_target");
            }

            if (HasOrderedTags(behaviorCase, "unsigned_game_access", "memory_injection_pattern"))
            {
                behaviorCase.Features.Add("sequence:target_access_then_memory");
            }

            if (HasOrderedTags(behaviorCase, "vulnerable_driver_loader", "transient_loader_behavior"))
            {
                behaviorCase.Features.Add("sequence:loader_then_transient_artifact");
            }

            if (HasOrderedTags(behaviorCase, "lolbin_native_abuse", "vulnerable_driver_loader") ||
                HasOrderedTags(behaviorCase, "lolbin_native_abuse", "hidden_driver_pattern"))
            {
                behaviorCase.Features.Add("sequence:lolbin_then_driver");
            }

            if (HasOrderedTags(behaviorCase, "trusted_process_abuse", "unsigned_game_access") ||
                HasOrderedTags(behaviorCase, "trusted_process_abuse", "memory_injection_pattern"))
            {
                behaviorCase.Features.Add("sequence:trusted_abuse_then_target_or_memory");
            }

            if (HasOrderedTags(behaviorCase, "local_controller_channel", "suspicious_device_channel") ||
                HasOrderedTags(behaviorCase, "local_controller_channel", "unsigned_game_access"))
            {
                behaviorCase.Features.Add("sequence:local_controller_then_device_or_target");
            }
        }

        private bool HasOrderedTags(BehavioralCase behaviorCase, params string[] tags)
        {
            int index = 0;
            foreach (BehavioralSignal signal in behaviorCase.Signals.OrderBy(s => s.TimestampUtc))
            {
                List<string> signalTags = DeriveTags(signal);
                if (signalTags.Contains(tags[index], StringComparer.OrdinalIgnoreCase))
                {
                    index++;
                    if (index == tags.Length)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private void AddArtifacts(BehavioralCase behaviorCase, BehavioralSignal signal)
        {
            AddArtifact(behaviorCase.ProcessNames, signal.ProcessName);
            AddArtifact(behaviorCase.ProcessNames, signal.Detail("source_process_name"));
            AddArtifact(behaviorCase.ProcessNames, signal.Detail("target_process_name"));
            AddArtifact(behaviorCase.ProcessNames, signal.Detail("process_name"));

            AddPathArtifacts(behaviorCase, signal.Path);
            foreach (KeyValuePair<string, string> detail in signal.Details)
            {
                string key = detail.Key ?? string.Empty;
                string value = detail.Value ?? string.Empty;
                if (key.IndexOf("sha256", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    key.Equals("hash", StringComparison.OrdinalIgnoreCase))
                {
                    AddArtifact(behaviorCase.Hashes, value);
                }
                else if (key.IndexOf("path", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         key.IndexOf("file", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         key.IndexOf("image", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         key.IndexOf("module", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddPathArtifacts(behaviorCase, value);
                }
                else if (key.IndexOf("signature_subject", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         key.IndexOf("signer", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddArtifact(behaviorCase.Signers, NormalizeSigner(value));
                }
                else if (key.IndexOf("object_name", StringComparison.OrdinalIgnoreCase) >= 0 ||
                         key.IndexOf("device", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (value.IndexOf("\\Device\\", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        AddArtifact(behaviorCase.DeviceNames, value);
                    }
                }
                else if (key.IndexOf("section", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddArtifact(behaviorCase.SectionNames, value);
                }
                else if (key.IndexOf("command", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddArtifact(behaviorCase.CommandPatterns, NormalizeCommandLine(value));
                }
            }
        }

        private void AddPathArtifacts(BehavioralCase behaviorCase, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            foreach (string token in value.Split(new[] { '|', ';', '\r', '\n', '\t', '"' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string path = token.Trim().Trim('\'', '"');
                if (path.IndexOf(@":\", StringComparison.OrdinalIgnoreCase) > 0 || path.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase))
                {
                    AddArtifact(behaviorCase.Paths, path);
                    string extension = Path.GetExtension(path);
                    if (!string.IsNullOrWhiteSpace(extension))
                    {
                        behaviorCase.Features.Add("artifact_ext:" + extension.ToLowerInvariant());
                    }
                }
            }
        }

        private List<SimilarCase> FindSimilarCases(BehavioralCase behaviorCase)
        {
            List<SimilarCase> matches = new List<SimilarCase>();
            lock (_previousLock)
            {
                foreach (PersistedFingerprint previous in _previousFingerprints)
                {
                    if (string.Equals(previous.FingerprintSha256, behaviorCase.FingerprintSha256, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(previous.CaseId, behaviorCase.CaseId, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    SimilarCase match = ScoreSimilarity(behaviorCase, previous);
                    if (match.Score >= Math.Max(0.35, _options.BehavioralSimilarityThreshold - 0.15))
                    {
                        matches.Add(match);
                    }
                }
            }

            return matches.OrderByDescending(m => m.Score).Take(5).ToList();
        }

        private SimilarCase ScoreSimilarity(BehavioralCase current, PersistedFingerprint previous)
        {
            double featureScore = Jaccard(current.FingerprintFeatures, previous.Features);
            double tagScore = Jaccard(current.Tags, previous.Tags);
            double profileScore = Jaccard(new HashSet<string>(current.Profiles.Where(p => p.Value >= 0.55).Select(p => p.Key), StringComparer.OrdinalIgnoreCase), previous.Profiles);
            double artifactScore = Jaccard(BuildArtifactSet(current), previous.Artifacts);
            double score = featureScore * 0.45 + tagScore * 0.25 + profileScore * 0.15 + artifactScore * 0.15;

            return new SimilarCase
            {
                CaseId = previous.CaseId,
                FingerprintSha256 = previous.FingerprintSha256,
                Score = score,
                SharedTags = current.Tags.Intersect(previous.Tags, StringComparer.OrdinalIgnoreCase).OrderBy(t => t).ToList(),
                SharedFeatures = current.FingerprintFeatures.Intersect(previous.Features, StringComparer.OrdinalIgnoreCase).OrderBy(f => f).ToList()
            };
        }

        private HashSet<string> BuildArtifactSet(BehavioralCase behaviorCase)
        {
            HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string item in behaviorCase.Hashes) set.Add("hash:" + item);
            foreach (string item in behaviorCase.ProcessNames) set.Add("process:" + NormalizeName(item));
            foreach (string item in behaviorCase.Signers) set.Add("signer:" + NormalizeSigner(item));
            foreach (string item in behaviorCase.DeviceNames) set.Add("device:" + ClassifyObjectName(item));
            foreach (string item in behaviorCase.SectionNames) set.Add("section:" + ClassifyObjectName(item));
            foreach (string item in behaviorCase.Paths) set.Add("path_location:" + ClassifyPathLocation(item) + ":" + Path.GetExtension(item).ToLowerInvariant());
            foreach (string item in behaviorCase.CommandPatterns) set.Add("cmd:" + item);
            return set;
        }

        private double CalculateConfidence(BehavioralCase behaviorCase)
        {
            double score = 0.25;
            if (behaviorCase.MaxSeverity >= EventSeverity.High) score += 0.15;
            if (behaviorCase.MaxSeverity >= EventSeverity.Critical) score += 0.10;
            score += Math.Min(0.25, behaviorCase.Tags.Count * 0.04);
            score += Math.Min(0.20, behaviorCase.Profiles.Where(p => p.Value >= 0.55).Sum(p => p.Value) * 0.05);

            string[] dimensions =
            {
                "file_ext:", "process:", "memory:", "device_pattern:", "registry:",
                "target_access:", "telemetry:", "sequence:", "stage:", "trust:", "native:"
            };

            int dimensionCount = dimensions.Count(prefix => behaviorCase.Features.Any(f => f.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)));
            score += Math.Min(0.18, dimensionCount * 0.025);

            if (behaviorCase.SimilarCases.Any(s => s.Score >= _options.BehavioralSimilarityThreshold))
            {
                score += 0.08;
            }

            return Math.Min(0.99, score);
        }

        private static void AddProfileScore(BehavioralCase behaviorCase, string profile, double score)
        {
            if (score >= 0.30)
            {
                behaviorCase.Profiles[profile] = Math.Min(0.99, score);
            }
        }

        private static double ScoreKernelMapper(BehavioralCase c)
        {
            double score = 0;
            if (c.Tags.Contains("vulnerable_driver_loader")) score += 0.35;
            if (c.Tags.Contains("hidden_driver_pattern")) score += 0.25;
            if (c.Tags.Contains("transient_loader_behavior")) score += 0.15;
            if (c.Features.Contains("artifact_ext:.sys")) score += 0.15;
            if (c.Features.Any(f => f.StartsWith("device_pattern:", StringComparison.OrdinalIgnoreCase))) score += 0.10;
            return score;
        }

        private static double ScoreHiddenDriverController(BehavioralCase c)
        {
            double score = 0;
            if (c.Tags.Contains("hidden_driver_pattern")) score += 0.30;
            if (c.Tags.Contains("suspicious_device_channel")) score += 0.30;
            if (c.Tags.Contains("unsigned_game_access")) score += 0.15;
            if (c.Features.Contains("sequence:loader_device_target")) score += 0.20;
            if (c.Features.Any(f => f.StartsWith("device_pattern:", StringComparison.OrdinalIgnoreCase))) score += 0.10;
            return score;
        }

        private static double ScoreManualMapInjector(BehavioralCase c)
        {
            double score = 0;
            if (c.Tags.Contains("manual_map_behavior")) score += 0.30;
            if (c.Tags.Contains("memory_injection_pattern")) score += 0.30;
            if (c.Tags.Contains("unsigned_game_access")) score += 0.20;
            if (c.Features.Contains("memory:private_pe_header")) score += 0.10;
            if (c.Features.Contains("memory:image_not_in_module_list")) score += 0.10;
            if (c.Features.Contains("sequence:target_access_then_memory")) score += 0.15;
            return score;
        }

        private static double ScoreTransientBootstrap(BehavioralCase c)
        {
            double score = 0;
            if (c.Tags.Contains("transient_loader_behavior")) score += 0.35;
            if (c.Features.Contains("timing:burst_under_5s") || c.Features.Contains("timing:burst_under_30s")) score += 0.20;
            if (c.Features.Contains("sequence:loader_then_transient_artifact")) score += 0.25;
            if (c.Features.Any(f => f.StartsWith("stage:temp", StringComparison.OrdinalIgnoreCase) || f.StartsWith("stage:downloads", StringComparison.OrdinalIgnoreCase))) score += 0.10;
            if (c.Tags.Contains("vulnerable_driver_loader")) score += 0.10;
            return score;
        }

        private static double ScoreUnsignedTargetManipulator(BehavioralCase c)
        {
            double score = 0;
            if (c.Tags.Contains("unsigned_game_access")) score += 0.40;
            if (c.Features.Contains("target_access:write_or_thread")) score += 0.25;
            if (c.Tags.Contains("memory_injection_pattern")) score += 0.20;
            if (c.Features.Contains("sequence:target_access_then_memory")) score += 0.15;
            return score;
        }

        private static double ScoreTelemetryTamperUtility(BehavioralCase c)
        {
            double score = 0;
            if (c.Tags.Contains("telemetry_tamper_behavior")) score += 0.45;
            if (c.Tags.Contains("anti_debug_behavior")) score += 0.15;
            if (c.Features.Contains("telemetry:eventlog_or_audit_tamper")) score += 0.20;
            if (c.Features.Contains("registry:defender_exclusion")) score += 0.10;
            if (c.Features.Contains("registry:powershell_logging")) score += 0.10;
            if (c.Features.Contains("registry:code_integrity")) score += 0.10;
            return score;
        }

        private static double ScoreTrustedProcessAbuse(BehavioralCase c)
        {
            double score = 0;
            if (c.Tags.Contains("trusted_process_abuse")) score += 0.40;
            if (c.Tags.Contains("memory_injection_pattern")) score += 0.15;
            if (c.Tags.Contains("suspicious_device_channel")) score += 0.15;
            if (c.Tags.Contains("unsigned_game_access")) score += 0.15;
            if (c.Features.Contains("trust:trusted_unsigned_module")) score += 0.12;
            if (c.Features.Contains("trust:trusted_kernel_channel")) score += 0.10;
            if (c.Features.Contains("sequence:trusted_abuse_then_target_or_memory")) score += 0.15;
            return score;
        }

        private static double ScoreLolbinNativeLoader(BehavioralCase c)
        {
            double score = 0;
            if (c.Tags.Contains("lolbin_native_abuse")) score += 0.35;
            if (c.Tags.Contains("vulnerable_driver_loader")) score += 0.15;
            if (c.Tags.Contains("transient_loader_behavior")) score += 0.12;
            if (c.Features.Contains("native:driver_control")) score += 0.18;
            if (c.Features.Contains("native:identity_control")) score += 0.12;
            if (c.Features.Contains("sequence:lolbin_then_driver")) score += 0.18;
            if (c.Features.Contains("telemetry:eventlog_or_audit_tamper")) score += 0.08;
            return score;
        }

        private static double ScoreLocalControllerWorkflow(BehavioralCase c)
        {
            double score = 0;
            if (c.Tags.Contains("local_controller_channel")) score += 0.35;
            if (c.Tags.Contains("suspicious_device_channel")) score += 0.18;
            if (c.Tags.Contains("unsigned_game_access")) score += 0.15;
            if (c.Features.Contains("native:local_controller")) score += 0.15;
            if (c.Features.Contains("sequence:local_controller_then_device_or_target")) score += 0.20;
            return score;
        }

        private string BuildNarrative(BehavioralCase behaviorCase)
        {
            List<string> parts = new List<string>();
            string loader = FirstProcessName(behaviorCase);
            string location = FirstStageLocation(behaviorCase);
            string driver = behaviorCase.Paths.FirstOrDefault(p => Path.GetExtension(p).Equals(".sys", StringComparison.OrdinalIgnoreCase));
            string device = behaviorCase.DeviceNames.FirstOrDefault();
            string target = FirstTargetName(behaviorCase);
            bool vmWrite = behaviorCase.Features.Contains("target_access:write_or_thread");
            bool privateMemory = behaviorCase.Features.Contains("memory:private_execute") ||
                                 behaviorCase.Features.Contains("memory:rwx_private") ||
                                 behaviorCase.Features.Contains("memory:private_pe_header");

            if (!string.IsNullOrWhiteSpace(loader))
            {
                parts.Add(loader + (string.IsNullOrWhiteSpace(location) ? " appeared" : " appeared in " + location));
            }

            if (!string.IsNullOrWhiteSpace(driver))
            {
                parts.Add("created or referenced driver artifact " + Path.GetFileName(driver));
            }
            else if (behaviorCase.Features.Any(f => f.StartsWith("artifact_ext:.dll", StringComparison.OrdinalIgnoreCase)))
            {
                parts.Add("staged DLL artifacts");
            }

            if (behaviorCase.Tags.Contains("transient_loader_behavior"))
            {
                parts.Add("used short-lived or renamed staging behavior");
            }

            if (!string.IsNullOrWhiteSpace(device))
            {
                parts.Add("opened device or communication object " + device);
            }

            if (!string.IsNullOrWhiteSpace(target))
            {
                parts.Add("accessed " + target + (vmWrite ? " with write/operation-style rights" : string.Empty));
            }

            if (privateMemory)
            {
                parts.Add((string.IsNullOrWhiteSpace(target) ? "the target process" : target) + " developed private executable memory indicators");
            }

            if (behaviorCase.Tags.Contains("telemetry_tamper_behavior"))
            {
                parts.Add("telemetry or evidence tamper signals appeared nearby");
            }

            if (behaviorCase.Tags.Contains("trusted_process_abuse"))
            {
                parts.Add("a trusted application showed abuse indicators");
            }

            if (behaviorCase.Tags.Contains("lolbin_native_abuse"))
            {
                parts.Add("native Windows tooling was used in a suspicious chain");
            }

            if (behaviorCase.Tags.Contains("local_controller_channel"))
            {
                parts.Add("localhost or controller-style communication appeared");
            }

            if (parts.Count == 0)
            {
                return "Behavioral profile accumulated " + behaviorCase.Tags.Count.ToString(CultureInfo.InvariantCulture) +
                       " tags and " + behaviorCase.FingerprintFeatures.Count.ToString(CultureInfo.InvariantCulture) + " fingerprint features.";
            }

            return string.Join(", then ", parts.ToArray()) + ".";
        }

        private string BuildCaseKey(BehavioralSignal signal)
        {
            string caseId = FirstNonEmpty(signal.Detail("case_id"), signal.Detail("behavior_case_id"));
            if (!string.IsNullOrWhiteSpace(caseId))
            {
                return "case:" + caseId;
            }

            string sourcePid = signal.Detail("source_process_id");
            string targetPid = signal.Detail("target_process_id");
            if (!string.IsNullOrWhiteSpace(sourcePid) || !string.IsNullOrWhiteSpace(targetPid))
            {
                return "pid:" + sourcePid + "->" + targetPid;
            }

            if (signal.ProcessId.HasValue)
            {
                return "pid:" + signal.ProcessId.Value.ToString(CultureInfo.InvariantCulture);
            }

            if (!string.IsNullOrWhiteSpace(signal.Path))
            {
                return "path:" + NormalizePathKey(signal.Path);
            }

            long bucket = signal.TimestampUtc.Ticks / _options.BehavioralProfileWindow.Ticks;
            return "bucket:" + signal.Category + "|" + bucket.ToString(CultureInfo.InvariantCulture);
        }

        private string BuildBehaviorCaseId(BehavioralSignal signal)
        {
            string upstream = FirstNonEmpty(signal.Detail("case_id"), signal.Detail("behavior_case_id"));
            if (!string.IsNullOrWhiteSpace(upstream))
            {
                return "BHV-" + SanitizeFileName(upstream);
            }

            return "BHV-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        private bool IsCaseBearing(BehavioralSignal signal)
        {
            return !string.IsNullOrWhiteSpace(signal.Detail("case_id")) ||
                   signal.Category.StartsWith("TargetInteraction", StringComparison.OrdinalIgnoreCase) ||
                   signal.Category.StartsWith("KernelComm", StringComparison.OrdinalIgnoreCase) ||
                   signal.Category.StartsWith("HiddenKernel", StringComparison.OrdinalIgnoreCase) ||
                   signal.Category.StartsWith("DefensiveIntegrity", StringComparison.OrdinalIgnoreCase);
        }

        private void WriteCaseProfile(string path, BehavioralCase behaviorCase)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("{");
            bool first = true;
            JsonUtilities.AppendStringProperty(builder, "behavior_case_id", behaviorCase.CaseId, ref first);
            JsonUtilities.AppendStringProperty(builder, "case_key", behaviorCase.CaseKey, ref first);
            JsonUtilities.AppendStringProperty(builder, "first_seen_utc", behaviorCase.FirstSeenUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "last_seen_utc", behaviorCase.LastSeenUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "confidence_score", behaviorCase.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "fingerprint_sha256", behaviorCase.FingerprintSha256, ref first);
            JsonUtilities.AppendStringProperty(builder, "narrative", behaviorCase.Narrative, ref first);
            AppendArray(builder, "tags", behaviorCase.Tags.OrderBy(t => t), ref first);
            AppendArray(builder, "fingerprint_features", behaviorCase.FingerprintFeatures.OrderBy(f => f), ref first);
            AppendProfiles(builder, "rule_profiles", behaviorCase.Profiles, ref first);
            AppendArray(builder, "hashes", behaviorCase.Hashes.OrderBy(v => v), ref first);
            AppendArray(builder, "paths", behaviorCase.Paths.OrderBy(v => v), ref first);
            AppendArray(builder, "signers", behaviorCase.Signers.OrderBy(v => v), ref first);
            AppendArray(builder, "process_names", behaviorCase.ProcessNames.OrderBy(v => v), ref first);
            AppendArray(builder, "device_names", behaviorCase.DeviceNames.OrderBy(v => v), ref first);
            AppendArray(builder, "section_names", behaviorCase.SectionNames.OrderBy(v => v), ref first);
            AppendSimilarCases(builder, "similar_cases", behaviorCase.SimilarCases, ref first);
            AppendTimeline(builder, "timeline", behaviorCase.Signals.OrderBy(s => s.TimestampUtc), ref first);
            builder.Append("}");
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
        }

        private void AppendFingerprint(BehavioralCase behaviorCase)
        {
            PersistedFingerprint persisted = new PersistedFingerprint
            {
                CaseId = behaviorCase.CaseId,
                FingerprintSha256 = behaviorCase.FingerprintSha256,
                Tags = new HashSet<string>(behaviorCase.Tags, StringComparer.OrdinalIgnoreCase),
                Features = new HashSet<string>(behaviorCase.FingerprintFeatures, StringComparer.OrdinalIgnoreCase),
                Profiles = new HashSet<string>(behaviorCase.Profiles.Where(p => p.Value >= 0.55).Select(p => p.Key), StringComparer.OrdinalIgnoreCase),
                Artifacts = BuildArtifactSet(behaviorCase),
                CreatedUtc = DateTime.UtcNow
            };

            lock (_writeLock)
            {
                File.AppendAllText(_fingerprintPath, PersistedFingerprintToJson(persisted) + Environment.NewLine, Encoding.UTF8);
            }

            lock (_previousLock)
            {
                _previousFingerprints.Add(persisted);
                if (_previousFingerprints.Count > 2000)
                {
                    _previousFingerprints.RemoveAt(0);
                }
            }
        }

        private void LoadPreviousFingerprints()
        {
            if (!File.Exists(_fingerprintPath))
            {
                return;
            }

            try
            {
                foreach (string line in File.ReadLines(_fingerprintPath))
                {
                    PersistedFingerprint fingerprint = TryParseFingerprint(line);
                    if (fingerprint != null)
                    {
                        _previousFingerprints.Add(fingerprint);
                    }
                }
            }
            catch
            {
            }
        }

        private static PersistedFingerprint TryParseFingerprint(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                return null;
            }

            string caseId = ExtractJsonString(line, "case_id");
            string fingerprint = ExtractJsonString(line, "fingerprint_sha256");
            if (string.IsNullOrWhiteSpace(fingerprint))
            {
                return null;
            }

            return new PersistedFingerprint
            {
                CaseId = caseId,
                FingerprintSha256 = fingerprint,
                Tags = SplitSet(ExtractJsonString(line, "tags")),
                Features = SplitSet(ExtractJsonString(line, "features")),
                Profiles = SplitSet(ExtractJsonString(line, "profiles")),
                Artifacts = SplitSet(ExtractJsonString(line, "artifacts")),
                CreatedUtc = DateTime.UtcNow
            };
        }

        private static string PersistedFingerprintToJson(PersistedFingerprint fingerprint)
        {
            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "created_utc", fingerprint.CreatedUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "case_id", fingerprint.CaseId, ref first);
            JsonUtilities.AppendStringProperty(builder, "fingerprint_sha256", fingerprint.FingerprintSha256, ref first);
            JsonUtilities.AppendStringProperty(builder, "tags", string.Join(";", fingerprint.Tags.OrderBy(v => v).ToArray()), ref first);
            JsonUtilities.AppendStringProperty(builder, "features", string.Join(";", fingerprint.Features.OrderBy(v => v).ToArray()), ref first);
            JsonUtilities.AppendStringProperty(builder, "profiles", string.Join(";", fingerprint.Profiles.OrderBy(v => v).ToArray()), ref first);
            JsonUtilities.AppendStringProperty(builder, "artifacts", string.Join(";", fingerprint.Artifacts.OrderBy(v => v).ToArray()), ref first);
            builder.Append("}");
            return builder.ToString();
        }

        private void CleanupExpiredCases()
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(_options.BehavioralProfileWindow.Add(TimeSpan.FromMinutes(5)));
            foreach (KeyValuePair<string, BehavioralCase> pair in _cases.ToArray())
            {
                if (pair.Value.LastSeenUtc < cutoff)
                {
                    BehavioralCase ignored;
                    _cases.TryRemove(pair.Key, out ignored);
                }
            }
        }

        private static void AppendArray(StringBuilder builder, string name, IEnumerable<string> values, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"");
            builder.Append(JsonUtilities.Escape(name));
            builder.Append("\":[");
            bool firstValue = true;
            foreach (string value in values)
            {
                if (!firstValue) builder.Append(",");
                builder.Append("\"");
                builder.Append(JsonUtilities.Escape(value ?? string.Empty));
                builder.Append("\"");
                firstValue = false;
            }
            builder.Append("]");
            first = false;
        }

        private static void AppendProfiles(StringBuilder builder, string name, IDictionary<string, double> profiles, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"");
            builder.Append(JsonUtilities.Escape(name));
            builder.Append("\":{");
            bool firstValue = true;
            foreach (KeyValuePair<string, double> profile in profiles.OrderByDescending(p => p.Value))
            {
                if (!firstValue) builder.Append(",");
                builder.Append("\"");
                builder.Append(JsonUtilities.Escape(profile.Key));
                builder.Append("\":\"");
                builder.Append(profile.Value.ToString("0.00", CultureInfo.InvariantCulture));
                builder.Append("\"");
                firstValue = false;
            }
            builder.Append("}");
            first = false;
        }

        private static void AppendSimilarCases(StringBuilder builder, string name, IEnumerable<SimilarCase> cases, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"");
            builder.Append(JsonUtilities.Escape(name));
            builder.Append("\":[");
            bool firstCase = true;
            foreach (SimilarCase similar in cases)
            {
                if (!firstCase) builder.Append(",");
                builder.Append("{");
                bool firstProperty = true;
                JsonUtilities.AppendStringProperty(builder, "case_id", similar.CaseId, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "fingerprint_sha256", similar.FingerprintSha256, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "score", similar.Score.ToString("0.00", CultureInfo.InvariantCulture), ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "shared_tags", string.Join(";", similar.SharedTags.ToArray()), ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "shared_features", string.Join(";", similar.SharedFeatures.Take(40).ToArray()), ref firstProperty);
                builder.Append("}");
                firstCase = false;
            }
            builder.Append("]");
            first = false;
        }

        private static void AppendTimeline(StringBuilder builder, string name, IEnumerable<BehavioralSignal> signals, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"");
            builder.Append(JsonUtilities.Escape(name));
            builder.Append("\":[");
            bool firstSignal = true;
            foreach (BehavioralSignal signal in signals.Take(200))
            {
                if (!firstSignal) builder.Append(",");
                builder.Append("{");
                bool firstProperty = true;
                JsonUtilities.AppendStringProperty(builder, "timestamp_utc", signal.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "category", signal.Category, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "action", signal.Action, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "severity", signal.Severity.ToString(), ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "description", signal.Description, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "path", signal.Path, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "process_id", signal.ProcessId.HasValue ? signal.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : string.Empty, ref firstProperty);
                builder.Append("}");
                firstSignal = false;
            }
            builder.Append("]");
            first = false;
        }

        private static string FormatProfiles(IDictionary<string, double> profiles)
        {
            return string.Join(";", profiles
                .OrderByDescending(p => p.Value)
                .Select(p => p.Key + ":" + p.Value.ToString("0.00", CultureInfo.InvariantCulture))
                .ToArray());
        }

        private static string FormatSimilarCases(IEnumerable<SimilarCase> cases)
        {
            return string.Join(";", cases.Select(c => c.CaseId + ":" + c.Score.ToString("0.00", CultureInfo.InvariantCulture)).ToArray());
        }

        private static string TopProfileName(BehavioralCase behaviorCase)
        {
            KeyValuePair<string, double> profile = behaviorCase.Profiles.OrderByDescending(p => p.Value).FirstOrDefault();
            return string.IsNullOrWhiteSpace(profile.Key) ? "unclassified_behavior" : profile.Key;
        }

        private static double Jaccard(ISet<string> a, ISet<string> b)
        {
            if (a == null || b == null || (a.Count == 0 && b.Count == 0))
            {
                return 0;
            }

            int intersection = a.Intersect(b, StringComparer.OrdinalIgnoreCase).Count();
            int union = a.Union(b, StringComparer.OrdinalIgnoreCase).Count();
            return union == 0 ? 0 : (double)intersection / union;
        }

        private static string HashFeatureSet(IEnumerable<string> features)
        {
            string canonical = string.Join("\n", features.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToArray());
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(canonical));
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                }
                return builder.ToString();
            }
        }

        private static string ClassifyPathLocation(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "unknown";
            }

            string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (FileClassifier.IsUnder(path, Path.GetTempPath())) return "temp";
            if (FileClassifier.IsUnder(path, Path.Combine(user, "Downloads"))) return "downloads";
            if (FileClassifier.IsUnder(path, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory))) return "desktop";
            if (FileClassifier.IsUnder(path, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData))) return "localappdata";
            if (FileClassifier.IsUnder(path, Environment.GetFolderPath(Environment.SpecialFolder.Windows))) return "windows";
            if (FileClassifier.IsHighValuePersistencePath(path)) return "persistence";
            return "other";
        }

        private static string ClassifyObjectName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "unknown";
            string leaf = LeafName(name);
            if (LooksGuidLike(leaf)) return "guid_like";
            if (LooksRandomLike(leaf)) return "randomized";
            if (ContainsAny(name, "iqvw", "gdrv", "capcom", "dbutil", "rtcore", "winio", "mhyprot")) return "vulnerable_driver_named";
            if (name.IndexOf("\\Device\\NamedPipe", StringComparison.OrdinalIgnoreCase) >= 0) return "named_pipe";
            if (name.IndexOf("\\BaseNamedObjects", StringComparison.OrdinalIgnoreCase) >= 0) return "base_named_object";
            return NormalizePattern(leaf);
        }

        private static bool LooksGuidLike(string value)
        {
            return !string.IsNullOrWhiteSpace(value) && (value.IndexOf('{') >= 0 || value.Count(c => c == '-') >= 3);
        }

        private static bool LooksRandomLike(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length < 8) return false;
            int letters = value.Count(char.IsLetter);
            int digits = value.Count(char.IsDigit);
            int vowels = value.Count(c => "aeiouAEIOU".IndexOf(c) >= 0);
            return letters >= 5 && digits >= 2 && vowels <= Math.Max(1, letters / 5);
        }

        private static string LeafName(string value)
        {
            int slash = string.IsNullOrWhiteSpace(value) ? -1 : value.LastIndexOf('\\');
            return slash >= 0 && slash + 1 < value.Length ? value.Substring(slash + 1) : value;
        }

        private static string NormalizePattern(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return string.Empty;
            StringBuilder builder = new StringBuilder();
            foreach (char c in value.ToLowerInvariant())
            {
                if (char.IsLetter(c)) builder.Append('a');
                else if (char.IsDigit(c)) builder.Append('0');
                else if (c == '\\' || c == '/' || c == '-' || c == '_' || c == '.' || c == ':' || c == '>') builder.Append(c);
            }
            string result = builder.ToString();
            while (result.IndexOf("aa", StringComparison.OrdinalIgnoreCase) >= 0) result = result.Replace("aa", "a");
            while (result.IndexOf("00", StringComparison.OrdinalIgnoreCase) >= 0) result = result.Replace("00", "0");
            return result.Length > 80 ? result.Substring(0, 80) : result;
        }

        private static string NormalizeName(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? string.Empty : Path.GetFileName(value).ToLowerInvariant();
        }

        private static string NormalizeSigner(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return string.Empty;
            string signer = value.ToLowerInvariant();
            int cn = signer.IndexOf("cn=", StringComparison.OrdinalIgnoreCase);
            if (cn >= 0) signer = signer.Substring(cn + 3);
            int comma = signer.IndexOf(',');
            if (comma >= 0) signer = signer.Substring(0, comma);
            return signer.Trim();
        }

        private static string NormalizeCommandLine(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return string.Empty;
            string text = value.ToLowerInvariant();
            text = ReplaceQuotedPaths(text);
            text = text.Replace(Environment.UserName.ToLowerInvariant(), "%user%");
            return text.Length > 160 ? text.Substring(0, 160) : text;
        }

        private static string ReplaceQuotedPaths(string value)
        {
            StringBuilder builder = new StringBuilder();
            bool inPath = false;
            foreach (char c in value)
            {
                if (char.IsLetter(c) && !inPath)
                {
                    builder.Append(c);
                    continue;
                }
                if (c == ':' || c == '\\' || c == '/')
                {
                    if (!inPath)
                    {
                        builder.Append("%path%");
                        inPath = true;
                    }
                    continue;
                }
                if (char.IsWhiteSpace(c))
                {
                    inPath = false;
                    builder.Append(' ');
                    continue;
                }
                if (!inPath)
                {
                    builder.Append(char.IsDigit(c) ? '0' : c);
                }
            }
            return builder.ToString();
        }

        private static string NormalizePathKey(string path)
        {
            return ClassifyPathLocation(path) + "|" + Path.GetExtension(path).ToLowerInvariant() + "|" + Path.GetFileName(path).ToLowerInvariant();
        }

        private static void AddArtifact(ISet<string> set, string value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                set.Add(value.Trim());
            }
        }

        private static string FirstProcessName(BehavioralCase c)
        {
            return c.ProcessNames.FirstOrDefault(p => !string.IsNullOrWhiteSpace(p));
        }

        private static string FirstTargetName(BehavioralCase c)
        {
            return c.Signals.Select(s => s.Detail("target_process_name")).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
        }

        private static string FirstStageLocation(BehavioralCase c)
        {
            string feature = c.Features.FirstOrDefault(f => f.StartsWith("stage:", StringComparison.OrdinalIgnoreCase) &&
                                                            !f.Equals("stage:unknown", StringComparison.OrdinalIgnoreCase) &&
                                                            !f.Equals("stage:other", StringComparison.OrdinalIgnoreCase));
            return string.IsNullOrWhiteSpace(feature) ? string.Empty : feature.Substring("stage:".Length);
        }

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value)) return value;
            }
            return string.Empty;
        }

        private static bool ContainsAny(string value, params string[] terms)
        {
            if (string.IsNullOrWhiteSpace(value)) return false;
            foreach (string term in terms)
            {
                if (value.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            return false;
        }

        private static HashSet<string> SplitSet(string value)
        {
            HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(value)) return set;
            foreach (string part in value.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                set.Add(part.Trim());
            }
            return set;
        }

        private static string ExtractJsonString(string json, string key)
        {
            string marker = "\"" + key + "\":";
            int start = json.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (start < 0) return null;
            start += marker.Length;
            while (start < json.Length && char.IsWhiteSpace(json[start])) start++;
            if (start >= json.Length || json[start] != '"') return null;
            start++;
            StringBuilder builder = new StringBuilder();
            bool escape = false;
            for (int i = start; i < json.Length; i++)
            {
                char c = json[i];
                if (escape)
                {
                    builder.Append(c);
                    escape = false;
                }
                else if (c == '\\')
                {
                    escape = true;
                }
                else if (c == '"')
                {
                    break;
                }
                else
                {
                    builder.Append(c);
                }
            }
            return builder.ToString();
        }

        private static string SanitizeFileName(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "unknown";
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
        }

        private sealed class BehavioralSignal
        {
            public DateTime TimestampUtc { get; set; }
            public string Category { get; set; }
            public string Action { get; set; }
            public EventSeverity Severity { get; set; }
            public string Description { get; set; }
            public string Path { get; set; }
            public int? ProcessId { get; set; }
            public string ProcessName { get; set; }
            public Dictionary<string, string> Details { get; set; }

            public string Text
            {
                get { return (Category + " " + Action + " " + Description + " " + Path + " " + string.Join(" ", Details.Values.ToArray())).ToLowerInvariant(); }
            }

            public string Detail(string key)
            {
                string value;
                return Details != null && Details.TryGetValue(key, out value) ? value ?? string.Empty : string.Empty;
            }

            public static BehavioralSignal FromEvent(DetectionEvent detectionEvent)
            {
                Dictionary<string, string> details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (KeyValuePair<string, string> pair in detectionEvent.Details)
                {
                    details[pair.Key] = pair.Value;
                }

                return new BehavioralSignal
                {
                    TimestampUtc = detectionEvent.TimestampUtc.UtcDateTime,
                    Category = detectionEvent.Category,
                    Action = detectionEvent.Action,
                    Severity = detectionEvent.Severity,
                    Description = detectionEvent.Description,
                    Path = detectionEvent.Path,
                    ProcessId = detectionEvent.ProcessId,
                    ProcessName = detectionEvent.ProcessName,
                    Details = details
                };
            }
        }

        private sealed class BehavioralCase
        {
            public BehavioralCase()
            {
                SyncRoot = new object();
                Signals = new List<BehavioralSignal>();
                Tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Features = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                FingerprintFeatures = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Profiles = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
                SimilarCases = new List<SimilarCase>();
                Hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Signers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                ProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                SectionNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                DeviceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                CommandPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                MaxSeverity = EventSeverity.Low;
            }

            public object SyncRoot { get; private set; }
            public string CaseKey { get; set; }
            public string CaseId { get; set; }
            public DateTime FirstSeenUtc { get; set; }
            public DateTime LastSeenUtc { get; set; }
            public List<BehavioralSignal> Signals { get; private set; }
            public HashSet<string> Tags { get; private set; }
            public HashSet<string> Features { get; private set; }
            public HashSet<string> FingerprintFeatures { get; private set; }
            public Dictionary<string, double> Profiles { get; private set; }
            public List<SimilarCase> SimilarCases { get; set; }
            public HashSet<string> Hashes { get; private set; }
            public HashSet<string> Paths { get; private set; }
            public HashSet<string> Signers { get; private set; }
            public HashSet<string> ProcessNames { get; private set; }
            public HashSet<string> SectionNames { get; private set; }
            public HashSet<string> DeviceNames { get; private set; }
            public HashSet<string> CommandPatterns { get; private set; }
            public EventSeverity MaxSeverity { get; set; }
            public double ConfidenceScore { get; set; }
            public string FingerprintSha256 { get; set; }
            public string Narrative { get; set; }
            public int LastEmittedVersion { get; set; }
            public DateTime LastEmittedUtc { get; set; }
        }

        private sealed class PersistedFingerprint
        {
            public string CaseId { get; set; }
            public string FingerprintSha256 { get; set; }
            public HashSet<string> Tags { get; set; }
            public HashSet<string> Features { get; set; }
            public HashSet<string> Profiles { get; set; }
            public HashSet<string> Artifacts { get; set; }
            public DateTime CreatedUtc { get; set; }
        }

        private sealed class SimilarCase
        {
            public string CaseId { get; set; }
            public string FingerprintSha256 { get; set; }
            public double Score { get; set; }
            public List<string> SharedTags { get; set; }
            public List<string> SharedFeatures { get; set; }
        }
    }
}
