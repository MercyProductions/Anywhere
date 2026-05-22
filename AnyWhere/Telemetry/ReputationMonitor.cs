using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace AnyWhere.Telemetry
{
    internal sealed class ReputationMonitor : IDetectionMonitor
    {
        private static readonly Regex Sha256Regex = new Regex(@"\b[a-fA-F0-9]{64}\b", RegexOptions.Compiled);
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly string _reputationRoot;
        private readonly HashSet<string> _reportedSignals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private ReputationStore _store;
        private bool _disposed;

        public ReputationMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _reputationRoot = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Reputation");
        }

        public string Name
        {
            get { return "Reputation and Intelligence"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_reputationRoot);
            _store = ReputationStore.Open(_reputationRoot);

            ApplyConfiguredImports();
            ApplyConfiguredManualMarks();
            ApplyConfiguredExport();
            _store.Flush();

            if (_options.ReputationEnabled)
            {
                _logger.EventLogged += OnEventLogged;
            }

            _logger.Log(DetectionEvent.Create(
                "Reputation",
                _options.ReputationEnabled ? "Started" : "Disabled",
                EventSeverity.Low,
                _options.ReputationEnabled
                    ? "Local reputation and intelligence layer started."
                    : "Local reputation observation is disabled by configuration.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "reputation_root", _reputationRoot },
                    { "reputation_store_path", _store.StorePath },
                    { "record_count", _store.Count.ToString(CultureInfo.InvariantCulture) },
                    { "supported_categories", "trusted;known_good;unknown;suspicious;confirmed_cheat_artifact;confirmed_mapper;confirmed_loader;confirmed_hidden_driver_indicator;false_positive" },
                    { "tracked_artifact_types", "sha256;file_path;file_name;signer_subject;certificate_thumbprint;device_name;section_name;service_name;registry_key;command_pattern;detection_profile;case_fingerprint" },
                    { "safety_rule", "Defensive local classification only; original telemetry is preserved and never hidden or modified." }
                }));
        }

        private void ApplyConfiguredImports()
        {
            foreach (string path in _options.ReputationImportPaths)
            {
                try
                {
                    ReputationImportResult result = _store.Import(path);
                    _logger.Log(DetectionEvent.Create(
                        "Reputation",
                        "ImportApplied",
                        EventSeverity.Low,
                        "Reputation intelligence import processed.",
                        path,
                        null,
                        new Dictionary<string, string>
                        {
                            { "import_path", path },
                            { "imported_records", result.Imported.ToString(CultureInfo.InvariantCulture) },
                            { "updated_records", result.Updated.ToString(CultureInfo.InvariantCulture) },
                            { "skipped_records", result.Skipped.ToString(CultureInfo.InvariantCulture) },
                            { "reputation_store_path", _store.StorePath }
                        }));
                }
                catch (Exception ex)
                {
                    _logger.LogException("Reputation", "ImportFailed", ex, path);
                }
            }
        }

        private void ApplyConfiguredManualMarks()
        {
            foreach (string mark in _options.ReputationMarks)
            {
                string caseId;
                string artifactType;
                ReputationCategory category;
                string value;
                string note;
                if (!TryParseManualMark(mark, out caseId, out artifactType, out category, out value, out note))
                {
                    _logger.Log(DetectionEvent.Create(
                        "Reputation",
                        "ManualMarkRejected",
                        EventSeverity.Medium,
                        "Manual reputation mark could not be parsed.",
                        null,
                        null,
                        new Dictionary<string, string>
                        {
                            { "mark", mark },
                            { "expected_format", "type|category|value|note or case_id|type|category|value|note" }
                        }));
                    continue;
                }

                ReputationRecord record = _store.ApplyManualMark(artifactType, value, category, note, caseId);
                _logger.Log(DetectionEvent.Create(
                    "Reputation",
                    "ManualMarkApplied",
                    EventSeverity.Low,
                    "Manual reputation classification applied.",
                    null,
                    null,
                    new Dictionary<string, string>
                    {
                        { "artifact_type", record == null ? artifactType : record.ArtifactType },
                        { "artifact_value", value },
                        { "normalized_value", record == null ? ReputationStore.NormalizeArtifactValue(artifactType, value) : record.NormalizedValue },
                        { "reputation_category", ReputationStore.FormatCategory(category) },
                        { "case_id", caseId ?? string.Empty },
                        { "note", note ?? string.Empty },
                        { "reputation_store_path", _store.StorePath }
                    }));
            }
        }

        private void ApplyConfiguredExport()
        {
            if (string.IsNullOrWhiteSpace(_options.ReputationExportPath))
            {
                return;
            }

            try
            {
                _store.Export(_options.ReputationExportPath);
                _logger.Log(DetectionEvent.Create(
                    "Reputation",
                    "ExportWritten",
                    EventSeverity.Low,
                    "Reputation intelligence export written.",
                    _options.ReputationExportPath,
                    null,
                    new Dictionary<string, string>
                    {
                        { "export_path", _options.ReputationExportPath },
                        { "record_count", _store.Count.ToString(CultureInfo.InvariantCulture) }
                    }));
            }
            catch (Exception ex)
            {
                _logger.LogException("Reputation", "ExportFailed", ex, _options.ReputationExportPath);
            }
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed ||
                !_options.ReputationEnabled ||
                detectionEvent == null ||
                IsDerivedAnalysisEvent(detectionEvent.Category))
            {
                return;
            }

            if (!ShouldTrackEvent(detectionEvent))
            {
                return;
            }

            List<ReputationObservation> observations = ExtractObservations(detectionEvent);
            if (observations.Count == 0)
            {
                return;
            }

            List<ReputationAssessment> assessments = new List<ReputationAssessment>();
            foreach (ReputationObservation observation in observations)
            {
                ReputationAssessment assessment = _store.Observe(observation);
                if (assessment != null)
                {
                    assessments.Add(assessment);
                }
            }

            _store.Flush();
            EmitReputationSignals(detectionEvent, assessments);
        }

        private static bool IsDerivedAnalysisEvent(string category)
        {
            if (string.IsNullOrWhiteSpace(category))
            {
                return false;
            }

            return category.StartsWith("Reputation", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("DetectionEngine", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("BehaviorProfile", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("BehavioralProfile", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("BaselineLearning", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("SessionReplay", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("ActiveCapture", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("EvidenceDatabase", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("Monitor", StringComparison.OrdinalIgnoreCase) ||
                   category.StartsWith("Replay", StringComparison.OrdinalIgnoreCase);
        }

        private bool ShouldTrackEvent(DetectionEvent detectionEvent)
        {
            if (detectionEvent.Severity >= EventSeverity.Medium)
            {
                return true;
            }

            if (HasCaseId(detectionEvent))
            {
                return true;
            }

            if (IsSuspiciousCategory(detectionEvent.Category))
            {
                return true;
            }

            if (detectionEvent.Category.Equals("File", StringComparison.OrdinalIgnoreCase) &&
                (HasAnyDetailKey(detectionEvent, "sha256", "signature_subject") ||
                 FileClassifier.IsLikelyExecutable(detectionEvent.Path)))
            {
                return true;
            }

            return false;
        }

        private List<ReputationObservation> ExtractObservations(DetectionEvent detectionEvent)
        {
            List<ReputationObservation> observations = new List<ReputationObservation>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string caseId = ExtractCaseId(detectionEvent);
            bool suspicious = IsSuspiciousEvent(detectionEvent);
            HashSet<string> tags = ExtractTags(detectionEvent);
            string signatureStatus = FirstDetail(detectionEvent, "signature_status", "source_signature_status", "target_signature_status");

            AddPathObservations(observations, seen, detectionEvent.Path, detectionEvent, caseId, suspicious, tags, signatureStatus);
            if (!string.IsNullOrWhiteSpace(detectionEvent.ProcessName))
            {
                AddObservation(observations, seen, "file_name", detectionEvent.ProcessName, detectionEvent, caseId, suspicious, tags, signatureStatus);
            }

            foreach (KeyValuePair<string, string> detail in detectionEvent.Details)
            {
                string key = detail.Key ?? string.Empty;
                string value = detail.Value ?? string.Empty;
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                foreach (Match match in Sha256Regex.Matches(value))
                {
                    AddObservation(observations, seen, "sha256", match.Value, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }

                if (ContainsAny(key, "path", "file", "image", "module", "evidence_copy", "cluster_paths", "driver_path", "mapped_path", "executable_path"))
                {
                    AddPathObservations(observations, seen, value, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }

                if (ContainsAny(key, "signature_subject", "signer"))
                {
                    AddDelimitedValues(observations, seen, "signer_subject", value, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }

                if (key.IndexOf("thumbprint", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddDelimitedValues(observations, seen, "certificate_thumbprint", value, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }

                if (key.Equals("service_name", StringComparison.OrdinalIgnoreCase) ||
                    key.IndexOf("service", StringComparison.OrdinalIgnoreCase) >= 0 && !key.EndsWith("path", StringComparison.OrdinalIgnoreCase))
                {
                    AddDelimitedValues(observations, seen, "service_name", value, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }

                if (ContainsAny(key, "object_name", "device_name", "device") ||
                    value.IndexOf("\\Device\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    value.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase))
                {
                    AddObjectObservations(observations, seen, "device_name", value, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }

                if (ContainsAny(key, "section", "shared_memory", "sharedsection") ||
                    value.IndexOf("BaseNamedObjects", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddObjectObservations(observations, seen, "section_name", value, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }

                if (ContainsAny(key, "registry", "targetobject", "key_name") || LooksLikeRegistryKey(value))
                {
                    AddDelimitedValues(observations, seen, "registry_key", value, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }

                if (ContainsAny(key, "command_line", "commandline"))
                {
                    AddObservation(observations, seen, "command_pattern", value, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }

                if (key.Equals("behavior_profiles", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (string profile in SplitList(value))
                    {
                        string name = profile;
                        int colon = name.IndexOf(':');
                        if (colon > 0)
                        {
                            name = name.Substring(0, colon);
                        }

                        AddObservation(observations, seen, "detection_profile", name, detectionEvent, caseId, suspicious, tags, signatureStatus);
                    }
                }

                if (key.Equals("behavior_tags", StringComparison.OrdinalIgnoreCase))
                {
                    foreach (string tag in SplitList(value))
                    {
                        AddObservation(observations, seen, "detection_profile", tag, detectionEvent, caseId, suspicious, tags, signatureStatus);
                    }
                }

                if (key.IndexOf("fingerprint_sha256", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddDelimitedValues(observations, seen, "case_fingerprint", value, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }
            }

            return observations;
        }

        private void AddPathObservations(
            List<ReputationObservation> observations,
            HashSet<string> seen,
            string value,
            DetectionEvent detectionEvent,
            string caseId,
            bool suspicious,
            HashSet<string> tags,
            string signatureStatus)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            foreach (string token in SplitPathList(value))
            {
                if (!LooksLikePath(token))
                {
                    continue;
                }

                AddObservation(observations, seen, "file_path", token, detectionEvent, caseId, suspicious, tags, signatureStatus);
                string fileName = SafeFileName(token);
                if (!string.IsNullOrWhiteSpace(fileName))
                {
                    AddObservation(observations, seen, "file_name", fileName, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }
            }
        }

        private void AddDelimitedValues(
            List<ReputationObservation> observations,
            HashSet<string> seen,
            string artifactType,
            string value,
            DetectionEvent detectionEvent,
            string caseId,
            bool suspicious,
            HashSet<string> tags,
            string signatureStatus)
        {
            foreach (string token in SplitList(value))
            {
                AddObservation(observations, seen, artifactType, token, detectionEvent, caseId, suspicious, tags, signatureStatus);
            }
        }

        private void AddObjectObservations(
            List<ReputationObservation> observations,
            HashSet<string> seen,
            string artifactType,
            string value,
            DetectionEvent detectionEvent,
            string caseId,
            bool suspicious,
            HashSet<string> tags,
            string signatureStatus)
        {
            foreach (string token in SplitList(value))
            {
                if (token.IndexOf("\\Device\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    token.IndexOf("BaseNamedObjects", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    token.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) ||
                    token.StartsWith(@"\Sessions\", StringComparison.OrdinalIgnoreCase) ||
                    token.StartsWith(@"\BaseNamedObjects\", StringComparison.OrdinalIgnoreCase))
                {
                    AddObservation(observations, seen, artifactType, token, detectionEvent, caseId, suspicious, tags, signatureStatus);
                }
            }
        }

        private void AddObservation(
            List<ReputationObservation> observations,
            HashSet<string> seen,
            string artifactType,
            string value,
            DetectionEvent detectionEvent,
            string caseId,
            bool suspicious,
            HashSet<string> tags,
            string signatureStatus)
        {
            string normalizedType = ReputationStore.NormalizeArtifactType(artifactType);
            string normalizedValue = ReputationStore.NormalizeArtifactValue(normalizedType, value);
            if (string.IsNullOrWhiteSpace(normalizedValue))
            {
                return;
            }

            string key = ReputationStore.BuildKey(normalizedType, normalizedValue);
            if (!seen.Add(key))
            {
                return;
            }

            ReputationObservation observation = new ReputationObservation
            {
                ArtifactType = normalizedType,
                Value = value,
                CaseId = caseId,
                SourceCategory = detectionEvent.Category,
                SourceAction = detectionEvent.Action,
                SourceDescription = detectionEvent.Description,
                SignatureStatus = signatureStatus,
                Severity = detectionEvent.Severity,
                Suspicious = suspicious,
                TimestampUtc = detectionEvent.TimestampUtc
            };

            foreach (string tag in tags)
            {
                observation.Tags.Add(tag);
            }

            observation.Tags.Add("source:" + detectionEvent.Category);
            observation.Tags.Add("action:" + detectionEvent.Action);
            observations.Add(observation);
        }

        private void EmitReputationSignals(DetectionEvent sourceEvent, List<ReputationAssessment> assessments)
        {
            if (assessments == null || assessments.Count == 0)
            {
                return;
            }

            List<ReputationAssessment> confirmed = assessments
                .Where(a => a.IsConfirmedBad)
                .OrderByDescending(a => a.Record.ConfirmedSeenCount)
                .Take(8)
                .ToList();

            if (confirmed.Count > 0)
            {
                EmitAssessmentEvent(
                    "ConfirmedArtifactObserved",
                    sourceEvent.Severity >= EventSeverity.High ? EventSeverity.Critical : EventSeverity.High,
                    "Locally confirmed suspicious artifact appeared in telemetry.",
                    "confirmed_bad_artifact_seen",
                    "raise",
                    "0.95",
                    sourceEvent,
                    confirmed);
            }

            List<ReputationAssessment> repeated = assessments
                .Where(a => !a.IsConfirmedBad && a.IsRepeatedSuspicious)
                .OrderByDescending(a => a.Record.SuspiciousSeenCount)
                .ThenByDescending(a => a.Record.SeenCount)
                .Take(8)
                .ToList();

            if (repeated.Count > 0)
            {
                EmitAssessmentEvent(
                    "RepeatedSuspiciousArtifactLinked",
                    sourceEvent.Severity >= EventSeverity.High ? EventSeverity.High : EventSeverity.Medium,
                    "Artifact reputation linked this event to previous suspicious evidence.",
                    "repeat_artifact_or_case_link",
                    "raise",
                    "0.75",
                    sourceEvent,
                    repeated);
            }

            List<ReputationAssessment> knownGood = assessments
                .Where(a => a.IsKnownGood)
                .OrderByDescending(a => a.Record.SeenCount)
                .Take(8)
                .ToList();

            if (knownGood.Count > 0 && ShouldRecommendNoiseReduction(sourceEvent))
            {
                EmitAssessmentEvent(
                    "KnownGoodNoiseReductionCandidate",
                    EventSeverity.Low,
                    "Known-good reputation matched artifacts in this event; original telemetry remains preserved.",
                    "known_good_artifact_seen",
                    "lower",
                    "0.35",
                    sourceEvent,
                    knownGood);
            }
        }

        private void EmitAssessmentEvent(
            string action,
            EventSeverity severity,
            string description,
            string reason,
            string recommendedAdjustment,
            string confidenceScore,
            DetectionEvent sourceEvent,
            List<ReputationAssessment> assessments)
        {
            string caseId = ExtractCaseId(sourceEvent);
            string reportKey = action + "|" + caseId + "|" + string.Join("|", assessments.Select(a => a.Record.Key).OrderBy(k => k).ToArray());
            if (!string.IsNullOrWhiteSpace(caseId))
            {
                lock (_reportedSignals)
                {
                    if (!_reportedSignals.Add(reportKey))
                    {
                        return;
                    }
                }
            }

            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "case_id", caseId ?? string.Empty },
                { "source_event_category", sourceEvent.Category ?? string.Empty },
                { "source_event_action", sourceEvent.Action ?? string.Empty },
                { "source_event_severity", sourceEvent.Severity.ToString() },
                { "source_event_description", Trim(sourceEvent.Description, 240) },
                { "reputation_reason", reason },
                { "recommended_severity_adjustment", recommendedAdjustment },
                { "confidence_score", confidenceScore },
                { "artifact_count", assessments.Count.ToString(CultureInfo.InvariantCulture) },
                { "matched_artifacts", FormatAssessments(assessments) },
                { "previous_case_links", FormatLinks(assessments) },
                { "related_case_ids", FormatCaseIds(assessments) },
                { "confidence_boost_reasons", FormatReasons(assessments) },
                { "reputation_store_path", _store.StorePath },
                { "safety_rule", "Reputation output is advisory evidence only; no events are suppressed or altered." }
            };

            _logger.Log(DetectionEvent.Create(
                "Reputation",
                action,
                severity,
                description,
                sourceEvent.Path,
                null,
                details));
        }

        private static string FormatAssessments(IEnumerable<ReputationAssessment> assessments)
        {
            return string.Join("; ", assessments.Select(a =>
                a.Record.ArtifactType + "=" + Trim(a.Record.Value, 120) +
                " [" + ReputationStore.FormatCategory(a.Record.Category) +
                ", seen=" + a.Record.SeenCount.ToString(CultureInfo.InvariantCulture) +
                ", suspicious=" + a.Record.SuspiciousSeenCount.ToString(CultureInfo.InvariantCulture) + "]").ToArray());
        }

        private static string FormatLinks(IEnumerable<ReputationAssessment> assessments)
        {
            return string.Join("; ", assessments
                .Select(a => a.LinkText)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray());
        }

        private static string FormatCaseIds(IEnumerable<ReputationAssessment> assessments)
        {
            return string.Join(";", assessments
                .SelectMany(a => a.PreviousCaseIds ?? new List<string>())
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(20)
                .ToArray());
        }

        private static string FormatReasons(IEnumerable<ReputationAssessment> assessments)
        {
            return string.Join("; ", assessments
                .Select(a => a.ConfidenceBoostReason)
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray());
        }

        private bool ShouldRecommendNoiseReduction(DetectionEvent detectionEvent)
        {
            if (detectionEvent.Severity < EventSeverity.Medium)
            {
                return false;
            }

            string text = EventText(detectionEvent);
            if (ContainsAny(text,
                "tamper",
                "terminate",
                "suspend",
                "debug",
                "inject",
                "patch",
                "vm_write",
                "vm_operation",
                "private executable",
                "hidden kernel",
                "unknown device",
                "unsigned",
                "cleared",
                "disabled",
                "defender exclusion",
                "code integrity policy"))
            {
                return false;
            }

            return true;
        }

        private static bool IsSuspiciousEvent(DetectionEvent detectionEvent)
        {
            if (detectionEvent.Severity >= EventSeverity.High)
            {
                return true;
            }

            if (HasCaseId(detectionEvent) && detectionEvent.Severity >= EventSeverity.Medium)
            {
                return true;
            }

            if (IsSuspiciousCategory(detectionEvent.Category) && detectionEvent.Severity >= EventSeverity.Medium)
            {
                return true;
            }

            string text = EventText(detectionEvent);
            return ContainsAny(text,
                "manual_map",
                "hidden_driver",
                "vulnerable_driver",
                "unsigned_game_access",
                "suspicious_device_channel",
                "memory_injection",
                "transient_loader",
                "telemetry_tamper",
                "private executable",
                "rwx",
                "vm_write",
                "unknown device",
                "confirmed");
        }

        private static bool IsSuspiciousCategory(string category)
        {
            return ContainsAny(category,
                "HiddenKernel",
                "TargetInteraction",
                "KernelCommunication",
                "ActiveCapture",
                "DefensiveIntegrity",
                "BehaviorProfile",
                "HardwareIdentity");
        }

        private static bool HasCaseId(DetectionEvent detectionEvent)
        {
            return !string.IsNullOrWhiteSpace(ExtractCaseId(detectionEvent));
        }

        private static string ExtractCaseId(DetectionEvent detectionEvent)
        {
            return FirstDetail(
                detectionEvent,
                "case_id",
                "behavior_case_id",
                "capture_id",
                "active_capture_id",
                "upstream_case_id",
                "target_case_id");
        }

        private static HashSet<string> ExtractTags(DetectionEvent detectionEvent)
        {
            HashSet<string> tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string key in new[] { "behavior_tags", "behavior_profiles", "reputation_category", "profile_name", "trigger_reason" })
            {
                string value = FirstDetail(detectionEvent, key);
                foreach (string part in SplitList(value))
                {
                    string tag = part;
                    int colon = tag.IndexOf(':');
                    if (colon > 0)
                    {
                        tag = tag.Substring(0, colon);
                    }

                    if (!string.IsNullOrWhiteSpace(tag))
                    {
                        tags.Add(tag.Trim());
                    }
                }
            }

            return tags;
        }

        private static bool TryParseManualMark(
            string mark,
            out string caseId,
            out string artifactType,
            out ReputationCategory category,
            out string value,
            out string note)
        {
            caseId = null;
            artifactType = null;
            category = ReputationCategory.Unknown;
            value = null;
            note = null;

            if (string.IsNullOrWhiteSpace(mark))
            {
                return false;
            }

            string[] parts = mark.Split(new[] { '|' }, 5, StringSplitOptions.None)
                .Select(p => p.Trim())
                .ToArray();

            if (parts.Length == 5)
            {
                caseId = parts[0];
                artifactType = parts[1];
                if (!ReputationStore.TryParseCategory(parts[2], out category))
                {
                    return false;
                }

                value = parts[3];
                note = parts[4];
                return !string.IsNullOrWhiteSpace(artifactType) && !string.IsNullOrWhiteSpace(value);
            }

            if (parts.Length >= 3)
            {
                artifactType = parts[0];
                if (!ReputationStore.TryParseCategory(parts[1], out category))
                {
                    return false;
                }

                value = parts[2];
                note = parts.Length >= 4 ? parts[3] : string.Empty;
                return !string.IsNullOrWhiteSpace(artifactType) && !string.IsNullOrWhiteSpace(value);
            }

            return false;
        }

        private static string FirstDetail(DetectionEvent detectionEvent, params string[] keys)
        {
            if (detectionEvent == null || detectionEvent.Details == null || keys == null)
            {
                return string.Empty;
            }

            foreach (string key in keys)
            {
                string value;
                if (detectionEvent.Details.TryGetValue(key, out value) && !string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return string.Empty;
        }

        private static bool HasAnyDetailKey(DetectionEvent detectionEvent, params string[] keys)
        {
            if (detectionEvent == null || detectionEvent.Details == null)
            {
                return false;
            }

            foreach (string key in detectionEvent.Details.Keys)
            {
                foreach (string term in keys)
                {
                    if (key.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static IEnumerable<string> SplitList(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                yield break;
            }

            foreach (string part in value.Split(new[] { ';', '|', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string trimmed = part.Trim().Trim('"');
                if (!string.IsNullOrWhiteSpace(trimmed))
                {
                    yield return trimmed;
                }
            }
        }

        private static IEnumerable<string> SplitPathList(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                yield break;
            }

            foreach (string part in value.Split(new[] { ';', '|', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string trimmed = part.Trim().Trim('"');
                if (!string.IsNullOrWhiteSpace(trimmed))
                {
                    yield return trimmed;
                }
            }
        }

        private static bool LooksLikePath(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            string trimmed = value.Trim();
            if (trimmed.IndexOf(":\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                trimmed.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            string extension = Path.GetExtension(trimmed);
            return !string.IsNullOrWhiteSpace(extension) &&
                   ContainsAny(extension, ".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".drv", ".ocx");
        }

        private static bool LooksLikeRegistryKey(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            return value.StartsWith("HKLM\\", StringComparison.OrdinalIgnoreCase) ||
                   value.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase) ||
                   value.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase) ||
                   value.StartsWith(@"\REGISTRY\", StringComparison.OrdinalIgnoreCase);
        }

        private static string SafeFileName(string path)
        {
            try
            {
                return Path.GetFileName(path);
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string EventText(DetectionEvent detectionEvent)
        {
            if (detectionEvent == null)
            {
                return string.Empty;
            }

            string detailText = detectionEvent.Details == null
                ? string.Empty
                : string.Join(" ", detectionEvent.Details.Select(p => p.Key + " " + p.Value).ToArray());
            return ((detectionEvent.Category ?? string.Empty) + " " +
                    (detectionEvent.Action ?? string.Empty) + " " +
                    (detectionEvent.Description ?? string.Empty) + " " +
                    (detectionEvent.Path ?? string.Empty) + " " +
                    detailText).ToLowerInvariant();
        }

        private static bool ContainsAny(string value, params string[] terms)
        {
            if (string.IsNullOrWhiteSpace(value) || terms == null)
            {
                return false;
            }

            foreach (string term in terms)
            {
                if (!string.IsNullOrWhiteSpace(term) &&
                    value.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string Trim(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            {
                return value ?? string.Empty;
            }

            return value.Substring(0, Math.Max(0, maxLength - 3)) + "...";
        }

        public void Dispose()
        {
            _disposed = true;
            if (_store != null)
            {
                _store.Flush();
            }

            _logger.EventLogged -= OnEventLogged;
        }
    }
}
