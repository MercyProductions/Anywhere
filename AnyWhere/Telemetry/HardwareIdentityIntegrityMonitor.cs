using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal sealed class HardwareIdentityIntegrityMonitor : IDetectionMonitor
    {
        private static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(15);
        private static readonly TimeSpan PreLaunchWindow = TimeSpan.FromMinutes(15);
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly HardwareIdentityCollector _collector;
        private readonly HardwareIdentityBaselineStore _baselineStore;
        private readonly HardwareIdentityBaselineStore _lastSeenStore;
        private readonly ConcurrentQueue<RelatedActivity> _recentActivity = new ConcurrentQueue<RelatedActivity>();
        private readonly Dictionary<int, LaunchIdentitySession> _launchSessions = new Dictionary<int, LaunchIdentitySession>();
        private readonly HashSet<int> _activeProtectedProcesses = new HashSet<int>();
        private readonly HashSet<string> _reportedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly ManualResetEventSlim _stopSignal = new ManualResetEventSlim(false);
        private readonly object _captureLock = new object();
        private readonly object _sessionLock = new object();
        private readonly string _root;
        private readonly string _snapshotRoot;
        private readonly string _reportRoot;
        private readonly string _sessionRoot;
        private Dictionary<string, string> _bootSnapshotValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private string _bootSnapshotPath;
        private Thread _thread;
        private bool _disposed;

        public HardwareIdentityIntegrityMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _collector = new HardwareIdentityCollector(logger);
            _root = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Hardware Identity Integrity");
            _snapshotRoot = Path.Combine(_root, "Snapshots");
            _reportRoot = Path.Combine(_root, "Reports");
            _sessionRoot = Path.Combine(_root, "Launch Sessions");
            _baselineStore = new HardwareIdentityBaselineStore(Path.Combine(_root, "hwid-integrity-first-seen.tsv"));
            _lastSeenStore = new HardwareIdentityBaselineStore(Path.Combine(_root, "hwid-integrity-last-seen.tsv"));
        }

        public string Name
        {
            get { return "Hardware Identity Integrity"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_root);
            Directory.CreateDirectory(_snapshotRoot);
            Directory.CreateDirectory(_reportRoot);
            Directory.CreateDirectory(_sessionRoot);
            _logger.EventLogged += OnEventLogged;

            if (_options.HardwareIdentityIntegrityEnabled)
            {
                CaptureEvaluateAndReport("BootOrMonitorStart");
                _thread = new Thread(ThreadMain)
                {
                    IsBackground = true,
                    Name = "Aegis HWID Integrity Monitor"
                };
                _thread.Start();
            }

            _logger.Log(DetectionEvent.Create(
                "HardwareIdentityIntegrity",
                _options.HardwareIdentityIntegrityEnabled ? "Started" : "Disabled",
                EventSeverity.Low,
                _options.HardwareIdentityIntegrityEnabled
                    ? "Hardware identity integrity and HWID spoofing behavior monitor started."
                    : "Hardware identity integrity monitor is disabled by configuration.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "scan_interval_seconds", _options.HardwareIdentityIntegrityScanInterval.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) },
                    { "first_seen_baseline_path", Path.Combine(_root, "hwid-integrity-first-seen.tsv") },
                    { "last_seen_path", Path.Combine(_root, "hwid-integrity-last-seen.tsv") },
                    { "snapshot_root", _snapshotRoot },
                    { "report_root", _reportRoot },
                    { "launch_session_root", _sessionRoot },
                    { "pre_launch_lookback_minutes", PreLaunchWindow.TotalMinutes.ToString("0", CultureInfo.InvariantCulture) },
                    { "protected_processes", string.Join(";", _options.ProtectedProcessNames.ToArray()) },
                    { "safety_rule", "Evidence-only HWID integrity monitoring; no spoofing, bypass, patching, or interference behavior." }
                }));
        }

        private void ThreadMain()
        {
            while (!_stopSignal.Wait(_options.HardwareIdentityIntegrityScanInterval))
            {
                CaptureEvaluateAndReport(HasActiveProtectedProcess() ? "DuringProtectedGameRuntime" : "PeriodicIntegrity");
            }
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed || detectionEvent == null || detectionEvent.Category.StartsWith("HardwareIdentityIntegrity", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (IsCorrelationActivity(detectionEvent))
            {
                RememberActivity(detectionEvent);
            }

            if (LooksLikeHardwareIdentityApiProbe(detectionEvent))
            {
                EmitHardwareApiProbe(detectionEvent);
            }

            if (IsHardwareRegistryChange(detectionEvent))
            {
                QueueCapture("HardwareRegistryChange");
            }

            if (IsProtectedProcessEvent(detectionEvent))
            {
                if (IsProcessStartEvent(detectionEvent) && detectionEvent.ProcessId.HasValue)
                {
                    LaunchIdentitySession session = CreateLaunchSession(detectionEvent);
                    lock (_activeProtectedProcesses)
                    {
                        _activeProtectedProcesses.Add(detectionEvent.ProcessId.Value);
                    }

                    lock (_sessionLock)
                    {
                        _launchSessions[detectionEvent.ProcessId.Value] = session;
                    }

                    QueueLaunchSessionStart(session);
                    QueueCapture("ProtectedGameLaunchBoundary");
                }
                else if (IsProcessExitEvent(detectionEvent) && detectionEvent.ProcessId.HasValue)
                {
                    LaunchIdentitySession session = null;
                    lock (_activeProtectedProcesses)
                    {
                        _activeProtectedProcesses.Remove(detectionEvent.ProcessId.Value);
                    }

                    lock (_sessionLock)
                    {
                        if (_launchSessions.TryGetValue(detectionEvent.ProcessId.Value, out session))
                        {
                            _launchSessions.Remove(detectionEvent.ProcessId.Value);
                            session.ExitTimeUtc = detectionEvent.TimestampUtc;
                            session.ExitProcessEvent = detectionEvent.Description;
                        }
                    }

                    if (session != null)
                    {
                        QueueLaunchSessionExit(session);
                    }

                    QueueCapture("AfterProtectedGameExit");
                }
            }
        }

        private void QueueCapture(string stage)
        {
            if (!_options.HardwareIdentityIntegrityEnabled)
            {
                return;
            }

            ThreadPool.QueueUserWorkItem(delegate
            {
                Thread.Sleep(750);
                CaptureEvaluateAndReport(stage);
            });
        }

        private void QueueLaunchSessionStart(LaunchIdentitySession session)
        {
            if (session == null || !_options.HardwareIdentityIntegrityEnabled)
            {
                return;
            }

            ThreadPool.QueueUserWorkItem(delegate
            {
                Thread.Sleep(150);
                CaptureLaunchSessionStart(session);
            });
        }

        private void QueueLaunchSessionExit(LaunchIdentitySession session)
        {
            if (session == null || !_options.HardwareIdentityIntegrityEnabled)
            {
                return;
            }

            ThreadPool.QueueUserWorkItem(delegate
            {
                Thread.Sleep(1000);
                CaptureLaunchSessionExit(session);
            });
        }

        private LaunchIdentitySession CreateLaunchSession(DetectionEvent detectionEvent)
        {
            string processName = FirstNonEmpty(detectionEvent.ProcessName, Detail(detectionEvent, "process_name"), Path.GetFileName(detectionEvent.Path));
            LaunchIdentitySession session = new LaunchIdentitySession
            {
                CaseId = "HWID-LAUNCH-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" +
                         ReputationStore.HashText((processName ?? string.Empty) + "|" + detectionEvent.ProcessId + "|" + detectionEvent.TimestampUtc.ToString("o", CultureInfo.InvariantCulture)).Substring(0, 8).ToUpperInvariant(),
                ProcessId = detectionEvent.ProcessId ?? 0,
                ProcessName = processName,
                ProcessPath = FirstNonEmpty(detectionEvent.Path, Detail(detectionEvent, "executable_path")),
                CommandLine = Detail(detectionEvent, "command_line"),
                LaunchTimeUtc = detectionEvent.TimestampUtc,
                LaunchProcessEvent = detectionEvent.Description
            };

            Directory.CreateDirectory(GetSessionFolder(session));
            return session;
        }

        private void CaptureLaunchSessionStart(LaunchIdentitySession session)
        {
            if (_disposed || session == null)
            {
                return;
            }

            lock (_captureLock)
            {
                HardwareIdentitySnapshot snapshot = _collector.Capture("PreLaunchIdentityAudit");
                List<IdentityValue> values = FlattenSnapshot(snapshot);
                Dictionary<string, string> current = ValuesToDictionary(values);
                Dictionary<string, string> baseline = _baselineStore.Load();
                Dictionary<string, string> lastBoot = CloneDictionary(_bootSnapshotValues);
                Dictionary<string, string> previous = _lastSeenStore.Load();
                List<RelatedActivity> preLaunch = RecentActivities(session.LaunchTimeUtc.Subtract(PreLaunchWindow), session.LaunchTimeUtc);

                string snapshotPath = WriteSnapshot(snapshot, values, current, "PreLaunchIdentityAudit-" + session.CaseId);
                session.LaunchSnapshotPath = snapshotPath;
                session.LaunchValues = current;
                session.BaselineDiffs = BuildDictionaryDiffs(baseline, current, "launch_vs_locked_baseline");
                session.LastBootDiffs = BuildDictionaryDiffs(lastBoot, current, "launch_vs_last_boot_snapshot");
                session.PreLaunchActivities = preLaunch;
                session.LastRuntimeValues = current;
                session.LastRuntimeSnapshotPath = snapshotPath;

                List<HwidIntegrityFinding> findings = Evaluate(snapshot, values, current, baseline, previous, baseline.Count > 0, previous.Count > 0, preLaunch, true);
                List<HwidSpooferProfile> profiles = BuildSpooferProfiles(findings, current, baseline, previous, preLaunch, true, "PreLaunchIdentityAudit");
                foreach (HwidSpooferProfile profile in profiles)
                {
                    session.ObservedProfiles.Add(profile.ProfileName);
                }

                string reportPath = WriteLaunchSessionReport(session, "pre_launch", current, baseline, previous, preLaunch, profiles);
                EmitLaunchSessionEvent(
                    "PreLaunchIdentityAudit",
                    ScoreLaunchSession(session).Severity,
                    "Pre-launch identity audit captured for protected process " + session.ProcessName + ".",
                    session,
                    reportPath,
                    new Dictionary<string, string>
                    {
                        { "pre_launch_diff", FormatProfileDiff(session.BaselineDiffs) },
                        { "last_boot_diff", FormatProfileDiff(session.LastBootDiffs) },
                        { "pre_launch_activity", FormatRelatedActivity(preLaunch) },
                        { "suspected_spoofer_profile", InferSessionProfile(session, profiles) },
                        { "confidence_score", ScoreLaunchSession(session).Score.ToString("0.00", CultureInfo.InvariantCulture) }
                    });
            }
        }

        private void CaptureLaunchSessionExit(LaunchIdentitySession session)
        {
            if (_disposed || session == null)
            {
                return;
            }

            lock (_captureLock)
            {
                HardwareIdentitySnapshot snapshot = _collector.Capture("PostLaunchIdentityAudit");
                List<IdentityValue> values = FlattenSnapshot(snapshot);
                Dictionary<string, string> current = ValuesToDictionary(values);
                Dictionary<string, string> baseline = _baselineStore.Load();
                Dictionary<string, string> previous = _lastSeenStore.Load();
                List<RelatedActivity> sessionActivities = RecentActivities(session.LaunchTimeUtc.Subtract(PreLaunchWindow), DateTimeOffset.UtcNow);

                string snapshotPath = WriteSnapshot(snapshot, values, current, "PostLaunchIdentityAudit-" + session.CaseId);
                session.ExitSnapshotPath = snapshotPath;
                session.ExitValues = current;
                session.PostLaunchDiffs = BuildDictionaryDiffs(session.LaunchValues, current, "post_vs_launch");
                session.PostBaselineDiffs = BuildDictionaryDiffs(baseline, current, "post_vs_locked_baseline");
                session.SessionActivities = sessionActivities;

                DetectSessionReverts(session, baseline, current);

                List<HwidIntegrityFinding> findings = Evaluate(snapshot, values, current, baseline, previous, baseline.Count > 0, previous.Count > 0, sessionActivities, false);
                List<HwidSpooferProfile> profiles = BuildSpooferProfiles(findings, current, baseline, previous, sessionActivities, false, "PostLaunchIdentityAudit");
                session.CleanupTraces = BuildLaunchSessionCleanupTraces(session, findings, sessionActivities);
                foreach (HwidSpooferProfile profile in profiles)
                {
                    session.ObservedProfiles.Add(profile.ProfileName);
                }

                SpoofSessionScore score = ScoreLaunchSession(session);
                string reportPath = WriteLaunchSessionReport(session, "post_launch", current, baseline, previous, sessionActivities, profiles);
                EmitLaunchSessionEvent(
                    "LaunchSessionIdentityAuditComplete",
                    score.Severity,
                    "Protected launch-session identity audit completed for " + session.ProcessName + ".",
                    session,
                    reportPath,
                    new Dictionary<string, string>
                    {
                        { "pre_launch_diff", FormatProfileDiff(session.BaselineDiffs) },
                        { "runtime_diff", FormatProfileDiff(session.RuntimeDiffs) },
                        { "post_launch_diff", FormatProfileDiff(session.PostLaunchDiffs) },
                        { "reverted_identifiers", FormatProfileDiff(session.RevertedDiffs) },
                        { "cleanup_phase", FormatCleanupTraces(session.CleanupTraces) },
                        { "session_timeline", FormatSessionTimeline(session) },
                        { "related_artifacts", FormatRelatedArtifacts(session, profiles) },
                        { "confidence_score", score.Score.ToString("0.00", CultureInfo.InvariantCulture) },
                        { "score_reasons", string.Join(";", score.Reasons.OrderBy(v => v).ToArray()) },
                        { "suspected_spoofer_profile", InferSessionProfile(session, profiles) }
                    });

                EmitCleanupTraceEvents(session.CleanupTraces, reportPath, session.CaseId);
            }
        }

        private void CaptureEvaluateAndReport(string stage)
        {
            if (_disposed || !_options.HardwareIdentityIntegrityEnabled)
            {
                return;
            }

            lock (_captureLock)
            {
                HardwareIdentitySnapshot snapshot = _collector.Capture(stage);
                List<IdentityValue> values = FlattenSnapshot(snapshot);
                Dictionary<string, string> current = ValuesToDictionary(values);
                bool hadBaseline = _baselineStore.Exists;
                bool hadLast = _lastSeenStore.Exists;
                Dictionary<string, string> baseline = _baselineStore.Load();
                Dictionary<string, string> previous = _lastSeenStore.Load();

                if (!hadBaseline)
                {
                    _baselineStore.Save(current);
                    baseline = new Dictionary<string, string>(current, StringComparer.OrdinalIgnoreCase);
                }

                List<RelatedActivity> related = RecentActivities(CorrelationWindow);
                bool protectedRuntime = HasActiveProtectedProcess();
                List<HwidIntegrityFinding> findings = Evaluate(snapshot, values, current, baseline, previous, hadBaseline, hadLast, related, protectedRuntime);
                List<HwidSpooferProfile> profiles = BuildSpooferProfiles(findings, current, baseline, previous, related, protectedRuntime, stage);
                List<HardwareChangeAttribution> attributions = BuildAttributions(findings, related, stage);
                List<SpooferCleanupTrace> cleanupTraces = BuildSnapshotCleanupTraces(findings, related, stage, protectedRuntime);

                string snapshotPath = WriteSnapshot(snapshot, values, current, stage);
                string reportPath = WriteReport(snapshot, findings, profiles, attributions, cleanupTraces, current, baseline, previous, hadBaseline, hadLast, related, snapshotPath);
                if (stage.Equals("BootOrMonitorStart", StringComparison.OrdinalIgnoreCase))
                {
                    _bootSnapshotValues = CloneDictionary(current);
                    _bootSnapshotPath = snapshotPath;
                }

                if (protectedRuntime)
                {
                    UpdateRuntimeLaunchSessions(stage, snapshotPath, current, baseline, related, profiles);
                }

                foreach (HwidIntegrityFinding finding in findings)
                {
                    if (!ShouldEmitFinding(finding))
                    {
                        continue;
                    }

                    Dictionary<string, string> details = new Dictionary<string, string>(finding.Details, StringComparer.OrdinalIgnoreCase)
                    {
                        { "case_id", finding.CaseId ?? string.Empty },
                        { "identifier_type", finding.IdentifierType ?? string.Empty },
                        { "identity_key", finding.IdentityKey ?? string.Empty },
                        { "source", finding.Source ?? string.Empty },
                        { "entity", finding.Entity ?? string.Empty },
                        { "baseline_value", finding.BaselineValue ?? string.Empty },
                        { "previous_value", finding.PreviousValue ?? string.Empty },
                        { "current_value", finding.CurrentValue ?? string.Empty },
                        { "stage", stage },
                        { "protected_runtime_active", protectedRuntime.ToString() },
                        { "confidence_score", finding.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) },
                        { "correlation_tags", string.Join(";", finding.CorrelationTags.OrderBy(t => t).ToArray()) },
                        { "related_activity", FormatRelatedActivity(finding.RelatedActivities) },
                        { "snapshot_path", snapshotPath },
                        { "evidence_report", reportPath },
                        { "safety_rule", "Evidence-only finding; no hardware identity manipulation performed." }
                    };

                    _logger.Log(DetectionEvent.Create(
                        "HardwareIdentityIntegrity",
                        finding.Action,
                        finding.Severity,
                        finding.Description,
                        reportPath,
                        null,
                        details));
                }

                _logger.Log(DetectionEvent.Create(
                    "HardwareIdentityIntegrity",
                    "SnapshotComplete",
                    findings.Count > 0 ? EventSeverity.Medium : EventSeverity.Low,
                    "Hardware identity integrity snapshot complete for stage " + stage + ".",
                    reportPath,
                    null,
                    new Dictionary<string, string>
                    {
                        { "stage", stage },
                        { "finding_count", findings.Count.ToString(CultureInfo.InvariantCulture) },
                        { "profile_count", profiles.Count.ToString(CultureInfo.InvariantCulture) },
                        { "attribution_count", attributions.Count.ToString(CultureInfo.InvariantCulture) },
                        { "cleanup_trace_count", cleanupTraces.Count.ToString(CultureInfo.InvariantCulture) },
                        { "first_seen_baseline_existed", hadBaseline.ToString() },
                        { "last_seen_existed", hadLast.ToString() },
                        { "protected_runtime_active", protectedRuntime.ToString() },
                        { "active_launch_session_count", ActiveLaunchSessionCount().ToString(CultureInfo.InvariantCulture) },
                        { "identity_value_count", current.Count.ToString(CultureInfo.InvariantCulture) },
                        { "related_activity_count", related.Count.ToString(CultureInfo.InvariantCulture) },
                        { "snapshot_path", snapshotPath },
                        { "report_path", reportPath }
                    }));

                EmitCleanupTraceEvents(cleanupTraces, reportPath, null);

                foreach (HardwareChangeAttribution attribution in attributions)
                {
                    if (!ShouldEmitAttribution(attribution))
                    {
                        continue;
                    }

                    _logger.Log(DetectionEvent.Create(
                        "HardwareIdentityIntegrity",
                        "HardwareChangeAttributed",
                        SeverityForAttribution(attribution),
                        "Hardware identity change attributed to likely related activity: " + attribution.SuspectedCause + ".",
                        reportPath,
                        null,
                        new Dictionary<string, string>
                        {
                            { "case_id", attribution.CaseId ?? string.Empty },
                            { "changed_identifier", attribution.IdentityKey ?? string.Empty },
                            { "identifier_type", attribution.IdentifierType ?? string.Empty },
                            { "old_value", attribution.OldValue ?? string.Empty },
                            { "new_value", attribution.NewValue ?? string.Empty },
                            { "suspected_cause", attribution.SuspectedCause ?? string.Empty },
                            { "related_process", attribution.RelatedProcess ?? string.Empty },
                            { "related_driver_service", attribution.RelatedDriverService ?? string.Empty },
                            { "related_registry_key", attribution.RelatedRegistryKey ?? string.Empty },
                            { "related_device_event", attribution.RelatedDeviceEvent ?? string.Empty },
                            { "matched_signals", string.Join(";", attribution.MatchedSignals.OrderBy(v => v).ToArray()) },
                            { "evidence_timeline", string.Join(" || ", attribution.EvidenceTimeline.Take(20).ToArray()) },
                            { "stage", stage },
                            { "confidence_score", attribution.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) },
                            { "snapshot_path", snapshotPath },
                            { "evidence_report", reportPath },
                            { "safety_rule", "Hardware-change attribution is evidence-only and does not alter processes, drivers, services, registry, or devices." }
                        }));
                }

                foreach (HwidSpooferProfile profile in profiles)
                {
                    if (!ShouldEmitProfile(profile))
                    {
                        continue;
                    }

                    Dictionary<string, string> details = new Dictionary<string, string>
                    {
                        { "case_id", profile.CaseId ?? string.Empty },
                        { "profile_name", profile.ProfileName ?? string.Empty },
                        { "confidence_score", profile.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) },
                        { "matched_indicators", string.Join(";", profile.MatchedIndicators.OrderBy(v => v).ToArray()) },
                        { "before_after_identity_diff", FormatProfileDiff(profile.Diffs) },
                        { "related_processes_drivers_services", string.Join(";", profile.RelatedArtifacts.OrderBy(v => v).Take(40).ToArray()) },
                        { "evidence_timeline", string.Join(" || ", profile.EvidenceTimeline.Take(30).ToArray()) },
                        { "case_links", string.Join(";", profile.CaseLinks.OrderBy(v => v).ToArray()) },
                        { "stage", stage },
                        { "protected_runtime_active", protectedRuntime.ToString() },
                        { "snapshot_path", snapshotPath },
                        { "evidence_report", reportPath },
                        { "safety_rule", "Profile detection is classification-only; no spoofing, bypass, or interference behavior." }
                    };

                    _logger.Log(DetectionEvent.Create(
                        "HardwareIdentityIntegrity",
                        "HwidSpooferProfileMatched",
                        profile.Severity,
                        "HWID spoofer behavior profile matched: " + profile.ProfileName,
                        reportPath,
                        null,
                        details));
                }

                _lastSeenStore.Save(current);
            }
        }

        private List<HwidIntegrityFinding> Evaluate(
            HardwareIdentitySnapshot snapshot,
            List<IdentityValue> values,
            Dictionary<string, string> current,
            Dictionary<string, string> baseline,
            Dictionary<string, string> previous,
            bool hadBaseline,
            bool hadLast,
            List<RelatedActivity> related,
            bool protectedRuntime)
        {
            List<HwidIntegrityFinding> findings = new List<HwidIntegrityFinding>();
            EvaluateIdentifierQuality(values, findings);
            EvaluateDuplicateIdentifiers(values, findings);
            EvaluateVendorConsistency(snapshot, findings);
            EvaluateBaselineDiff(values, current, baseline, previous, hadBaseline, hadLast, related, protectedRuntime, findings);
            EvaluateDeviceStack(snapshot, current, baseline, previous, hadBaseline, hadLast, related, protectedRuntime, findings);
            EvaluateNetworkAnomalies(snapshot, current, baseline, previous, hadBaseline, hadLast, related, protectedRuntime, findings);
            EvaluateDiskVolumeAnomalies(snapshot, current, baseline, previous, hadBaseline, hadLast, related, protectedRuntime, findings);
            ApplyCorrelation(findings, related, protectedRuntime);
            return findings;
        }

        private static void EvaluateIdentifierQuality(IEnumerable<IdentityValue> values, ICollection<HwidIntegrityFinding> findings)
        {
            foreach (IdentityValue value in values)
            {
                if (!value.SessionSensitive)
                {
                    continue;
                }

                if (HardwareIdentityUtilities.IsBlankOrZero(value.Value))
                {
                    findings.Add(Finding(
                        "MalformedOrZeroedHardwareIdentifier",
                        EventSeverity.High,
                        "Hardware identity value is blank, generic, malformed, or zeroed.",
                        value,
                        null,
                        null,
                        value.Value,
                        0.82,
                        new Dictionary<string, string> { { "format_reason", "blank_or_zero_or_generic" } }));
                    continue;
                }

                if (value.IdentifierType == "smbios.uuid" && !LooksValidUuid(value.Value))
                {
                    findings.Add(Finding(
                        "MalformedSystemUuid",
                        EventSeverity.High,
                        "System UUID does not match a normal UUID format.",
                        value,
                        null,
                        null,
                        value.Value,
                        0.78,
                        new Dictionary<string, string> { { "format_reason", "invalid_uuid_format" } }));
                }

                if (value.IdentifierType.EndsWith(".serial", StringComparison.OrdinalIgnoreCase) &&
                    LooksRandomizedIdentifier(value.Value))
                {
                    findings.Add(Finding(
                        "RandomizedLookingHardwareIdentifier",
                        EventSeverity.Medium,
                        "Hardware serial has a randomized-looking format.",
                        value,
                        null,
                        null,
                        value.Value,
                        0.62,
                        new Dictionary<string, string> { { "format_reason", "high_entropy_serial_pattern" } }));
                }
            }
        }

        private static void EvaluateDuplicateIdentifiers(IEnumerable<IdentityValue> values, ICollection<HwidIntegrityFinding> findings)
        {
            foreach (IGrouping<string, IdentityValue> group in values
                .Where(v => v.SessionSensitive && !HardwareIdentityUtilities.IsBlankOrZero(v.Value))
                .GroupBy(v => v.IdentifierType + "|" + HardwareIdentityUtilities.NormalizeIdentifier(v.Value), StringComparer.OrdinalIgnoreCase))
            {
                List<IdentityValue> duplicates = group
                    .GroupBy(v => v.Entity ?? v.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.First())
                    .ToList();

                if (duplicates.Count < 2)
                {
                    continue;
                }

                IdentityValue first = duplicates[0];
                findings.Add(Finding(
                    "DuplicatedHardwareIdentifier",
                    EventSeverity.Medium,
                    "Same hardware identifier appears across multiple device records.",
                    first,
                    null,
                    null,
                    first.Value,
                    0.66,
                    new Dictionary<string, string>
                    {
                        { "duplicate_entities", string.Join(";", duplicates.Select(d => d.Entity).Where(e => !string.IsNullOrWhiteSpace(e)).Take(12).ToArray()) },
                        { "duplicate_count", duplicates.Count.ToString(CultureInfo.InvariantCulture) }
                    }));
            }
        }

        private static void EvaluateVendorConsistency(HardwareIdentitySnapshot snapshot, ICollection<HwidIntegrityFinding> findings)
        {
            foreach (SystemIdentityRecord system in snapshot.SystemIdentities)
            {
                string combined = HardwareIdentityUtilities.JoinNonEmpty(new[] { system.BiosVendor, system.BaseboardVendor, system.SystemVendor, system.SystemProduct }, " ");
                if (ContainsAny(combined, "vmware", "virtualbox", "qemu", "hyper-v", "parallels") && ContainsAny(combined, "asus", "msi", "gigabyte", "dell", "hp", "lenovo", "acer"))
                {
                    IdentityValue value = IdentityValue.From("system|" + system.Source + "|vendor_combo", "smbios.vendor_relationship", system.Source, system.SystemVendor, combined, true);
                    findings.Add(Finding(
                        "ImpossibleHardwareVendorCombination",
                        EventSeverity.High,
                        "System identity mixes virtualized and physical OEM manufacturer signals.",
                        value,
                        null,
                        null,
                        combined,
                        0.72,
                        SystemDetails(system)));
                }
            }

            foreach (GpuIdentityRecord gpu in snapshot.Gpus)
            {
                string combined = gpu.Name + " " + gpu.Vendor + " " + gpu.DriverPath;
                if (gpu.IsVirtual && ContainsAny(combined, "nvidia", "amd", "radeon", "geforce", "intel arc"))
                {
                    IdentityValue value = IdentityValue.From("gpu|" + gpu.Source + "|" + (gpu.PnpDeviceId ?? gpu.Name) + "|vendor", "gpu.vendor_relationship", gpu.Source, gpu.Name, combined, true);
                    findings.Add(Finding(
                        "SuspiciousVirtualGpuVendorMix",
                        EventSeverity.Medium,
                        "GPU/display identity mixes physical GPU vendor terms with a virtual display layer.",
                        value,
                        null,
                        null,
                        combined,
                        0.63,
                        GpuDetails(gpu)));
                }
            }
        }

        private static void EvaluateBaselineDiff(
            IEnumerable<IdentityValue> values,
            Dictionary<string, string> current,
            Dictionary<string, string> baseline,
            Dictionary<string, string> previous,
            bool hadBaseline,
            bool hadLast,
            List<RelatedActivity> related,
            bool protectedRuntime,
            ICollection<HwidIntegrityFinding> findings)
        {
            if (!hadBaseline)
            {
                return;
            }

            Dictionary<string, IdentityValue> byKey = values.ToDictionary(v => v.Key, v => v, StringComparer.OrdinalIgnoreCase);
            foreach (IdentityValue value in values.Where(v => v.SessionSensitive))
            {
                string baselineValue = null;
                string previousValue = null;
                bool hasBaseline = baseline.TryGetValue(value.Key, out baselineValue);
                bool hasPrevious = hadLast && previous.TryGetValue(value.Key, out previousValue);

                if (!hasBaseline)
                {
                    findings.Add(Finding(
                        "HardwareIdentifierFirstSeenAfterBaseline",
                        protectedRuntime ? EventSeverity.High : EventSeverity.Medium,
                        "Hardware identifier appeared after the first-seen baseline.",
                        value,
                        null,
                        hasPrevious ? previousValue : null,
                        value.Value,
                        protectedRuntime ? 0.78 : 0.64,
                        new Dictionary<string, string> { { "baseline_state", "missing" } }));
                    continue;
                }

                if (!NormalizedEquals(baselineValue, value.Value))
                {
                    EventSeverity severity = protectedRuntime ? EventSeverity.Critical : SeverityForIdentifier(value.IdentifierType);
                    findings.Add(Finding(
                        "HardwareIdentifierChangedFromBaseline",
                        severity,
                        "Hardware identity value changed compared to first-seen baseline.",
                        value,
                        baselineValue,
                        hasPrevious ? previousValue : null,
                        value.Value,
                        protectedRuntime ? 0.92 : 0.82,
                        new Dictionary<string, string> { { "baseline_diff_mode", "changed_identifier" } }));
                }

                if (hasPrevious && !NormalizedEquals(previousValue, value.Value))
                {
                    bool reverted = NormalizedEquals(baselineValue, value.Value) && !NormalizedEquals(previousValue, baselineValue);
                    findings.Add(Finding(
                        reverted ? "HardwareIdentifierRevertedToBaseline" : "RapidHardwareIdentifierRuntimeChange",
                        reverted ? EventSeverity.High : (protectedRuntime ? EventSeverity.Critical : EventSeverity.High),
                        reverted
                            ? "Hardware identity value reverted to the first-seen baseline after a prior change."
                            : "Hardware identity value changed between integrity snapshots.",
                        value,
                        baselineValue,
                        previousValue,
                        value.Value,
                        reverted ? 0.84 : (protectedRuntime ? 0.94 : 0.86),
                        new Dictionary<string, string> { { "baseline_diff_mode", reverted ? "reverted_identifier" : "runtime_change" } }));
                }
            }

            foreach (KeyValuePair<string, string> pair in baseline.Where(p => IsSensitiveKey(p.Key)))
            {
                if (current.ContainsKey(pair.Key))
                {
                    continue;
                }

                IdentityValue value;
                if (!byKey.TryGetValue(pair.Key, out value))
                {
                    value = IdentityValue.From(pair.Key, InferIdentifierType(pair.Key), "baseline", pair.Key, string.Empty, true);
                }

                findings.Add(Finding(
                    "HardwareIdentifierMissingFromBaseline",
                    EventSeverity.Medium,
                    "Hardware identifier from first-seen baseline is missing in the current snapshot.",
                    value,
                    pair.Value,
                    null,
                    "missing",
                    0.67,
                    new Dictionary<string, string> { { "baseline_diff_mode", "missing_identifier" } }));
            }
        }

        private static void EvaluateDeviceStack(
            HardwareIdentitySnapshot snapshot,
            Dictionary<string, string> current,
            Dictionary<string, string> baseline,
            Dictionary<string, string> previous,
            bool hadBaseline,
            bool hadLast,
            List<RelatedActivity> related,
            bool protectedRuntime,
            ICollection<HwidIntegrityFinding> findings)
        {
            foreach (DeviceStackRecord device in snapshot.Devices)
            {
                if (!string.IsNullOrWhiteSpace(device.UpperFilters) || !string.IsNullOrWhiteSpace(device.LowerFilters))
                {
                    string filters = HardwareIdentityUtilities.JoinNonEmpty(new[] { device.UpperFilters, device.LowerFilters }, ";");
                    if (LooksUnusualFilter(filters))
                    {
                        IdentityValue value = IdentityValue.From(
                            "devicefilter|" + (device.ClassGuid ?? device.DeviceId ?? device.PnpClass),
                            "device.filter_driver",
                            device.Source,
                            device.Name ?? device.ClassGuid,
                            filters,
                            true);

                        findings.Add(Finding(
                            "UnusualDeviceFilterDriver",
                            EventSeverity.High,
                            "Device class has an unusual or spoofing-relevant filter driver.",
                            value,
                            null,
                            null,
                            filters,
                            0.78,
                            DeviceDetails(device)));
                    }
                }

                if (device.IsVirtual && IsHardwareSensitiveClass(device.PnpClass))
                {
                    string key = "device|" + StableDeviceId(device) + "|present";
                    bool newComparedToBaseline = hadBaseline && !baseline.ContainsKey(key);
                    if (newComparedToBaseline || protectedRuntime)
                    {
                        IdentityValue value = IdentityValue.From(key, "device.virtual_hardware", device.Source, device.Name ?? device.DeviceId, "present", true);
                        findings.Add(Finding(
                            "VirtualHardwareDevicePresent",
                            protectedRuntime ? EventSeverity.High : EventSeverity.Medium,
                            "Virtual hardware-related device is present in a spoofing-sensitive device class.",
                            value,
                            newComparedToBaseline ? "missing" : null,
                            null,
                            "present",
                            protectedRuntime ? 0.78 : 0.62,
                            DeviceDetails(device)));
                    }
                }
            }

            if (!hadLast)
            {
                return;
            }

            foreach (KeyValuePair<string, string> pair in current.Where(p => p.Key.StartsWith("device|", StringComparison.OrdinalIgnoreCase)))
            {
                if (!previous.ContainsKey(pair.Key) && IsHardwareSensitiveKey(pair.Key))
                {
                    IdentityValue value = IdentityValue.From(pair.Key, "device.transient_candidate", "current", pair.Key, pair.Value, true);
                    findings.Add(Finding(
                        "HardwareDeviceAppearedDuringRuntime",
                        protectedRuntime ? EventSeverity.High : EventSeverity.Medium,
                        "Hardware-related PnP/device-stack entry appeared between snapshots.",
                        value,
                        baseline.ContainsKey(pair.Key) ? baseline[pair.Key] : null,
                        null,
                        pair.Value,
                        protectedRuntime ? 0.80 : 0.66,
                        new Dictionary<string, string> { { "device_stack_change", "appeared" } }));
                }
            }

            foreach (KeyValuePair<string, string> pair in previous.Where(p => p.Key.StartsWith("device|", StringComparison.OrdinalIgnoreCase)))
            {
                if (!current.ContainsKey(pair.Key) && IsHardwareSensitiveKey(pair.Key))
                {
                    IdentityValue value = IdentityValue.From(pair.Key, "device.transient_candidate", "previous", pair.Key, "missing", true);
                    findings.Add(Finding(
                        "TransientHardwareDeviceDisappeared",
                        EventSeverity.High,
                        "Hardware-related PnP/device-stack entry disappeared between snapshots.",
                        value,
                        baseline.ContainsKey(pair.Key) ? baseline[pair.Key] : null,
                        pair.Value,
                        "missing",
                        0.74,
                        new Dictionary<string, string> { { "device_stack_change", "disappeared" } }));
                }
            }
        }

        private static void EvaluateNetworkAnomalies(
            HardwareIdentitySnapshot snapshot,
            Dictionary<string, string> current,
            Dictionary<string, string> baseline,
            Dictionary<string, string> previous,
            bool hadBaseline,
            bool hadLast,
            List<RelatedActivity> related,
            bool protectedRuntime,
            ICollection<HwidIntegrityFinding> findings)
        {
            foreach (NetworkIdentityRecord adapter in snapshot.NetworkAdapters)
            {
                string entity = adapter.Name ?? adapter.Description ?? adapter.AdapterId;
                string key = "network|" + adapter.Source + "|" + (adapter.AdapterId ?? entity) + "|mac";
                IdentityValue value = IdentityValue.From(key, "network.mac", adapter.Source, entity, adapter.MacAddress, true);

                if (adapter.IsLocallyAdministered && HasSuspiciousContext(related, protectedRuntime))
                {
                    findings.Add(Finding(
                        "LocallyAdministeredMacInSuspiciousContext",
                        EventSeverity.High,
                        "Locally administered MAC address is present near suspicious loader, driver, or protected-game activity.",
                        value,
                        baseline.ContainsKey(key) ? baseline[key] : null,
                        previous.ContainsKey(key) ? previous[key] : null,
                        adapter.MacAddress,
                        0.82,
                        NetworkDetails(adapter)));
                }

                if (adapter.IsVirtual && protectedRuntime && hadBaseline && !baseline.ContainsKey(key))
                {
                    findings.Add(Finding(
                        "TemporaryVirtualAdapterDuringProtectedRuntime",
                        EventSeverity.High,
                        "Virtual network adapter appeared during protected runtime.",
                        value,
                        "missing",
                        previous.ContainsKey(key) ? previous[key] : null,
                        adapter.MacAddress,
                        0.80,
                        NetworkDetails(adapter)));
                }
            }
        }

        private static void EvaluateDiskVolumeAnomalies(
            HardwareIdentitySnapshot snapshot,
            Dictionary<string, string> current,
            Dictionary<string, string> baseline,
            Dictionary<string, string> previous,
            bool hadBaseline,
            bool hadLast,
            List<RelatedActivity> related,
            bool protectedRuntime,
            ICollection<HwidIntegrityFinding> findings)
        {
            foreach (DiskIdentityRecord disk in snapshot.Disks)
            {
                string combined = disk.Model + " " + disk.Vendor + " " + disk.InterfaceType + " " + disk.PnpDeviceId;
                if (HardwareIdentityUtilities.LooksVirtual(combined) && HasSuspiciousContext(related, protectedRuntime))
                {
                    IdentityValue value = IdentityValue.From(
                        "disk|" + disk.Source + "|" + (disk.Index ?? disk.DeviceId ?? disk.RegistryPath) + "|serial",
                        "disk.virtual_storage_layer",
                        disk.Source,
                        disk.Model ?? disk.DeviceId,
                        disk.Serial,
                        true);

                    findings.Add(Finding(
                        "SuspiciousVirtualStorageLayer",
                        EventSeverity.High,
                        "Virtual storage layer is present near suspicious HWID-related activity.",
                        value,
                        baseline.ContainsKey(value.Key) ? baseline[value.Key] : null,
                        previous.ContainsKey(value.Key) ? previous[value.Key] : null,
                        disk.Serial,
                        0.78,
                        DiskDetails(disk)));
                }
            }

            foreach (VolumeIdentityRecord volume in snapshot.Volumes)
            {
                string key = "volume|" + volume.DriveName + "|serial";
                if (hadLast && previous.ContainsKey(key) && current.ContainsKey(key) && !NormalizedEquals(previous[key], current[key]))
                {
                    IdentityValue value = IdentityValue.From(key, "volume.serial", "GetVolumeInformation", volume.DriveName, volume.VolumeSerial, true);
                    findings.Add(Finding(
                        "VolumeSerialChangedDuringRuntime",
                        protectedRuntime ? EventSeverity.High : EventSeverity.Medium,
                        "Volume serial changed between integrity snapshots.",
                        value,
                        baseline.ContainsKey(key) ? baseline[key] : null,
                        previous[key],
                        current[key],
                        protectedRuntime ? 0.82 : 0.67,
                        VolumeDetails(volume)));
                }
            }
        }

        private static void ApplyCorrelation(ICollection<HwidIntegrityFinding> findings, List<RelatedActivity> related, bool protectedRuntime)
        {
            if (findings.Count == 0)
            {
                return;
            }

            foreach (HwidIntegrityFinding finding in findings)
            {
                foreach (RelatedActivity activity in related)
                {
                    foreach (string tag in activity.Tags)
                    {
                        finding.CorrelationTags.Add(tag);
                    }

                    finding.RelatedActivities.Add(activity);
                }

                if (finding.CorrelationTags.Contains("hidden_kernel_indicator") ||
                    finding.CorrelationTags.Contains("vulnerable_driver") ||
                    finding.CorrelationTags.Contains("mapper_behavior") ||
                    finding.CorrelationTags.Contains("transient_sys") ||
                    finding.CorrelationTags.Contains("device_object"))
                {
                    finding.ConfidenceScore = Math.Min(0.99, finding.ConfidenceScore + 0.12);
                    if (finding.Severity == EventSeverity.Medium)
                    {
                        finding.Severity = EventSeverity.High;
                    }

                    finding.Details["correlation_reason"] = "hardware_identity_change_near_driver_mapper_or_device_activity";
                }

                if (protectedRuntime)
                {
                    finding.CorrelationTags.Add("protected_runtime");
                    finding.ConfidenceScore = Math.Min(0.99, finding.ConfidenceScore + 0.06);
                }

                string caseId = related.Select(a => a.CaseId).FirstOrDefault(c => !string.IsNullOrWhiteSpace(c));
                finding.CaseId = string.IsNullOrWhiteSpace(caseId) ? BuildCaseId(finding) : caseId;
            }
        }

        private bool ShouldEmitFinding(HwidIntegrityFinding finding)
        {
            string key = finding.Action + "|" + finding.IdentityKey + "|" + finding.CurrentValue + "|" + finding.PreviousValue + "|" + finding.BaselineValue;
            if (finding.Severity >= EventSeverity.High)
            {
                lock (_reportedKeys)
                {
                    return _reportedKeys.Add(key);
                }
            }

            return true;
        }

        private List<HwidSpooferProfile> BuildSpooferProfiles(
            List<HwidIntegrityFinding> findings,
            Dictionary<string, string> current,
            Dictionary<string, string> baseline,
            Dictionary<string, string> previous,
            List<RelatedActivity> related,
            bool protectedRuntime,
            string stage)
        {
            List<HwidSpooferProfile> profiles = new List<HwidSpooferProfile>();
            ProfileScore registryOnly = NewProfile("registry_only_spoofer");
            ProfileScore driverBacked = NewProfile("driver_backed_spoofer");
            ProfileScore networkMac = NewProfile("network_mac_spoofer");
            ProfileScore diskVolume = NewProfile("disk_volume_spoofer");
            ProfileScore smbiosFirmware = NewProfile("smbios_firmware_spoofer");
            ProfileScore vmHypervisor = NewProfile("vm_hypervisor_assisted_spoofer");
            ProfileScore temporarySession = NewProfile("temporary_session_spoofer");

            bool hasDriverContext = HasTag(related, "hidden_kernel_indicator", "vulnerable_driver", "mapper_behavior", "transient_sys", "service_activity", "device_object");
            bool hasRegistryContext = HasTag(related, "machine_guid_registry", "windows_identity_registry", "network_identity_registry", "storage_identity_registry", "hardware_identity_registry");
            bool hasDeviceChange = findings.Any(f => ContainsAny(f.Action, "Device", "Filter") || ContainsAny(f.IdentifierType, "device."));
            bool hasIdentityChange = findings.Any(IsIdentityChangeFinding);
            bool hasRevert = findings.Any(f => f.Action.Equals("HardwareIdentifierRevertedToBaseline", StringComparison.OrdinalIgnoreCase));
            bool hasRuntimeChange = findings.Any(f => f.Action.Equals("RapidHardwareIdentifierRuntimeChange", StringComparison.OrdinalIgnoreCase));
            bool launchOrRuntimeStage = ContainsAny(stage, "ProtectedGameLaunch", "DuringProtectedGameRuntime", "AfterProtectedGameExit");

            if (hasRegistryContext) AddScore(registryOnly, 0.25, "hardware_identity_registry_write");
            if (hasIdentityChange && hasRegistryContext) AddScore(registryOnly, 0.25, "registry_edit_near_identity_change");
            if (findings.Any(f => ContainsAny(f.IdentifierType, "network.mac", "volume.serial", "smbios.", "disk.serial") && IsIdentityChangeFinding(f))) AddScore(registryOnly, 0.20, "registry_spoofable_identifier_changed");
            if (hasIdentityChange && !hasDeviceChange && !hasDriverContext) AddScore(registryOnly, 0.20, "identity_changed_without_matching_device_stack_change");
            if (HasTag(related, "machine_guid_registry")) AddScore(registryOnly, 0.15, "machine_guid_or_windows_identity_key_changed");

            if (HasTag(related, "hidden_kernel_indicator")) AddScore(driverBacked, 0.22, "hidden_driver_indicator_near_hwid_change");
            if (HasTag(related, "vulnerable_driver")) AddScore(driverBacked, 0.20, "vulnerable_driver_pattern_before_identifier_change");
            if (HasTag(related, "mapper_behavior")) AddScore(driverBacked, 0.20, "mapper_behavior_near_identifier_change");
            if (HasTag(related, "transient_sys")) AddScore(driverBacked, 0.18, "temporary_sys_artifact_near_identifier_change");
            if (HasTag(related, "service_activity")) AddScore(driverBacked, 0.12, "temporary_driver_service_activity");
            if (findings.Any(f => ContainsAny(f.Action, "UnusualDeviceFilterDriver", "VirtualHardwareDevicePresent", "HardwareDeviceAppearedDuringRuntime", "TransientHardwareDeviceDisappeared"))) AddScore(driverBacked, 0.20, "new_device_or_filter_behavior");
            if (hasIdentityChange && hasDriverContext) AddScore(driverBacked, 0.18, "hardware_identifier_changed_after_driver_activity");

            if (findings.Any(f => ContainsAny(f.IdentifierType, "network.mac") && IsIdentityChangeFinding(f))) AddScore(networkMac, 0.28, "mac_identifier_changed");
            if (findings.Any(f => f.Action.Equals("LocallyAdministeredMacInSuspiciousContext", StringComparison.OrdinalIgnoreCase))) AddScore(networkMac, 0.25, "locally_administered_mac_in_suspicious_context");
            if (findings.Any(f => f.Action.Equals("TemporaryVirtualAdapterDuringProtectedRuntime", StringComparison.OrdinalIgnoreCase))) AddScore(networkMac, 0.22, "temporary_virtual_adapter_during_game_runtime");
            if (HasTag(related, "adapter_reset")) AddScore(networkMac, 0.18, "adapter_reset_or_disable_enable_near_session");
            if (HasTag(related, "network_identity_registry")) AddScore(networkMac, 0.18, "adapter_registry_write_before_or_during_session");

            if (findings.Any(f => ContainsAny(f.IdentifierType, "disk.", "volume.", "storage."))) AddScore(diskVolume, 0.26, "disk_or_volume_identity_anomaly");
            if (findings.Any(f => f.Action.Equals("VolumeSerialChangedDuringRuntime", StringComparison.OrdinalIgnoreCase))) AddScore(diskVolume, 0.24, "volume_serial_runtime_change");
            if (findings.Any(f => f.Action.Equals("SuspiciousVirtualStorageLayer", StringComparison.OrdinalIgnoreCase))) AddScore(diskVolume, 0.24, "suspicious_virtual_storage_layer");
            if (findings.Any(f => ContainsAny(f.Action, "Disk", "Storage") && ContainsAny(f.Action, "Mismatch", "Changed"))) AddScore(diskVolume, 0.18, "storage_model_vendor_or_serial_mismatch");
            if (HasTag(related, "storage_identity_registry")) AddScore(diskVolume, 0.14, "storage_registry_write_near_session");
            if (hasDriverContext && findings.Any(f => ContainsAny(f.IdentifierType, "disk.", "volume.", "storage."))) AddScore(diskVolume, 0.12, "storage_change_near_driver_activity");

            if (findings.Any(f => ContainsAny(f.IdentifierType, "smbios.uuid", "smbios.baseboard", "smbios.bios", "smbios.firmware_hash") && IsIdentityChangeFinding(f))) AddScore(smbiosFirmware, 0.28, "smbios_or_firmware_identifier_changed");
            if (findings.Any(f => ContainsAny(f.Action, "MalformedSystemUuid", "MalformedOrZeroedHardwareIdentifier", "RandomizedLookingHardwareIdentifier") && ContainsAny(f.IdentifierType, "smbios", "system."))) AddScore(smbiosFirmware, 0.22, "smbios_identifier_blank_generic_or_randomized");
            if (findings.Any(f => f.Action.Equals("ImpossibleHardwareVendorCombination", StringComparison.OrdinalIgnoreCase))) AddScore(smbiosFirmware, 0.22, "impossible_vendor_model_relationship");
            if (HasTag(related, "hardware_identity_registry")) AddScore(smbiosFirmware, 0.14, "smbios_registry_cache_change");
            if (hasDriverContext && findings.Any(f => ContainsAny(f.IdentifierType, "smbios", "system."))) AddScore(smbiosFirmware, 0.12, "firmware_identity_change_near_driver_activity");

            if (findings.Any(f => ContainsAny(f.IdentifierType, "system.hypervisor_present") && IsIdentityChangeFinding(f))) AddScore(vmHypervisor, 0.30, "hypervisor_presence_changed");
            if (findings.Any(f => ContainsAny(f.Action, "VirtualHardwareDevicePresent", "SuspiciousVirtualGpuVendorMix", "SuspiciousVirtualStorageLayer"))) AddScore(vmHypervisor, 0.28, "unusual_virtual_hardware_identity_pattern");
            if (findings.Any(f => ContainsAny(f.Action, "ImpossibleHardwareVendorCombination", "SuspiciousVirtualGpuVendorMix"))) AddScore(vmHypervisor, 0.20, "inconsistent_physical_virtual_device_mix");
            if (findings.Any(f => ContainsAny(f.IdentifierType, "device.virtual_hardware", "gpu.vendor_relationship", "disk.virtual_storage_layer"))) AddScore(vmHypervisor, 0.18, "virtualized_device_identity_indicator");
            if (protectedRuntime) AddScore(vmHypervisor, 0.06, "virtualization_indicator_during_protected_runtime");

            if (launchOrRuntimeStage && hasIdentityChange) AddScore(temporarySession, 0.24, "identifier_changed_at_game_session_boundary");
            if (hasRevert) AddScore(temporarySession, 0.26, "identifier_reverted_to_baseline");
            if (hasRuntimeChange) AddScore(temporarySession, 0.20, "identifier_changed_between_runtime_snapshots");
            if (findings.Any(f => f.Action.Equals("TransientHardwareDeviceDisappeared", StringComparison.OrdinalIgnoreCase))) AddScore(temporarySession, 0.20, "spoofing_artifact_disappeared_after_use");
            if (hasDriverContext && launchOrRuntimeStage) AddScore(temporarySession, 0.16, "loader_or_driver_activity_only_near_game_session");
            if (HasTag(related, "transient_sys", "mapper_behavior")) AddScore(temporarySession, 0.14, "transient_loader_or_mapper_artifacts");

            AddProfileIfMatched(profiles, registryOnly, findings, current, baseline, previous, related);
            AddProfileIfMatched(profiles, driverBacked, findings, current, baseline, previous, related);
            AddProfileIfMatched(profiles, networkMac, findings, current, baseline, previous, related);
            AddProfileIfMatched(profiles, diskVolume, findings, current, baseline, previous, related);
            AddProfileIfMatched(profiles, smbiosFirmware, findings, current, baseline, previous, related);
            AddProfileIfMatched(profiles, vmHypervisor, findings, current, baseline, previous, related);
            AddProfileIfMatched(profiles, temporarySession, findings, current, baseline, previous, related);

            return profiles.OrderByDescending(p => p.ConfidenceScore).ToList();
        }

        private static ProfileScore NewProfile(string name)
        {
            return new ProfileScore { Name = name };
        }

        private static void AddScore(ProfileScore score, double amount, string indicator)
        {
            score.Score = Math.Min(1.0, score.Score + amount);
            if (!string.IsNullOrWhiteSpace(indicator))
            {
                score.Indicators.Add(indicator);
            }
        }

        private static void AddProfileIfMatched(
            ICollection<HwidSpooferProfile> profiles,
            ProfileScore score,
            List<HwidIntegrityFinding> findings,
            Dictionary<string, string> current,
            Dictionary<string, string> baseline,
            Dictionary<string, string> previous,
            List<RelatedActivity> related)
        {
            if (score.Score < 0.45 || score.Indicators.Count < 2)
            {
                return;
            }

            HwidSpooferProfile profile = new HwidSpooferProfile
            {
                ProfileName = score.Name,
                ConfidenceScore = Math.Min(0.99, score.Score),
                Severity = score.Score >= 0.82 ? EventSeverity.Critical :
                    score.Score >= 0.62 ? EventSeverity.High : EventSeverity.Medium,
                CaseId = BuildCaseId("profile|" + score.Name + "|" + string.Join(";", score.Indicators.OrderBy(i => i).ToArray()))
            };

            foreach (string indicator in score.Indicators)
            {
                profile.MatchedIndicators.Add(indicator);
            }

            foreach (HwidIntegrityFinding finding in RelevantFindingsForProfile(score.Name, findings).Take(24))
            {
                profile.Diffs.Add(ProfileDiff.FromFinding(finding));
                profile.EvidenceTimeline.Add("finding " + finding.Action + " " + finding.IdentifierType + " " + Trim(finding.Entity, 80));
                if (!string.IsNullOrWhiteSpace(finding.CaseId))
                {
                    profile.CaseLinks.Add(finding.CaseId);
                }

                AddRelatedArtifacts(profile, finding);
            }

            foreach (ProfileDiff diff in BuildCurrentDiffs(current, baseline, previous).Where(d => ProfileNameMatchesDiff(score.Name, d)).Take(16))
            {
                profile.Diffs.Add(diff);
            }

            foreach (RelatedActivity activity in related.Take(20))
            {
                profile.RelatedActivities.Add(activity);
                profile.EvidenceTimeline.Add(activity.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + " " + activity.Category + "/" + activity.Action + " " + Trim(activity.Description, 140));
                if (!string.IsNullOrWhiteSpace(activity.CaseId))
                {
                    profile.CaseLinks.Add(activity.CaseId);
                }

                if (!string.IsNullOrWhiteSpace(activity.ProcessName))
                {
                    profile.RelatedArtifacts.Add("process:" + activity.ProcessName);
                }

                if (!string.IsNullOrWhiteSpace(activity.Path))
                {
                    profile.RelatedArtifacts.Add("path:" + activity.Path);
                }

                foreach (string tag in activity.Tags)
                {
                    profile.RelatedArtifacts.Add("tag:" + tag);
                }
            }

            if (profile.CaseLinks.Count == 0)
            {
                profile.CaseLinks.Add(profile.CaseId);
            }

            profiles.Add(profile);
        }

        private static IEnumerable<HwidIntegrityFinding> RelevantFindingsForProfile(string profileName, IEnumerable<HwidIntegrityFinding> findings)
        {
            foreach (HwidIntegrityFinding finding in findings)
            {
                if (ProfileNameMatchesFinding(profileName, finding))
                {
                    yield return finding;
                }
            }
        }

        private static bool ProfileNameMatchesFinding(string profileName, HwidIntegrityFinding finding)
        {
            string text = (finding.Action + " " + finding.IdentifierType + " " + finding.IdentityKey + " " + string.Join(";", finding.CorrelationTags.ToArray())).ToLowerInvariant();
            if (profileName == "registry_only_spoofer") return ContainsAny(text, "registry", "machineguid", "windows", "network.mac", "volume.serial", "smbios", "disk.serial");
            if (profileName == "driver_backed_spoofer") return ContainsAny(text, "driver", "device", "filter", "hidden", "vulnerable", "mapper", "service", "sys");
            if (profileName == "network_mac_spoofer") return ContainsAny(text, "network", "mac", "adapter");
            if (profileName == "disk_volume_spoofer") return ContainsAny(text, "disk", "volume", "storage", "mounteddevice");
            if (profileName == "smbios_firmware_spoofer") return ContainsAny(text, "smbios", "bios", "baseboard", "uuid", "firmware", "vendor");
            if (profileName == "vm_hypervisor_assisted_spoofer") return ContainsAny(text, "virtual", "hypervisor", "gpu.vendor", "virtual_hardware");
            if (profileName == "temporary_session_spoofer") return ContainsAny(text, "reverted", "runtime", "transient", "changed", "disappeared", "protected_runtime");
            return true;
        }

        private static IEnumerable<ProfileDiff> BuildCurrentDiffs(Dictionary<string, string> current, Dictionary<string, string> baseline, Dictionary<string, string> previous)
        {
            foreach (KeyValuePair<string, string> pair in current.OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase))
            {
                string baselineValue = null;
                string previousValue = null;
                bool changed = baseline.TryGetValue(pair.Key, out baselineValue) && !NormalizedEquals(baselineValue, pair.Value);
                bool runtimeChanged = previous.TryGetValue(pair.Key, out previousValue) && !NormalizedEquals(previousValue, pair.Value);
                bool appeared = !baseline.ContainsKey(pair.Key);
                if (!changed && !runtimeChanged && !appeared)
                {
                    continue;
                }

                yield return new ProfileDiff
                {
                    IdentityKey = pair.Key,
                    IdentifierType = InferIdentifierType(pair.Key),
                    BaselineValue = baselineValue,
                    PreviousValue = previousValue,
                    CurrentValue = pair.Value,
                    ChangeType = appeared ? "appeared_after_baseline" : runtimeChanged ? "runtime_changed" : "changed_from_baseline"
                };
            }
        }

        private static bool ProfileNameMatchesDiff(string profileName, ProfileDiff diff)
        {
            string text = (diff.IdentityKey + " " + diff.IdentifierType + " " + diff.ChangeType).ToLowerInvariant();
            if (profileName == "registry_only_spoofer") return ContainsAny(text, "network", "volume", "smbios", "system", "disk");
            if (profileName == "driver_backed_spoofer") return ContainsAny(text, "device", "filter", "disk", "network", "smbios");
            if (profileName == "network_mac_spoofer") return ContainsAny(text, "network", "mac");
            if (profileName == "disk_volume_spoofer") return ContainsAny(text, "disk", "volume", "storage", "mounteddevice");
            if (profileName == "smbios_firmware_spoofer") return ContainsAny(text, "smbios", "bios", "baseboard", "uuid", "firmware", "system");
            if (profileName == "vm_hypervisor_assisted_spoofer") return ContainsAny(text, "virtual", "hypervisor", "gpu", "device");
            if (profileName == "temporary_session_spoofer") return ContainsAny(text, "runtime_changed", "appeared", "changed", "device", "network", "disk", "smbios");
            return true;
        }

        private static void AddRelatedArtifacts(HwidSpooferProfile profile, HwidIntegrityFinding finding)
        {
            if (!string.IsNullOrWhiteSpace(finding.Source)) profile.RelatedArtifacts.Add("source:" + finding.Source);
            if (!string.IsNullOrWhiteSpace(finding.Entity)) profile.RelatedArtifacts.Add("entity:" + finding.Entity);

            foreach (KeyValuePair<string, string> detail in finding.Details)
            {
                if (string.IsNullOrWhiteSpace(detail.Value))
                {
                    continue;
                }

                if (detail.Key.IndexOf("service", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    detail.Key.IndexOf("driver", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    detail.Key.IndexOf("path", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    detail.Key.IndexOf("device", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    profile.RelatedArtifacts.Add(detail.Key + ":" + detail.Value);
                }
            }
        }

        private bool ShouldEmitProfile(HwidSpooferProfile profile)
        {
            string key = "profile|" + profile.ProfileName + "|" + string.Join(";", profile.CaseLinks.OrderBy(v => v).ToArray()) + "|" + FormatProfileDiff(profile.Diffs);
            if (profile.Severity >= EventSeverity.High)
            {
                lock (_reportedKeys)
                {
                    return _reportedKeys.Add(key);
                }
            }

            return true;
        }

        private void UpdateRuntimeLaunchSessions(
            string stage,
            string snapshotPath,
            Dictionary<string, string> current,
            Dictionary<string, string> baseline,
            List<RelatedActivity> related,
            List<HwidSpooferProfile> profiles)
        {
            List<LaunchIdentitySession> sessions;
            lock (_sessionLock)
            {
                sessions = _launchSessions.Values.ToList();
            }

            foreach (LaunchIdentitySession session in sessions)
            {
                if (session.LaunchValues.Count == 0)
                {
                    continue;
                }

                List<ProfileDiff> runtimeDiffs = BuildDictionaryDiffs(session.LaunchValues, current, "runtime_vs_launch");
                foreach (ProfileDiff diff in runtimeDiffs)
                {
                    AddUniqueDiff(session.RuntimeDiffs, diff);
                }

                foreach (RelatedActivity activity in related.Where(a => a.TimestampUtc >= session.LaunchTimeUtc))
                {
                    session.SessionActivities.Add(activity);
                }

                foreach (HwidSpooferProfile profile in profiles)
                {
                    session.ObservedProfiles.Add(profile.ProfileName);
                }

                session.LastRuntimeValues = CloneDictionary(current);
                session.LastRuntimeSnapshotPath = snapshotPath;
                session.RuntimeSnapshotCount++;

                if (runtimeDiffs.Count > 0 && ShouldEmitSessionRuntime(session, runtimeDiffs))
                {
                    string reportPath = WriteLaunchSessionReport(session, "runtime", current, baseline, session.LaunchValues, related, profiles);
                    SpoofSessionScore score = ScoreLaunchSession(session);
                    EmitLaunchSessionEvent(
                        "RuntimeIdentityDriftObserved",
                        score.Severity >= EventSeverity.High ? score.Severity : EventSeverity.Medium,
                        "Protected process runtime identity drift observed for " + session.ProcessName + ".",
                        session,
                        reportPath,
                        new Dictionary<string, string>
                        {
                            { "runtime_diff", FormatProfileDiff(runtimeDiffs) },
                            { "accumulated_runtime_diff", FormatProfileDiff(session.RuntimeDiffs) },
                            { "confidence_score", score.Score.ToString("0.00", CultureInfo.InvariantCulture) },
                            { "score_reasons", string.Join(";", score.Reasons.OrderBy(v => v).ToArray()) },
                            { "suspected_spoofer_profile", InferSessionProfile(session, profiles) },
                            { "stage", stage }
                        });
                }
            }
        }

        private bool ShouldEmitSessionRuntime(LaunchIdentitySession session, List<ProfileDiff> diffs)
        {
            string key = "session-runtime|" + session.CaseId + "|" + FormatProfileDiff(diffs);
            lock (_reportedKeys)
            {
                return _reportedKeys.Add(key);
            }
        }

        private int ActiveLaunchSessionCount()
        {
            lock (_sessionLock)
            {
                return _launchSessions.Count;
            }
        }

        private List<IdentityValue> FlattenSnapshot(HardwareIdentitySnapshot snapshot)
        {
            List<IdentityValue> values = new List<IdentityValue>();

            foreach (SystemIdentityRecord system in snapshot.SystemIdentities)
            {
                string entity = system.SystemVendor + " " + system.SystemProduct + " " + system.Source;
                Add(values, "system|" + system.Source + "|bios_vendor", "smbios.bios_vendor", system.Source, entity, system.BiosVendor, false);
                Add(values, "system|" + system.Source + "|bios_version", "smbios.bios_version", system.Source, entity, system.BiosVersion, false);
                Add(values, "system|" + system.Source + "|bios_serial", "smbios.bios_serial", system.Source, entity, system.BiosSerial, true);
                Add(values, "system|" + system.Source + "|baseboard_vendor", "smbios.baseboard_vendor", system.Source, entity, system.BaseboardVendor, false);
                Add(values, "system|" + system.Source + "|baseboard_serial", "smbios.baseboard_serial", system.Source, entity, system.BaseboardSerial, true);
                Add(values, "system|" + system.Source + "|system_uuid", "smbios.uuid", system.Source, entity, system.SystemUuid, true);
                Add(values, "system|" + system.Source + "|firmware_hash", "smbios.firmware_hash", system.Source, entity, system.FirmwareHash, true);
                Add(values, "system|" + system.Source + "|hypervisor_present", "system.hypervisor_present", system.Source, entity, system.HypervisorPresent, true);
            }

            foreach (DiskIdentityRecord disk in snapshot.Disks)
            {
                string key = "disk|" + disk.Source + "|" + (disk.Index ?? disk.DeviceId ?? disk.RegistryPath ?? disk.PnpDeviceId);
                string entity = disk.Model ?? disk.DeviceId ?? key;
                Add(values, key + "|serial", "disk.serial", disk.Source, entity, disk.Serial, true);
                Add(values, key + "|model", "disk.model", disk.Source, entity, disk.Model, false);
                Add(values, key + "|vendor", "disk.vendor", disk.Source, entity, disk.Vendor, false);
                Add(values, key + "|pnp", "disk.pnp", disk.Source, entity, disk.PnpDeviceId, true);
            }

            foreach (VolumeIdentityRecord volume in snapshot.Volumes)
            {
                Add(values, "volume|" + volume.DriveName + "|serial", "volume.serial", "GetVolumeInformation", volume.DriveName, volume.VolumeSerial, true);
            }

            foreach (MountedDeviceRecord mounted in snapshot.MountedDevices)
            {
                Add(values, "mounteddevice|" + mounted.RegistryValueName, "storage.mounted_device", "Registry.MountedDevices", mounted.RegistryValueName, mounted.ValueHash, true);
            }

            foreach (NetworkIdentityRecord adapter in snapshot.NetworkAdapters)
            {
                string key = "network|" + adapter.Source + "|" + (adapter.AdapterId ?? adapter.Name ?? adapter.Description);
                string entity = adapter.Name ?? adapter.Description ?? adapter.AdapterId;
                Add(values, key + "|mac", "network.mac", adapter.Source, entity, adapter.MacAddress, true);
                Add(values, key + "|pnp", "network.pnp", adapter.Source, entity, adapter.PnpDeviceId, true);
            }

            foreach (GpuIdentityRecord gpu in snapshot.Gpus)
            {
                string key = "gpu|" + gpu.Source + "|" + (gpu.PnpDeviceId ?? gpu.DeviceId ?? gpu.Name);
                string entity = gpu.Name ?? gpu.DeviceId ?? key;
                Add(values, key + "|pnp", "gpu.pnp", gpu.Source, entity, gpu.PnpDeviceId, true);
                Add(values, key + "|device_id", "gpu.device_id", gpu.Source, entity, gpu.DeviceId, true);
                Add(values, key + "|driver_version", "gpu.driver_version", gpu.Source, entity, gpu.DriverVersion, false);
                Add(values, key + "|driver_path", "gpu.driver_path", gpu.Source, entity, gpu.DriverPath, true);
            }

            foreach (TpmIdentityRecord tpm in snapshot.Tpms)
            {
                string entity = "TPM";
                Add(values, "tpm|" + tpm.Source + "|present", "tpm.present", tpm.Source, entity, tpm.Present.ToString(), true);
                Add(values, "tpm|" + tpm.Source + "|enabled", "tpm.enabled", tpm.Source, entity, tpm.Enabled.ToString(), true);
                Add(values, "tpm|" + tpm.Source + "|activated", "tpm.activated", tpm.Source, entity, tpm.Activated.ToString(), true);
                Add(values, "tpm|" + tpm.Source + "|owned", "tpm.owned", tpm.Source, entity, tpm.Owned.ToString(), true);
                Add(values, "tpm|" + tpm.Source + "|manufacturer", "tpm.manufacturer", tpm.Source, entity, tpm.ManufacturerId, false);
                Add(values, "tpm|" + tpm.Source + "|version", "tpm.version", tpm.Source, entity, tpm.ManufacturerVersion, false);
            }

            foreach (MonitorIdentityRecord monitor in snapshot.Monitors)
            {
                string key = "monitor|" + monitor.Source + "|" + (monitor.DeviceId ?? monitor.InstanceId ?? monitor.EdidHash);
                string entity = monitor.FriendlyName ?? monitor.DeviceId ?? key;
                Add(values, key + "|manufacturer", "monitor.manufacturer", monitor.Source, entity, monitor.Manufacturer, false);
                Add(values, key + "|product", "monitor.product", monitor.Source, entity, monitor.ProductCode, true);
                Add(values, key + "|serial", "monitor.serial", monitor.Source, entity, monitor.Serial, true);
                Add(values, key + "|edid_hash", "monitor.edid_hash", monitor.Source, entity, monitor.EdidHash, true);
            }

            foreach (DeviceStackRecord device in snapshot.Devices)
            {
                string key = "device|" + StableDeviceId(device);
                string entity = device.Name ?? device.DeviceId ?? key;
                Add(values, key + "|present", "device.present", device.Source, entity, "present", IsHardwareSensitiveClass(device.PnpClass));
                Add(values, key + "|service", "device.service", device.Source, entity, device.Service, IsHardwareSensitiveClass(device.PnpClass));
                Add(values, key + "|status", "device.status", device.Source, entity, device.Status, false);
                Add(values, key + "|upper_filters", "device.upper_filters", device.Source, entity, device.UpperFilters, true);
                Add(values, key + "|lower_filters", "device.lower_filters", device.Source, entity, device.LowerFilters, true);
            }

            return values;
        }

        private static void Add(ICollection<IdentityValue> values, string key, string identifierType, string source, string entity, string value, bool sessionSensitive)
        {
            string normalized = HardwareIdentityUtilities.NormalizeIdentifier(value);
            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(normalized))
            {
                return;
            }

            values.Add(IdentityValue.From(key, identifierType, source, entity, normalized, sessionSensitive));
        }

        private static Dictionary<string, string> ValuesToDictionary(IEnumerable<IdentityValue> values)
        {
            Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (IdentityValue value in values)
            {
                result[value.Key] = value.Value;
            }

            return result;
        }

        private static Dictionary<string, string> CloneDictionary(IDictionary<string, string> source)
        {
            return source == null
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(source, StringComparer.OrdinalIgnoreCase);
        }

        private static List<ProfileDiff> BuildDictionaryDiffs(IDictionary<string, string> before, IDictionary<string, string> after, string changeType)
        {
            List<ProfileDiff> diffs = new List<ProfileDiff>();
            if (after == null)
            {
                return diffs;
            }

            Dictionary<string, string> safeBefore = before == null
                ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(before, StringComparer.OrdinalIgnoreCase);

            foreach (KeyValuePair<string, string> pair in after.Where(p => IsSensitiveKey(p.Key)).OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase))
            {
                string oldValue;
                if (!safeBefore.TryGetValue(pair.Key, out oldValue))
                {
                    diffs.Add(new ProfileDiff
                    {
                        IdentityKey = pair.Key,
                        IdentifierType = InferIdentifierType(pair.Key),
                        BaselineValue = null,
                        PreviousValue = null,
                        CurrentValue = pair.Value,
                        ChangeType = changeType + ":appeared"
                    });
                }
                else if (!NormalizedEquals(oldValue, pair.Value))
                {
                    diffs.Add(new ProfileDiff
                    {
                        IdentityKey = pair.Key,
                        IdentifierType = InferIdentifierType(pair.Key),
                        BaselineValue = oldValue,
                        PreviousValue = oldValue,
                        CurrentValue = pair.Value,
                        ChangeType = changeType + ":changed"
                    });
                }
            }

            foreach (KeyValuePair<string, string> pair in safeBefore.Where(p => IsSensitiveKey(p.Key)).OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase))
            {
                if (after.ContainsKey(pair.Key))
                {
                    continue;
                }

                diffs.Add(new ProfileDiff
                {
                    IdentityKey = pair.Key,
                    IdentifierType = InferIdentifierType(pair.Key),
                    BaselineValue = pair.Value,
                    PreviousValue = pair.Value,
                    CurrentValue = "missing",
                    ChangeType = changeType + ":missing"
                });
            }

            return diffs;
        }

        private static void AddUniqueDiff(ICollection<ProfileDiff> target, ProfileDiff diff)
        {
            if (target == null || diff == null)
            {
                return;
            }

            string key = diff.IdentityKey + "|" + diff.ChangeType + "|" + diff.BaselineValue + "|" + diff.PreviousValue + "|" + diff.CurrentValue;
            if (target.Any(d => string.Equals(d.IdentityKey + "|" + d.ChangeType + "|" + d.BaselineValue + "|" + d.PreviousValue + "|" + d.CurrentValue, key, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            target.Add(diff);
        }

        private static void DetectSessionReverts(LaunchIdentitySession session, IDictionary<string, string> baseline, IDictionary<string, string> post)
        {
            if (session == null || post == null)
            {
                return;
            }

            foreach (ProfileDiff runtime in session.RuntimeDiffs.Concat(session.BaselineDiffs).ToList())
            {
                string postValue;
                if (!post.TryGetValue(runtime.IdentityKey, out postValue))
                {
                    continue;
                }

                string baselineValue = null;
                if (baseline != null)
                {
                    baseline.TryGetValue(runtime.IdentityKey, out baselineValue);
                }

                string launchValue = null;
                session.LaunchValues.TryGetValue(runtime.IdentityKey, out launchValue);

                if ((!string.IsNullOrWhiteSpace(baselineValue) && NormalizedEquals(postValue, baselineValue) && !NormalizedEquals(runtime.CurrentValue, baselineValue)) ||
                    (!string.IsNullOrWhiteSpace(launchValue) && NormalizedEquals(postValue, launchValue) && !NormalizedEquals(runtime.CurrentValue, launchValue)))
                {
                    AddUniqueDiff(session.RevertedDiffs, new ProfileDiff
                    {
                        IdentityKey = runtime.IdentityKey,
                        IdentifierType = runtime.IdentifierType,
                        BaselineValue = baselineValue,
                        PreviousValue = runtime.CurrentValue,
                        CurrentValue = postValue,
                        ChangeType = "post_launch_revert"
                    });
                }
            }
        }

        private SpoofSessionScore ScoreLaunchSession(LaunchIdentitySession session)
        {
            SpoofSessionScore score = new SpoofSessionScore();
            if (session == null)
            {
                return score;
            }

            if (session.BaselineDiffs.Count > 0 || session.LastBootDiffs.Count > 0)
            {
                score.Add(0.18, "identity_diff_at_launch");
            }

            if (session.RuntimeDiffs.Count > 0)
            {
                score.Add(0.24, "identity_changed_during_game_runtime");
            }

            if (session.RevertedDiffs.Count > 0)
            {
                score.Add(0.28, "identity_reverted_after_exit_or_session_end");
            }

            if (HasTag(session.PreLaunchActivities, "mapper_behavior", "vulnerable_driver", "transient_sys", "service_activity", "device_object"))
            {
                score.Add(0.22, "loader_driver_or_service_activity_before_launch");
            }

            if (HasTag(session.PreLaunchActivities, "adapter_reset", "network_identity_registry"))
            {
                score.Add(0.14, "adapter_reset_or_network_registry_write_before_launch");
            }

            if (HasTag(session.SessionActivities, "hidden_kernel_indicator"))
            {
                score.Add(0.20, "hidden_driver_indicator_during_session");
            }

            if (session.ObservedProfiles.Count > 0)
            {
                score.Add(0.10, "hwid_spoofer_profile_matched");
            }

            if (session.PostLaunchDiffs.Any(d => d.ChangeType.IndexOf("missing", StringComparison.OrdinalIgnoreCase) >= 0) ||
                HasTag(session.SessionActivities, "service_activity", "transient_sys"))
            {
                score.Add(0.10, "post_session_cleanup_or_transient_artifacts");
            }

            if (session.CleanupTraces.Count > 0)
            {
                score.Add(Math.Min(0.22, session.CleanupTraces.Max(t => t.ConfidenceScore) * 0.22), "cleanup_phase_detected_after_session");
            }

            return score;
        }

        private string WriteLaunchSessionReport(
            LaunchIdentitySession session,
            string phase,
            Dictionary<string, string> current,
            Dictionary<string, string> baseline,
            Dictionary<string, string> previous,
            List<RelatedActivity> related,
            List<HwidSpooferProfile> profiles)
        {
            string folder = GetSessionFolder(session);
            Directory.CreateDirectory(folder);
            string path = Path.Combine(folder, "launch-session-" + SanitizeFileName(phase) + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff", CultureInfo.InvariantCulture) + ".json");
            SpoofSessionScore score = ScoreLaunchSession(session);

            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "case_id", session.CaseId, ref first);
            JsonUtilities.AppendStringProperty(builder, "phase", phase, ref first);
            JsonUtilities.AppendStringProperty(builder, "process_name", session.ProcessName, ref first);
            JsonUtilities.AppendNumberProperty(builder, "process_id", session.ProcessId.ToString(CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "process_path", session.ProcessPath, ref first);
            JsonUtilities.AppendStringProperty(builder, "command_line", session.CommandLine, ref first);
            JsonUtilities.AppendStringProperty(builder, "launch_time_utc", session.LaunchTimeUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "exit_time_utc", session.ExitTimeUtc.HasValue ? session.ExitTimeUtc.Value.ToString("o", CultureInfo.InvariantCulture) : string.Empty, ref first);
            JsonUtilities.AppendNumberProperty(builder, "confidence_score", score.Score.ToString("0.00", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "score_reasons", string.Join(";", score.Reasons.OrderBy(v => v).ToArray()), ref first);
            JsonUtilities.AppendStringProperty(builder, "suspected_spoofer_profile", InferSessionProfile(session, profiles), ref first);
            JsonUtilities.AppendStringProperty(builder, "launch_snapshot_path", session.LaunchSnapshotPath, ref first);
            JsonUtilities.AppendStringProperty(builder, "last_runtime_snapshot_path", session.LastRuntimeSnapshotPath, ref first);
            JsonUtilities.AppendStringProperty(builder, "exit_snapshot_path", session.ExitSnapshotPath, ref first);
            JsonUtilities.AppendStringProperty(builder, "boot_snapshot_path", _bootSnapshotPath, ref first);
            JsonUtilities.AppendStringProperty(builder, "pre_launch_diff", FormatProfileDiff(session.BaselineDiffs), ref first);
            JsonUtilities.AppendStringProperty(builder, "last_boot_diff", FormatProfileDiff(session.LastBootDiffs), ref first);
            JsonUtilities.AppendStringProperty(builder, "runtime_diff", FormatProfileDiff(session.RuntimeDiffs), ref first);
            JsonUtilities.AppendStringProperty(builder, "post_launch_diff", FormatProfileDiff(session.PostLaunchDiffs), ref first);
            JsonUtilities.AppendStringProperty(builder, "reverted_identifiers", FormatProfileDiff(session.RevertedDiffs), ref first);
            JsonUtilities.AppendStringProperty(builder, "cleanup_phase", FormatCleanupTraces(session.CleanupTraces), ref first);
            JsonUtilities.AppendStringProperty(builder, "session_timeline", FormatSessionTimeline(session), ref first);
            JsonUtilities.AppendStringProperty(builder, "related_artifacts", FormatRelatedArtifacts(session, profiles), ref first);
            JsonUtilities.AppendStringProperty(builder, "case_links", session.CaseId + ";" + string.Join(";", profiles.SelectMany(p => p.CaseLinks).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()), ref first);
            AppendCleanupTraces(builder, session.CleanupTraces, ref first);
            AppendProfiles(builder, profiles, ref first);
            AppendChangedValues(builder, current, baseline, previous, ref first);
            AppendRelatedActivities(builder, related, ref first);
            builder.Append("}");
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
            session.LastReportPath = path;
            return path;
        }

        private void EmitLaunchSessionEvent(
            string action,
            EventSeverity severity,
            string description,
            LaunchIdentitySession session,
            string reportPath,
            Dictionary<string, string> details)
        {
            Dictionary<string, string> eventDetails = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "case_id", session.CaseId },
                { "launch_session_case_id", session.CaseId },
                { "process_name", session.ProcessName ?? string.Empty },
                { "process_id", session.ProcessId.ToString(CultureInfo.InvariantCulture) },
                { "process_path", session.ProcessPath ?? string.Empty },
                { "command_line", session.CommandLine ?? string.Empty },
                { "launch_time_utc", session.LaunchTimeUtc.ToString("o", CultureInfo.InvariantCulture) },
                { "launch_snapshot_path", session.LaunchSnapshotPath ?? string.Empty },
                { "exit_snapshot_path", session.ExitSnapshotPath ?? string.Empty },
                { "evidence_report", reportPath ?? string.Empty },
                { "safety_rule", "Pre/post launch HWID auditing is evidence-only and does not alter processes, drivers, or identity values." }
            };

            if (details != null)
            {
                foreach (KeyValuePair<string, string> pair in details)
                {
                    eventDetails[pair.Key] = pair.Value ?? string.Empty;
                }
            }

            _logger.Log(DetectionEvent.Create(
                "HardwareIdentityIntegrity",
                action,
                severity,
                description,
                reportPath,
                null,
                eventDetails));
        }

        private string GetSessionFolder(LaunchIdentitySession session)
        {
            return Path.Combine(_sessionRoot, SanitizeFileName(session == null ? "unknown" : session.CaseId));
        }

        private string WriteSnapshot(HardwareIdentitySnapshot snapshot, List<IdentityValue> values, Dictionary<string, string> current, string stage)
        {
            string stamp = snapshot.TimestampUtc.ToString("yyyyMMdd-HHmmssfff", CultureInfo.InvariantCulture);
            string path = Path.Combine(_snapshotRoot, "hwid-snapshot-" + stamp + "-" + SanitizeFileName(stage) + ".json");
            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "timestamp_utc", snapshot.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "stage", stage, ref first);
            JsonUtilities.AppendNumberProperty(builder, "identity_value_count", current.Count.ToString(CultureInfo.InvariantCulture), ref first);
            AppendSnapshotCounts(builder, snapshot, ref first);
            AppendIdentityValues(builder, values, ref first);
            builder.Append("}");
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
            return path;
        }

        private string WriteReport(
            HardwareIdentitySnapshot snapshot,
            List<HwidIntegrityFinding> findings,
            List<HwidSpooferProfile> profiles,
            List<HardwareChangeAttribution> attributions,
            List<SpooferCleanupTrace> cleanupTraces,
            Dictionary<string, string> current,
            Dictionary<string, string> baseline,
            Dictionary<string, string> previous,
            bool hadBaseline,
            bool hadLast,
            List<RelatedActivity> related,
            string snapshotPath)
        {
            string stamp = snapshot.TimestampUtc.ToString("yyyyMMdd-HHmmssfff", CultureInfo.InvariantCulture);
            string path = Path.Combine(_reportRoot, "hwid-integrity-" + stamp + "-" + SanitizeFileName(snapshot.Stage ?? "snapshot") + ".json");
            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "timestamp_utc", snapshot.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "stage", snapshot.Stage, ref first);
            JsonUtilities.AppendStringProperty(builder, "snapshot_path", snapshotPath, ref first);
            JsonUtilities.AppendStringProperty(builder, "first_seen_baseline_existed", hadBaseline.ToString(), ref first);
            JsonUtilities.AppendStringProperty(builder, "last_seen_existed", hadLast.ToString(), ref first);
            JsonUtilities.AppendNumberProperty(builder, "finding_count", findings.Count.ToString(CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendNumberProperty(builder, "profile_count", profiles.Count.ToString(CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendNumberProperty(builder, "attribution_count", attributions.Count.ToString(CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendNumberProperty(builder, "cleanup_trace_count", cleanupTraces.Count.ToString(CultureInfo.InvariantCulture), ref first);
            AppendSnapshotCounts(builder, snapshot, ref first);
            AppendFindings(builder, findings, ref first);
            AppendProfiles(builder, profiles, ref first);
            AppendAttributions(builder, attributions, ref first);
            AppendCleanupTraces(builder, cleanupTraces, ref first);
            AppendChangedValues(builder, current, baseline, previous, ref first);
            AppendRelatedActivities(builder, related, ref first);
            builder.Append("}");
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
            return path;
        }

        private static void AppendSnapshotCounts(StringBuilder builder, HardwareIdentitySnapshot snapshot, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"snapshot_counts\":{");
            bool child = true;
            JsonUtilities.AppendNumberProperty(builder, "disk_records", snapshot.Disks.Count.ToString(CultureInfo.InvariantCulture), ref child);
            JsonUtilities.AppendNumberProperty(builder, "volume_records", snapshot.Volumes.Count.ToString(CultureInfo.InvariantCulture), ref child);
            JsonUtilities.AppendNumberProperty(builder, "mounted_device_records", snapshot.MountedDevices.Count.ToString(CultureInfo.InvariantCulture), ref child);
            JsonUtilities.AppendNumberProperty(builder, "network_records", snapshot.NetworkAdapters.Count.ToString(CultureInfo.InvariantCulture), ref child);
            JsonUtilities.AppendNumberProperty(builder, "system_records", snapshot.SystemIdentities.Count.ToString(CultureInfo.InvariantCulture), ref child);
            JsonUtilities.AppendNumberProperty(builder, "gpu_records", snapshot.Gpus.Count.ToString(CultureInfo.InvariantCulture), ref child);
            JsonUtilities.AppendNumberProperty(builder, "tpm_records", snapshot.Tpms.Count.ToString(CultureInfo.InvariantCulture), ref child);
            JsonUtilities.AppendNumberProperty(builder, "monitor_records", snapshot.Monitors.Count.ToString(CultureInfo.InvariantCulture), ref child);
            JsonUtilities.AppendNumberProperty(builder, "device_stack_records", snapshot.Devices.Count.ToString(CultureInfo.InvariantCulture), ref child);
            builder.Append("}");
            first = false;
        }

        private static void AppendIdentityValues(StringBuilder builder, IEnumerable<IdentityValue> values, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"identity_values\":[");
            bool firstValue = true;
            foreach (IdentityValue value in values.OrderBy(v => v.Key, StringComparer.OrdinalIgnoreCase))
            {
                if (!firstValue) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "key", value.Key, ref child);
                JsonUtilities.AppendStringProperty(builder, "identifier_type", value.IdentifierType, ref child);
                JsonUtilities.AppendStringProperty(builder, "source", value.Source, ref child);
                JsonUtilities.AppendStringProperty(builder, "entity", value.Entity, ref child);
                JsonUtilities.AppendStringProperty(builder, "value", value.Value, ref child);
                JsonUtilities.AppendStringProperty(builder, "session_sensitive", value.SessionSensitive.ToString(), ref child);
                builder.Append("}");
                firstValue = false;
            }
            builder.Append("]");
            first = false;
        }

        private static void AppendFindings(StringBuilder builder, IEnumerable<HwidIntegrityFinding> findings, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"findings\":[");
            bool firstFinding = true;
            foreach (HwidIntegrityFinding finding in findings)
            {
                if (!firstFinding) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "action", finding.Action, ref child);
                JsonUtilities.AppendStringProperty(builder, "severity", finding.Severity.ToString(), ref child);
                JsonUtilities.AppendStringProperty(builder, "description", finding.Description, ref child);
                JsonUtilities.AppendStringProperty(builder, "identifier_type", finding.IdentifierType, ref child);
                JsonUtilities.AppendStringProperty(builder, "identity_key", finding.IdentityKey, ref child);
                JsonUtilities.AppendStringProperty(builder, "source", finding.Source, ref child);
                JsonUtilities.AppendStringProperty(builder, "entity", finding.Entity, ref child);
                JsonUtilities.AppendStringProperty(builder, "baseline_value", finding.BaselineValue, ref child);
                JsonUtilities.AppendStringProperty(builder, "previous_value", finding.PreviousValue, ref child);
                JsonUtilities.AppendStringProperty(builder, "current_value", finding.CurrentValue, ref child);
                JsonUtilities.AppendNumberProperty(builder, "confidence_score", finding.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture), ref child);
                JsonUtilities.AppendStringProperty(builder, "correlation_tags", string.Join(";", finding.CorrelationTags.OrderBy(t => t).ToArray()), ref child);
                builder.Append("}");
                firstFinding = false;
            }
            builder.Append("]");
            first = false;
        }

        private static void AppendProfiles(StringBuilder builder, IEnumerable<HwidSpooferProfile> profiles, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"spoofer_profiles\":[");
            bool firstProfile = true;
            foreach (HwidSpooferProfile profile in profiles)
            {
                if (!firstProfile) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "profile_name", profile.ProfileName, ref child);
                JsonUtilities.AppendStringProperty(builder, "case_id", profile.CaseId, ref child);
                JsonUtilities.AppendStringProperty(builder, "severity", profile.Severity.ToString(), ref child);
                JsonUtilities.AppendNumberProperty(builder, "confidence_score", profile.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture), ref child);
                JsonUtilities.AppendStringProperty(builder, "matched_indicators", string.Join(";", profile.MatchedIndicators.OrderBy(v => v).ToArray()), ref child);
                JsonUtilities.AppendStringProperty(builder, "before_after_identity_diff", FormatProfileDiff(profile.Diffs), ref child);
                JsonUtilities.AppendStringProperty(builder, "related_processes_drivers_services", string.Join(";", profile.RelatedArtifacts.OrderBy(v => v).Take(60).ToArray()), ref child);
                JsonUtilities.AppendStringProperty(builder, "evidence_timeline", string.Join(" || ", profile.EvidenceTimeline.Take(40).ToArray()), ref child);
                JsonUtilities.AppendStringProperty(builder, "case_links", string.Join(";", profile.CaseLinks.OrderBy(v => v).ToArray()), ref child);
                builder.Append("}");
                firstProfile = false;
            }
            builder.Append("]");
            first = false;
        }

        private static void AppendAttributions(StringBuilder builder, IEnumerable<HardwareChangeAttribution> attributions, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"hardware_change_attribution\":[");
            bool firstAttribution = true;
            foreach (HardwareChangeAttribution attribution in attributions)
            {
                if (!firstAttribution) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "case_id", attribution.CaseId, ref child);
                JsonUtilities.AppendStringProperty(builder, "stage", attribution.Stage, ref child);
                JsonUtilities.AppendStringProperty(builder, "changed_identifier", attribution.IdentityKey, ref child);
                JsonUtilities.AppendStringProperty(builder, "identifier_type", attribution.IdentifierType, ref child);
                JsonUtilities.AppendStringProperty(builder, "old_value", attribution.OldValue, ref child);
                JsonUtilities.AppendStringProperty(builder, "new_value", attribution.NewValue, ref child);
                JsonUtilities.AppendStringProperty(builder, "suspected_cause", attribution.SuspectedCause, ref child);
                JsonUtilities.AppendStringProperty(builder, "related_process", attribution.RelatedProcess, ref child);
                JsonUtilities.AppendStringProperty(builder, "related_driver_service", attribution.RelatedDriverService, ref child);
                JsonUtilities.AppendStringProperty(builder, "related_registry_key", attribution.RelatedRegistryKey, ref child);
                JsonUtilities.AppendStringProperty(builder, "related_device_event", attribution.RelatedDeviceEvent, ref child);
                JsonUtilities.AppendNumberProperty(builder, "confidence_score", attribution.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture), ref child);
                JsonUtilities.AppendStringProperty(builder, "matched_signals", string.Join(";", attribution.MatchedSignals.OrderBy(v => v).ToArray()), ref child);
                JsonUtilities.AppendStringProperty(builder, "evidence_timeline", string.Join(" || ", attribution.EvidenceTimeline.Take(40).ToArray()), ref child);
                builder.Append("}");
                firstAttribution = false;
            }

            builder.Append("]");
            first = false;
        }

        private static void AppendCleanupTraces(StringBuilder builder, IEnumerable<SpooferCleanupTrace> traces, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"spoofer_cleanup_traces\":[");
            bool firstTrace = true;
            foreach (SpooferCleanupTrace trace in traces)
            {
                if (!firstTrace) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "case_id", trace.CaseId, ref child);
                JsonUtilities.AppendStringProperty(builder, "phase", trace.Phase, ref child);
                JsonUtilities.AppendStringProperty(builder, "summary", trace.Summary, ref child);
                JsonUtilities.AppendStringProperty(builder, "severity", trace.Severity.ToString(), ref child);
                JsonUtilities.AppendNumberProperty(builder, "confidence_score", trace.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture), ref child);
                JsonUtilities.AppendStringProperty(builder, "reverted_identifiers", string.Join("; ", trace.RevertedIdentifiers.Take(20).ToArray()), ref child);
                JsonUtilities.AppendStringProperty(builder, "deleted_artifacts", string.Join("; ", trace.DeletedArtifacts.Take(30).ToArray()), ref child);
                JsonUtilities.AppendStringProperty(builder, "cleanup_actions", string.Join("; ", trace.CleanupActions.Take(30).ToArray()), ref child);
                JsonUtilities.AppendStringProperty(builder, "matched_signals", string.Join(";", trace.MatchedSignals.OrderBy(v => v).ToArray()), ref child);
                JsonUtilities.AppendStringProperty(builder, "timeline", string.Join(" || ", trace.Timeline.Take(60).ToArray()), ref child);
                builder.Append("}");
                firstTrace = false;
            }

            builder.Append("]");
            first = false;
        }

        private static void AppendChangedValues(StringBuilder builder, Dictionary<string, string> current, Dictionary<string, string> baseline, Dictionary<string, string> previous, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"baseline_diff\":[");
            bool firstItem = true;
            foreach (KeyValuePair<string, string> pair in current.OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase))
            {
                string baselineValue;
                string previousValue;
                bool changed = baseline.TryGetValue(pair.Key, out baselineValue) && !NormalizedEquals(baselineValue, pair.Value);
                bool runtimeChanged = previous.TryGetValue(pair.Key, out previousValue) && !NormalizedEquals(previousValue, pair.Value);
                bool appeared = !baseline.ContainsKey(pair.Key);
                if (!changed && !runtimeChanged && !appeared)
                {
                    continue;
                }

                if (!firstItem) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "key", pair.Key, ref child);
                JsonUtilities.AppendStringProperty(builder, "baseline_value", baselineValue, ref child);
                JsonUtilities.AppendStringProperty(builder, "previous_value", previousValue, ref child);
                JsonUtilities.AppendStringProperty(builder, "current_value", pair.Value, ref child);
                JsonUtilities.AppendStringProperty(builder, "changed_from_baseline", changed.ToString(), ref child);
                JsonUtilities.AppendStringProperty(builder, "runtime_changed", runtimeChanged.ToString(), ref child);
                JsonUtilities.AppendStringProperty(builder, "appeared_after_baseline", appeared.ToString(), ref child);
                builder.Append("}");
                firstItem = false;
            }
            builder.Append("]");
            first = false;
        }

        private static void AppendRelatedActivities(StringBuilder builder, IEnumerable<RelatedActivity> activities, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"related_activity\":[");
            bool firstActivity = true;
            foreach (RelatedActivity activity in activities)
            {
                if (!firstActivity) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "timestamp_utc", activity.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref child);
                JsonUtilities.AppendStringProperty(builder, "category", activity.Category, ref child);
                JsonUtilities.AppendStringProperty(builder, "action", activity.Action, ref child);
                JsonUtilities.AppendStringProperty(builder, "severity", activity.Severity.ToString(), ref child);
                JsonUtilities.AppendStringProperty(builder, "description", activity.Description, ref child);
                JsonUtilities.AppendStringProperty(builder, "case_id", activity.CaseId, ref child);
                JsonUtilities.AppendStringProperty(builder, "path", activity.Path, ref child);
                JsonUtilities.AppendStringProperty(builder, "process_id", activity.ProcessId.HasValue ? activity.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : string.Empty, ref child);
                JsonUtilities.AppendStringProperty(builder, "process_name", activity.ProcessName, ref child);
                JsonUtilities.AppendStringProperty(builder, "tags", string.Join(";", activity.Tags.OrderBy(t => t).ToArray()), ref child);
                JsonUtilities.AppendStringProperty(builder, "details_summary", FormatActivityDetails(activity), ref child);
                builder.Append("}");
                firstActivity = false;
            }
            builder.Append("]");
            first = false;
        }

        private void RememberActivity(DetectionEvent detectionEvent)
        {
            RelatedActivity activity = new RelatedActivity
            {
                TimestampUtc = detectionEvent.TimestampUtc,
                Category = detectionEvent.Category,
                Action = detectionEvent.Action,
                Severity = detectionEvent.Severity,
                Description = detectionEvent.Description,
                CaseId = ExtractCaseId(detectionEvent),
                Path = detectionEvent.Path,
                ProcessId = detectionEvent.ProcessId,
                ProcessName = detectionEvent.ProcessName
            };

            if (detectionEvent.Details != null)
            {
                foreach (KeyValuePair<string, string> pair in detectionEvent.Details)
                {
                    activity.Details[pair.Key] = pair.Value ?? string.Empty;
                }
            }

            foreach (string tag in DeriveCorrelationTags(detectionEvent))
            {
                activity.Tags.Add(tag);
            }

            _recentActivity.Enqueue(activity);
            while (_recentActivity.Count > 240)
            {
                RelatedActivity ignored;
                _recentActivity.TryDequeue(out ignored);
            }
        }

        private List<RelatedActivity> RecentActivities(TimeSpan window)
        {
            DateTimeOffset cutoff = DateTimeOffset.UtcNow.Subtract(window);
            return _recentActivity
                .ToArray()
                .Where(a => a.TimestampUtc >= cutoff)
                .OrderBy(a => a.TimestampUtc)
                .Take(40)
                .ToList();
        }

        private List<RelatedActivity> RecentActivities(DateTimeOffset fromUtc, DateTimeOffset toUtc)
        {
            return _recentActivity
                .ToArray()
                .Where(a => a.TimestampUtc >= fromUtc && a.TimestampUtc <= toUtc)
                .OrderBy(a => a.TimestampUtc)
                .Take(80)
                .ToList();
        }

        private static bool IsCorrelationActivity(DetectionEvent detectionEvent)
        {
            if (detectionEvent.Severity >= EventSeverity.High)
            {
                return true;
            }

            string text = EventText(detectionEvent);
            return ContainsAny(text,
                "hiddenkernel",
                "hidden kernel",
                "vulnerable driver",
                "mapper",
                "manual_map",
                "device object",
                "\\device\\",
                ".sys",
                "service",
                "driver",
                "registry",
                "hardware",
                "short-lived",
                "shortlived",
                "cleanup",
                "deleted",
                "auditlogcleared",
                "eventlogcleared",
                "wevtutil",
                "prefetch",
                "amcache",
                "shimcache",
                "networkaddress",
                "mounteddevices",
                "class\\{4d36e972",
                "hwid");
        }

        private static IEnumerable<string> DeriveCorrelationTags(DetectionEvent detectionEvent)
        {
            string text = EventText(detectionEvent);
            if (ContainsAny(text, "hiddenkernel", "hidden kernel", "hidden_driver")) yield return "hidden_kernel_indicator";
            if (ContainsAny(text, "vulnerable driver", "iqvw", "gdrv", "capcom", "dbutil", "rtcore", "winio", "kdu")) yield return "vulnerable_driver";
            if (ContainsAny(text, "mapper", "manual_map", "manual map", "kdmapper", "drvmap")) yield return "mapper_behavior";
            if (ContainsAny(text, ".sys", "driver file", "transient", "created/deleted driver", "short-lived")) yield return "transient_sys";
            if (ContainsAny(text, "shortlivedstagingfiledeleted", "short-lived staging artifact", "short_lived_staging_artifact_deleted")) yield return "short_lived_staging_file";
            if (ContainsAny(text, "driverloaded", "driver loaded", "codeintegrity", "service control manager")) yield return "driver_load_event";
            if (ContainsAny(text, "serviceinstalled", "service installed", "7045", "sc.exe create")) yield return "driver_service_created";
            if (ContainsAny(text, "serviceremoved", "service deleted", "delete service", "sc.exe delete")) yield return "driver_service_deleted";
            if (ContainsAny(text, "service", "7045", "serviceinstalled", "serviceremoved", "scm")) yield return "service_activity";
            if (ContainsAny(text, "service deleted", "service removed", "sc.exe delete", "keydeleted", "services\\", "serviceremoved")) yield return "service_cleanup";
            if (ContainsAny(text, "\\device\\", "device object", "new visible device", "device handle")) yield return "device_object";
            if (ContainsAny(text, "object_type device", "suspiciousdevicehandle", "suspiciousdeviceobjecthandle")) yield return "device_handle";
            if (ContainsAny(text, "section", "shared section", "shared memory", "writableexecutablesection")) yield return "section_object";
            if (ContainsAny(text, "networkaddress", "adapter", "mac", "class\\{4d36e972")) yield return "network_identity_registry";
            if (ContainsAny(text, "mounteddevices", "usbstor", "storage", "disk")) yield return "storage_identity_registry";
            if (ContainsAny(text, "machineguid", "cryptography\\machineguid")) yield return "machine_guid_registry";
            if (ContainsAny(text, "windows nt\\currentversion", "productid", "installationid", "digitalproductid")) yield return "windows_identity_registry";
            if (ContainsAny(text, "hardware\\description\\system", "system\\bios", "smbios", "baseboard")) yield return "hardware_identity_registry";
            if (ContainsAny(text, "system\\currentcontrolset\\enum", "pnp", "device install", "device remove", "device configured", "device started")) yield return "pnp_device_event";
            if (ContainsAny(text, "reset", "disabled", "enabled", "disconnect", "reconnect", "adapter reset", "device restarted")) yield return "adapter_reset";
            if (ContainsAny(text, "storage reset", "disk reset", "stornvme", "storahci", "disk surprise removal")) yield return "storage_reset";
            if (ContainsAny(text, "virtual adapter", "tap-windows", "wireguard", "tailscale", "zerotier", "hyper-v", "vmware", "virtualbox")) yield return "virtual_adapter_or_hypervisor";
            if (ContainsAny(text, "protected", "game", "targetinteraction")) yield return "protected_runtime_related";
            if (ContainsAny(text, "unsigned", "untrusted", "not trusted", "invalid signature", "signature_status untrusted", "signature_status unsigned", "untrustedorinvalid")) yield return "unsigned_or_untrusted_binary";
            if (ContainsAny(text, "\\temp\\", "\\appdata\\", "\\downloads\\", "\\desktop\\", "is_download_location true", "mark_of_the_web")) yield return "user_writable_location";
            if (ContainsAny(text, "integrity high", "elevated true", "administrator", "runas", "uac")) yield return "admin_or_elevated";
            if (ContainsAny(text, "devcon", "pnputil", "netsh", "restart-netadapter", "disable-netadapter", "enable-netadapter", "wmic nic", "set-netadapteradvancedproperty")) yield return "hardware_control_command";
            if (ContainsAny(text, "auditlogcleared", "eventlogcleared", "wevtutil cl", "clear-eventlog")) yield return "event_log_cleared";
            if (ContainsAny(text, "prefetch", "amcache", "shimcache", "recentfilecache", "usn deletejournal", "deletejournal", "srum", "jumplist")) yield return "trace_wipe";
            if (ContainsAny(text, "shortlived", "short-lived", "cleanup_indicator", "deleted", "remove", "cleanup", "self-delete", "delete temp")) yield return "cleanup_behavior";
            if (ContainsAny(text, "self-delete", "delete self", "process exited", "file deleted") && ContainsAny(text, ".exe", ".dll", ".ps1", ".bat", ".cmd")) yield return "self_delete_behavior";
        }

        private void EmitHardwareApiProbe(DetectionEvent source)
        {
            string key = "probe|" + source.ProcessId + "|" + source.TimestampUtc.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
            lock (_reportedKeys)
            {
                if (!_reportedKeys.Add(key))
                {
                    return;
                }
            }

            _logger.Log(DetectionEvent.Create(
                "HardwareIdentityIntegrity",
                "SuspiciousHardwareIdentityApiProbe",
                EventSeverity.Medium,
                "Process command line indicates hardware identity enumeration or device-stack manipulation.",
                source.Path,
                null,
                new Dictionary<string, string>
                {
                    { "source_process_name", source.ProcessName ?? string.Empty },
                    { "source_process_id", source.ProcessId.HasValue ? source.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : string.Empty },
                    { "source_path", source.Path ?? string.Empty },
                    { "command_line", Detail(source, "command_line") },
                    { "case_id", ExtractCaseId(source) },
                    { "confidence_score", "0.60" },
                    { "safety_rule", "Observation only; no process interference." }
                }));
        }

        private static bool LooksLikeHardwareIdentityApiProbe(DetectionEvent detectionEvent)
        {
            if (!IsProcessStartEvent(detectionEvent))
            {
                return false;
            }

            string command = Detail(detectionEvent, "command_line");
            if (string.IsNullOrWhiteSpace(command))
            {
                return false;
            }

            bool identityQuery = ContainsAny(command,
                "Win32_DiskDrive",
                "Win32_BIOS",
                "Win32_BaseBoard",
                "Win32_ComputerSystemProduct",
                "Win32_NetworkAdapter",
                "WmiMonitorID",
                "Win32_Tpm",
                "GetSystemFirmwareTable",
                "GetAdaptersAddresses",
                "IOCTL_STORAGE_QUERY_PROPERTY",
                "GetVolumeInformation",
                "wmic diskdrive",
                "wmic bios",
                "wmic baseboard",
                "wmic csproduct",
                "Get-CimInstance",
                "Get-WmiObject",
                "pnputil",
                "devcon",
                "NetworkAddress");

            if (!identityQuery)
            {
                return false;
            }

            string path = detectionEvent.Path ?? string.Empty;
            return detectionEvent.Severity >= EventSeverity.Medium ||
                   FileClassifier.IsLikelyDownloadLocation(path) ||
                   ContainsAny(command, "spoof", "serial", "hwid", "mac", "NetworkAddress", "devcon", "pnputil");
        }

        private static bool IsHardwareRegistryChange(DetectionEvent detectionEvent)
        {
            if (!detectionEvent.Category.Equals("Registry", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string text = EventText(detectionEvent);
            return ContainsAny(text,
                "system\\currentcontrolset\\enum",
                "system\\mounteddevices",
                "system\\currentcontrolset\\control\\class",
                "networkaddress",
                "hardware\\description\\system",
                "cryptography\\machineguid",
                "windows nt\\currentversion\\productid",
                "windows nt\\currentversion\\installationid",
                "tcpip\\parameters");
        }

        private bool IsProtectedProcessEvent(DetectionEvent detectionEvent)
        {
            string name = detectionEvent.ProcessName;
            if (string.IsNullOrWhiteSpace(name))
            {
                name = Detail(detectionEvent, "process_name");
            }

            if (string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(detectionEvent.Path))
            {
                name = Path.GetFileName(detectionEvent.Path);
            }

            return !string.IsNullOrWhiteSpace(name) && TargetProcessMatcher.IsProtectedProcessName(name, _options.ProtectedProcessNames);
        }

        private static bool IsProcessStartEvent(DetectionEvent detectionEvent)
        {
            return detectionEvent.Action.IndexOf("Executed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   detectionEvent.Action.IndexOf("Created", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   detectionEvent.Action.IndexOf("Started", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsProcessExitEvent(DetectionEvent detectionEvent)
        {
            return detectionEvent.Action.IndexOf("Exited", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool HasActiveProtectedProcess()
        {
            lock (_activeProtectedProcesses)
            {
                return _activeProtectedProcesses.Count > 0;
            }
        }

        private static bool HasSuspiciousContext(List<RelatedActivity> related, bool protectedRuntime)
        {
            return protectedRuntime || related.Any(a => a.Tags.Count > 0);
        }

        private static bool HasTag(IEnumerable<RelatedActivity> related, params string[] tags)
        {
            if (related == null || tags == null)
            {
                return false;
            }

            foreach (RelatedActivity activity in related)
            {
                foreach (string tag in tags)
                {
                    if (activity.Tags.Contains(tag))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static List<SpooferCleanupTrace> BuildSnapshotCleanupTraces(
            List<HwidIntegrityFinding> findings,
            List<RelatedActivity> related,
            string stage,
            bool protectedRuntime)
        {
            List<ProfileDiff> reverted = findings
                .Where(f => f.Action.Equals("HardwareIdentifierRevertedToBaseline", StringComparison.OrdinalIgnoreCase))
                .Select(ProfileDiff.FromFinding)
                .ToList();

            List<RelatedActivity> cleanupActivities = related
                .Where(IsCleanupActivity)
                .OrderBy(a => a.TimestampUtc)
                .ToList();
            bool registryRestore = ContainsRegistryRestorePattern(related);

            bool spoofContext = protectedRuntime ||
                                registryRestore ||
                                reverted.Count > 0 ||
                                findings.Any(IsIdentityChangeFinding) ||
                                HasTag(related, "hidden_kernel_indicator", "vulnerable_driver", "mapper_behavior", "transient_sys", "service_activity", "hardware_identity_registry", "network_identity_registry", "storage_identity_registry", "machine_guid_registry", "protected_runtime_related");

            if (!spoofContext || (reverted.Count == 0 && cleanupActivities.Count == 0 && !registryRestore))
            {
                return new List<SpooferCleanupTrace>();
            }

            SpooferCleanupTrace trace = BuildCleanupTrace(
                "snapshot_cleanup",
                BuildCaseId("cleanup|" + stage + "|" + FormatProfileDiff(reverted)),
                reverted,
                cleanupActivities,
                related,
                null,
                stage,
                false);

            return trace.ConfidenceScore >= 0.40 ? new List<SpooferCleanupTrace> { trace } : new List<SpooferCleanupTrace>();
        }

        private static List<SpooferCleanupTrace> BuildLaunchSessionCleanupTraces(
            LaunchIdentitySession session,
            List<HwidIntegrityFinding> findings,
            List<RelatedActivity> sessionActivities)
        {
            if (session == null)
            {
                return new List<SpooferCleanupTrace>();
            }

            DateTimeOffset cleanupStart = session.ExitTimeUtc.HasValue
                ? session.ExitTimeUtc.Value.Subtract(TimeSpan.FromMinutes(2))
                : DateTimeOffset.UtcNow.Subtract(TimeSpan.FromMinutes(5));

            List<RelatedActivity> cleanupActivities = sessionActivities
                .Where(a => a.TimestampUtc >= cleanupStart || IsHighValueCleanupActivity(a))
                .Where(IsCleanupActivity)
                .OrderBy(a => a.TimestampUtc)
                .ToList();
            bool registryRestore = ContainsRegistryRestorePattern(sessionActivities);

            List<ProfileDiff> reverted = new List<ProfileDiff>();
            foreach (ProfileDiff diff in session.RevertedDiffs)
            {
                AddUniqueDiff(reverted, diff);
            }

            foreach (HwidIntegrityFinding finding in findings.Where(f => f.Action.Equals("HardwareIdentifierRevertedToBaseline", StringComparison.OrdinalIgnoreCase)))
            {
                AddUniqueDiff(reverted, ProfileDiff.FromFinding(finding));
            }

            bool sessionHadSpoofingContext = session.BaselineDiffs.Count > 0 ||
                                             session.RuntimeDiffs.Count > 0 ||
                                             session.ObservedProfiles.Count > 0 ||
                                             registryRestore ||
                                             HasTag(session.PreLaunchActivities, "mapper_behavior", "vulnerable_driver", "transient_sys", "service_activity", "device_object", "hardware_identity_registry", "network_identity_registry", "storage_identity_registry", "machine_guid_registry");

            if (!sessionHadSpoofingContext || (reverted.Count == 0 && cleanupActivities.Count == 0 && !registryRestore))
            {
                return new List<SpooferCleanupTrace>();
            }

            SpooferCleanupTrace trace = BuildCleanupTrace(
                "post_exit_cleanup",
                session.CaseId,
                reverted,
                cleanupActivities,
                session.PreLaunchActivities.Concat(session.SessionActivities).ToList(),
                session,
                "PostLaunchIdentityAudit",
                true);

            return trace.ConfidenceScore >= 0.42 ? new List<SpooferCleanupTrace> { trace } : new List<SpooferCleanupTrace>();
        }

        private static SpooferCleanupTrace BuildCleanupTrace(
            string phase,
            string caseId,
            List<ProfileDiff> reverted,
            List<RelatedActivity> cleanupActivities,
            List<RelatedActivity> allActivities,
            LaunchIdentitySession session,
            string stage,
            bool protectedExit)
        {
            SpooferCleanupTrace trace = new SpooferCleanupTrace
            {
                CaseId = caseId ?? string.Empty,
                Phase = phase ?? string.Empty,
                Stage = stage ?? string.Empty
            };

            foreach (ProfileDiff diff in reverted.Take(24))
            {
                trace.RevertedIdentifiers.Add(diff.IdentifierType + " key=" + Trim(diff.IdentityKey, 90) +
                    " old=" + Trim(FirstNonEmpty(diff.PreviousValue, diff.BaselineValue, "missing"), 70) +
                    " new=" + Trim(diff.CurrentValue, 70));
            }

            foreach (RelatedActivity activity in cleanupActivities.Take(40))
            {
                string action = activity.Category + "/" + activity.Action + " " + Trim(activity.Description, 160);
                trace.CleanupActions.Add(action);
                if (IsDeletedArtifactActivity(activity))
                {
                    trace.DeletedArtifacts.Add(DescribeDeletedArtifact(activity));
                }

                trace.Timeline.Add(activity.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + " cleanup " + action);
            }

            if (session != null)
            {
                foreach (RelatedActivity activity in session.PreLaunchActivities.Take(12))
                {
                    trace.Timeline.Add(activity.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + " pre-launch " + activity.Category + "/" + activity.Action + " " + Trim(activity.Description, 140));
                }

                foreach (ProfileDiff diff in session.RuntimeDiffs.Take(12))
                {
                    trace.Timeline.Add("runtime spoofed identifier active " + diff.IdentifierType + " " + Trim(diff.IdentityKey, 90));
                }
            }

            double score = 0.18;
            if (reverted.Count > 0)
            {
                score += 0.28;
                trace.MatchedSignals.Add("reverted_identity_values");
            }

            if (protectedExit)
            {
                score += 0.10;
                trace.MatchedSignals.Add("cleanup_after_protected_process_exit");
            }

            if (cleanupActivities.Any(a => HasActivityTag(a, "short_lived_staging_file", "transient_sys")))
            {
                score += 0.16;
                trace.MatchedSignals.Add("short_lived_deleted_artifact");
            }

            if (cleanupActivities.Any(a => HasActivityTag(a, "service_cleanup", "driver_service_deleted") || ContainsAny(a.Action, "ServiceRemoved", "ServiceDeleted", "KeyDeleted")))
            {
                score += 0.14;
                trace.MatchedSignals.Add("service_deleted_after_driver_behavior");
            }

            if (cleanupActivities.Any(a => HasActivityTag(a, "event_log_cleared", "trace_wipe") || ContainsAny(a.Action, "AuditLogCleared", "EventLogCleared")))
            {
                score += 0.22;
                trace.MatchedSignals.Add("event_or_trace_logs_cleared");
            }

            if (cleanupActivities.Any(a => HasActivityTag(a, "adapter_reset")))
            {
                score += 0.10;
                trace.MatchedSignals.Add("adapter_disable_enable_or_reset");
            }

            if (cleanupActivities.Any(a => HasActivityTag(a, "self_delete_behavior")))
            {
                score += 0.10;
                trace.MatchedSignals.Add("self_delete_or_deleted_loader");
            }

            if (cleanupActivities.Any(a => DeletedArtifactMatchesPriorSuspiciousHash(a, allActivities)))
            {
                score += 0.14;
                trace.MatchedSignals.Add("deleted_file_hash_seen_in_prior_suspicious_signal");
            }

            if (cleanupActivities.Any(a => CleanupHappenedSoonAfterExit(a, session)))
            {
                score += 0.12;
                trace.MatchedSignals.Add("cleanup_happened_right_after_game_exit");
            }

            if (DetectRegistryRestorePattern(allActivities, trace))
            {
                score += 0.24;
                trace.MatchedSignals.Add("registry_identity_value_restored");
            }

            if (HasTag(allActivities, "mapper_behavior", "vulnerable_driver", "hidden_kernel_indicator") &&
                cleanupActivities.Any(a => HasActivityTag(a, "transient_sys", "service_cleanup", "driver_service_deleted")))
            {
                score += 0.12;
                trace.MatchedSignals.Add("driver_mapper_activity_then_cleanup");
            }

            trace.ConfidenceScore = Math.Min(0.99, score);
            trace.Severity = SeverityForCleanupTrace(trace);
            trace.Summary = BuildCleanupSummary(trace, session);
            return trace;
        }

        private void EmitCleanupTraceEvents(IEnumerable<SpooferCleanupTrace> traces, string reportPath, string fallbackCaseId)
        {
            foreach (SpooferCleanupTrace trace in traces)
            {
                if (!ShouldEmitCleanupTrace(trace))
                {
                    continue;
                }

                _logger.Log(DetectionEvent.Create(
                    "HardwareIdentityIntegrity",
                    "SpooferCleanupTraceDetected",
                    trace.Severity,
                    trace.Summary,
                    reportPath,
                    null,
                    new Dictionary<string, string>
                    {
                        { "case_id", FirstNonEmpty(trace.CaseId, fallbackCaseId) },
                        { "phase", trace.Phase ?? string.Empty },
                        { "stage", trace.Stage ?? string.Empty },
                        { "confidence_score", trace.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) },
                        { "reverted_identifiers", string.Join("; ", trace.RevertedIdentifiers.Take(20).ToArray()) },
                        { "deleted_artifacts", string.Join("; ", trace.DeletedArtifacts.Take(30).ToArray()) },
                        { "cleanup_actions", string.Join("; ", trace.CleanupActions.Take(30).ToArray()) },
                        { "matched_signals", string.Join(";", trace.MatchedSignals.OrderBy(v => v).ToArray()) },
                        { "cleanup_timeline", string.Join(" || ", trace.Timeline.Take(50).ToArray()) },
                        { "evidence_report", reportPath ?? string.Empty },
                        { "safety_rule", "Spoofer cleanup detection is evidence-only; no files, registry keys, services, adapters, or logs are modified." }
                    }));
            }
        }

        private bool ShouldEmitCleanupTrace(SpooferCleanupTrace trace)
        {
            string key = "cleanup|" + trace.CaseId + "|" + trace.Phase + "|" + trace.Summary + "|" +
                         string.Join(";", trace.MatchedSignals.OrderBy(v => v).ToArray()) + "|" +
                         string.Join(";", trace.RevertedIdentifiers.Take(8).ToArray()) + "|" +
                         string.Join(";", trace.DeletedArtifacts.Take(8).ToArray());
            lock (_reportedKeys)
            {
                return _reportedKeys.Add(key);
            }
        }

        private static EventSeverity SeverityForCleanupTrace(SpooferCleanupTrace trace)
        {
            if (trace.ConfidenceScore >= 0.86) return EventSeverity.Critical;
            if (trace.ConfidenceScore >= 0.62) return EventSeverity.High;
            if (trace.ConfidenceScore >= 0.40) return EventSeverity.Medium;
            return EventSeverity.Low;
        }

        private static string BuildCleanupSummary(SpooferCleanupTrace trace, LaunchIdentitySession session)
        {
            List<string> parts = new List<string>();
            if (session != null)
            {
                parts.Add("post-exit cleanup phase for " + session.ProcessName);
            }
            else
            {
                parts.Add("spoofer cleanup trace");
            }

            if (trace.RevertedIdentifiers.Count > 0)
            {
                parts.Add(trace.RevertedIdentifiers.Count.ToString(CultureInfo.InvariantCulture) + " reverted identifier(s)");
            }

            if (trace.DeletedArtifacts.Count > 0)
            {
                parts.Add(trace.DeletedArtifacts.Count.ToString(CultureInfo.InvariantCulture) + " deleted artifact(s)");
            }

            if (trace.MatchedSignals.Contains("event_or_trace_logs_cleared"))
            {
                parts.Add("event/trace clearing");
            }

            if (trace.MatchedSignals.Contains("service_deleted_after_driver_behavior"))
            {
                parts.Add("service cleanup");
            }

            return string.Join("; ", parts.ToArray()) + ".";
        }

        private static string FormatCleanupTraces(IEnumerable<SpooferCleanupTrace> traces)
        {
            if (traces == null)
            {
                return string.Empty;
            }

            return string.Join("; ", traces
                .OrderByDescending(t => t.ConfidenceScore)
                .Take(8)
                .Select(t => t.Phase + " score=" + t.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) +
                             " signals=" + string.Join("|", t.MatchedSignals.OrderBy(v => v).Take(10).ToArray()) +
                             " summary=" + Trim(t.Summary, 180))
                .ToArray());
        }

        private static bool IsCleanupActivity(RelatedActivity activity)
        {
            if (activity == null)
            {
                return false;
            }

            string text = ActivityText(activity);
            return HasActivityTag(activity,
                       "cleanup_behavior",
                       "trace_wipe",
                       "event_log_cleared",
                       "short_lived_staging_file",
                       "service_cleanup",
                       "driver_service_deleted",
                       "self_delete_behavior") ||
                   ContainsAny(activity.Action,
                       "ShortLivedStagingFileDeleted",
                       "ShortLivedDriverFileDeleted",
                       "DriverFileDeleted",
                       "FileDeleted",
                       "FileDeletedOrModified",
                       "AuditLogCleared",
                       "EventLogCleared",
                       "KeyDeleted",
                       "ValueDeleted",
                       "RegistryObjectCreatedOrDeleted",
                       "RegistryObjectRenamed") ||
                   ContainsAny(text,
                       "service deleted",
                       "service removed",
                       "delete service",
                       "wevtutil cl",
                       "clear-eventlog",
                       "prefetch",
                       "amcache",
                       "shimcache",
                       "recentfilecache",
                       "deletejournal",
                       "self-delete",
                       "cleanup_indicator",
                       "short_lived true");
        }

        private static bool IsHighValueCleanupActivity(RelatedActivity activity)
        {
            return activity != null &&
                   (HasActivityTag(activity, "event_log_cleared", "trace_wipe", "short_lived_staging_file", "transient_sys") ||
                    ContainsAny(activity.Action, "AuditLogCleared", "ShortLived", "DriverFileDeleted"));
        }

        private static bool IsDeletedArtifactActivity(RelatedActivity activity)
        {
            return activity != null &&
                   (ContainsAny(activity.Action, "Deleted", "ShortLived") ||
                    HasActivityTag(activity, "short_lived_staging_file", "transient_sys"));
        }

        private static string DescribeDeletedArtifact(RelatedActivity activity)
        {
            string hash = FirstNonEmpty(ActivityDetail(activity, "sha256"), ActivityDetail(activity, "file_sha256"), ActivityDetail(activity, "driver_sha256"));
            string lifetime = FirstNonEmpty(ActivityDetail(activity, "artifact_lifetime_seconds"), ActivityDetail(activity, "lifetime_seconds"));
            return "path=" + FirstNonEmpty(activity.Path, ActivityDetail(activity, "TargetFilename"), ActivityDetail(activity, "driver_path")) +
                   " action=" + activity.Category + "/" + activity.Action +
                   (string.IsNullOrWhiteSpace(hash) ? string.Empty : " sha256=" + hash) +
                   (string.IsNullOrWhiteSpace(lifetime) ? string.Empty : " lifetime_seconds=" + lifetime);
        }

        private static bool DeletedArtifactMatchesPriorSuspiciousHash(RelatedActivity cleanupActivity, IEnumerable<RelatedActivity> allActivities)
        {
            string hash = FirstNonEmpty(
                ActivityDetail(cleanupActivity, "sha256"),
                ActivityDetail(cleanupActivity, "file_sha256"),
                ActivityDetail(cleanupActivity, "driver_sha256"));
            if (string.IsNullOrWhiteSpace(hash) || allActivities == null)
            {
                return false;
            }

            foreach (RelatedActivity activity in allActivities)
            {
                if (activity == null || activity.TimestampUtc > cleanupActivity.TimestampUtc)
                {
                    continue;
                }

                string otherHash = FirstNonEmpty(
                    ActivityDetail(activity, "sha256"),
                    ActivityDetail(activity, "file_sha256"),
                    ActivityDetail(activity, "driver_sha256"));
                if (!hash.Equals(otherHash, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (activity.Severity >= EventSeverity.High ||
                    HasActivityTag(activity, "unsigned_or_untrusted_binary", "user_writable_location", "transient_sys", "mapper_behavior", "vulnerable_driver"))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool DetectRegistryRestorePattern(IEnumerable<RelatedActivity> activities, SpooferCleanupTrace trace)
        {
            if (activities == null)
            {
                return false;
            }

            List<RelatedActivity> registryChanges = activities
                .Where(a => a != null &&
                            a.Category.IndexOf("Registry", StringComparison.OrdinalIgnoreCase) >= 0 &&
                            ContainsAny(a.Action, "ValueModified", "RegistryValueSet", "RegistryValueModified") &&
                            HasActivityTag(a, "machine_guid_registry", "network_identity_registry", "storage_identity_registry", "hardware_identity_registry", "windows_identity_registry"))
                .OrderBy(a => a.TimestampUtc)
                .ToList();

            for (int i = 0; i < registryChanges.Count; i++)
            {
                RelatedActivity first = registryChanges[i];
                string firstPath = FirstNonEmpty(first.Path, ActivityDetail(first, "TargetObject"), ActivityDetail(first, "watch_target"));
                string firstOld = HardwareIdentityUtilities.NormalizeIdentifier(ActivityDetail(first, "old_value"));
                string firstNew = HardwareIdentityUtilities.NormalizeIdentifier(ActivityDetail(first, "new_value"));
                if (string.IsNullOrWhiteSpace(firstPath) || string.IsNullOrWhiteSpace(firstOld) || string.IsNullOrWhiteSpace(firstNew) || firstOld.Equals(firstNew, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                for (int j = i + 1; j < registryChanges.Count; j++)
                {
                    RelatedActivity second = registryChanges[j];
                    string secondPath = FirstNonEmpty(second.Path, ActivityDetail(second, "TargetObject"), ActivityDetail(second, "watch_target"));
                    if (!firstPath.Equals(secondPath, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    string secondOld = HardwareIdentityUtilities.NormalizeIdentifier(ActivityDetail(second, "old_value"));
                    string secondNew = HardwareIdentityUtilities.NormalizeIdentifier(ActivityDetail(second, "new_value"));
                    if (firstNew.Equals(secondOld, StringComparison.OrdinalIgnoreCase) && firstOld.Equals(secondNew, StringComparison.OrdinalIgnoreCase))
                    {
                        trace.CleanupActions.Add("registry value restored: " + Trim(firstPath, 180));
                        trace.Timeline.Add(second.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + " cleanup registry_restore " + Trim(firstPath, 160));
                        return true;
                    }
                }
            }

            return false;
        }

        private static bool ContainsRegistryRestorePattern(IEnumerable<RelatedActivity> activities)
        {
            return DetectRegistryRestorePattern(activities, new SpooferCleanupTrace());
        }

        private static bool CleanupHappenedSoonAfterExit(RelatedActivity activity, LaunchIdentitySession session)
        {
            if (activity == null || session == null || !session.ExitTimeUtc.HasValue)
            {
                return false;
            }

            TimeSpan delta = activity.TimestampUtc.Subtract(session.ExitTimeUtc.Value);
            return delta >= TimeSpan.Zero && delta <= TimeSpan.FromMinutes(5);
        }

        private static List<HardwareChangeAttribution> BuildAttributions(IEnumerable<HwidIntegrityFinding> findings, IEnumerable<RelatedActivity> related, string stage)
        {
            List<HardwareChangeAttribution> attributions = new List<HardwareChangeAttribution>();
            List<RelatedActivity> activities = related == null
                ? new List<RelatedActivity>()
                : related.OrderBy(a => a.TimestampUtc).ToList();

            foreach (HwidIntegrityFinding finding in findings.Where(IsAttributableHardwareChangeFinding))
            {
                attributions.Add(AttributeFinding(finding, activities, stage));
            }

            return attributions;
        }

        private static HardwareChangeAttribution AttributeFinding(HwidIntegrityFinding finding, List<RelatedActivity> activities, string stage)
        {
            AttributionCandidate process = BestCandidate(finding, activities, ScoreProcessAttribution);
            AttributionCandidate driver = BestCandidate(finding, activities, ScoreDriverAttribution);
            AttributionCandidate registry = BestCandidate(finding, activities, ScoreRegistryAttribution);
            AttributionCandidate deviceEvent = BestCandidate(finding, activities, ScoreDeviceEventAttribution);

            HardwareChangeAttribution attribution = new HardwareChangeAttribution
            {
                CaseId = finding.CaseId ?? BuildCaseId(finding),
                Stage = stage ?? string.Empty,
                IdentifierType = finding.IdentifierType ?? string.Empty,
                IdentityKey = finding.IdentityKey ?? string.Empty,
                OldValue = FirstNonEmpty(finding.PreviousValue, finding.BaselineValue, "missing"),
                NewValue = finding.CurrentValue ?? string.Empty,
                RelatedProcess = process.Activity == null ? string.Empty : DescribeProcessActivity(process.Activity),
                RelatedDriverService = driver.Activity == null ? string.Empty : DescribeDriverServiceActivity(driver.Activity),
                RelatedRegistryKey = registry.Activity == null ? string.Empty : DescribeRegistryActivity(registry.Activity),
                RelatedDeviceEvent = deviceEvent.Activity == null ? string.Empty : DescribeDeviceEventActivity(deviceEvent.Activity)
            };

            AddSignals(attribution, "process", process);
            AddSignals(attribution, "driver", driver);
            AddSignals(attribution, "registry", registry);
            AddSignals(attribution, "device", deviceEvent);

            foreach (RelatedActivity activity in new[] { process.Activity, driver.Activity, registry.Activity, deviceEvent.Activity }
                .Where(a => a != null)
                .GroupBy(a => a.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + "|" + a.Category + "|" + a.Action + "|" + a.Description, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .OrderBy(a => a.TimestampUtc))
            {
                attribution.EvidenceTimeline.Add(activity.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + " " +
                    activity.Category + "/" + activity.Action + " " + Trim(activity.Description, 180));
            }

            attribution.SuspectedCause = BuildSuspectedCause(process, driver, registry, deviceEvent);
            double score = 0.22 + Math.Min(0.15, finding.ConfidenceScore * 0.15);
            score += process.Score + driver.Score + registry.Score + deviceEvent.Score;
            if (HasDomainSpecificEvidence(finding, process, driver, registry, deviceEvent))
            {
                score += 0.08;
                attribution.MatchedSignals.Add("domain_specific_match");
            }

            if (attribution.MatchedSignals.Count == 0)
            {
                attribution.MatchedSignals.Add("identity_change_without_correlated_activity");
                attribution.EvidenceTimeline.Add("No process, driver, registry, or device-event telemetry matched inside the lookback window.");
                attribution.SuspectedCause = "identity_change_observed_without_correlated_activity";
                score = Math.Max(score, 0.30);
            }

            attribution.ConfidenceScore = Math.Min(0.99, score);
            return attribution;
        }

        private static AttributionCandidate BestCandidate(
            HwidIntegrityFinding finding,
            IEnumerable<RelatedActivity> activities,
            Func<HwidIntegrityFinding, RelatedActivity, AttributionCandidate> scorer)
        {
            AttributionCandidate best = new AttributionCandidate();
            if (activities == null)
            {
                return best;
            }

            foreach (RelatedActivity activity in activities)
            {
                AttributionCandidate candidate = scorer(finding, activity);
                if (candidate.Score > best.Score)
                {
                    best = candidate;
                }
            }

            return best;
        }

        private static AttributionCandidate ScoreProcessAttribution(HwidIntegrityFinding finding, RelatedActivity activity)
        {
            AttributionCandidate candidate = NewCandidate(activity);
            string text = ActivityText(activity);
            bool processEvent = activity.Category.StartsWith("Process", StringComparison.OrdinalIgnoreCase) ||
                                (activity.Category.IndexOf("Sysmon", StringComparison.OrdinalIgnoreCase) >= 0 && ContainsAny(activity.Action, "ProcessCreated", "ProcessAccessed")) ||
                                ContainsAny(activity.Action, "Executed", "ProcessCreated", "ProcessAccessed", "SuspiciousHardwareIdentityApiProbe");

            if (processEvent)
            {
                candidate.Add(0.10, "process_launch_or_access");
            }

            if (activity.Severity >= EventSeverity.High)
            {
                candidate.Add(0.05, "high_severity_process_signal");
            }

            if (HasActivityTag(activity, "unsigned_or_untrusted_binary") || ContainsAny(text, "signature_status unsigned", "signature_status untrusted", "source_signature_status untrusted", "not trusted", "untrustedorinvalid"))
            {
                candidate.Add(0.13, "unsigned_or_untrusted_binary");
            }

            string path = ActivityPath(activity);
            if (HasActivityTag(activity, "user_writable_location") || FileClassifier.IsLikelyDownloadLocation(path))
            {
                candidate.Add(0.10, "user_writable_or_download_location");
            }

            if (HasActivityTag(activity, "admin_or_elevated"))
            {
                candidate.Add(0.06, "admin_or_elevated_context");
            }

            if (HasActivityTag(activity, "hardware_control_command") || ContainsAny(text, "win32_diskdrive", "win32_bios", "win32_baseboard", "getsystemfirmwaretable", "getadaptersaddresses", "ioctl_storage_query_property", "networkaddress", "devcon", "pnputil", "netsh"))
            {
                candidate.Add(0.12, "hardware_identity_api_or_control_command");
            }

            if (HasActivityTag(activity, "device_handle", "device_object", "section_object"))
            {
                candidate.Add(0.10, "device_or_section_handle");
            }

            if (IdentifierDomainMatchesActivity(finding, activity))
            {
                candidate.Add(0.07, "identifier_domain_match");
            }

            if (candidate.Score < 0.10)
            {
                candidate.Clear();
            }

            return candidate;
        }

        private static AttributionCandidate ScoreDriverAttribution(HwidIntegrityFinding finding, RelatedActivity activity)
        {
            AttributionCandidate candidate = NewCandidate(activity);
            if (HasActivityTag(activity, "hidden_kernel_indicator"))
            {
                candidate.Add(0.18, "hidden_driver_indicator");
            }

            if (HasActivityTag(activity, "vulnerable_driver"))
            {
                candidate.Add(0.16, "vulnerable_driver_indicator");
            }

            if (HasActivityTag(activity, "mapper_behavior"))
            {
                candidate.Add(0.16, "mapper_behavior");
            }

            if (HasActivityTag(activity, "transient_sys"))
            {
                candidate.Add(0.14, "temporary_sys_file");
            }

            if (HasActivityTag(activity, "driver_load_event"))
            {
                candidate.Add(0.14, "driver_load_event");
            }

            if (HasActivityTag(activity, "driver_service_created"))
            {
                candidate.Add(0.12, "driver_service_created");
            }

            if (HasActivityTag(activity, "driver_service_deleted"))
            {
                candidate.Add(0.10, "driver_service_deleted");
            }

            if (HasActivityTag(activity, "service_activity"))
            {
                candidate.Add(0.08, "service_activity");
            }

            string text = ActivityText(activity);
            if (ContainsAny(text, ".sys", "driver_path", "driver_file_name", "service_name", "kernel driver"))
            {
                candidate.Add(0.08, "driver_or_service_artifact");
            }

            if (HasActivityTag(activity, "unsigned_or_untrusted_binary") || ContainsAny(text, "untrusted", "unsigned", "codeintegrityblocked"))
            {
                candidate.Add(0.10, "unsigned_or_untrusted_driver");
            }

            if (IdentifierDomainMatchesActivity(finding, activity))
            {
                candidate.Add(0.05, "identifier_domain_match");
            }

            if (candidate.Score < 0.10)
            {
                candidate.Clear();
            }

            return candidate;
        }

        private static AttributionCandidate ScoreRegistryAttribution(HwidIntegrityFinding finding, RelatedActivity activity)
        {
            AttributionCandidate candidate = NewCandidate(activity);
            string text = ActivityText(activity);
            bool registryEvent = activity.Category.IndexOf("Registry", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 ContainsAny(activity.Action, "RegistryValueSet", "RegistryValueModified", "RegistryObjectCreatedOrDeleted", "RegistryObjectRenamed", "KeyCreated", "KeyDeleted", "ValueCreated", "ValueModified", "ValueDeleted");
            if (registryEvent)
            {
                candidate.Add(0.12, "registry_change_event");
            }

            if (HasActivityTag(activity, "network_identity_registry", "storage_identity_registry", "machine_guid_registry", "windows_identity_registry", "hardware_identity_registry"))
            {
                candidate.Add(0.16, "hardware_identity_registry_key");
            }

            if (ContainsAny(text, "networkaddress", "class\\{4d36e972", "tcpip\\parameters"))
            {
                candidate.Add(0.08, "nic_registry_key");
            }

            if (ContainsAny(text, "mounteddevices", "usbstor", "enum\\scsi", "enum\\storage", "enum\\disk"))
            {
                candidate.Add(0.08, "storage_registry_key");
            }

            if (ContainsAny(text, "machineguid", "windows nt\\currentversion", "hardware\\description\\system", "system\\bios"))
            {
                candidate.Add(0.08, "system_identity_registry_key");
            }

            if (ContainsAny(text, "services\\", "imagepath", "type= kernel"))
            {
                candidate.Add(0.07, "service_device_configuration_key");
            }

            if (IdentifierDomainMatchesActivity(finding, activity))
            {
                candidate.Add(0.08, "identifier_domain_match");
            }

            if (candidate.Score < 0.10)
            {
                candidate.Clear();
            }

            return candidate;
        }

        private static AttributionCandidate ScoreDeviceEventAttribution(HwidIntegrityFinding finding, RelatedActivity activity)
        {
            AttributionCandidate candidate = NewCandidate(activity);
            string text = ActivityText(activity);
            if (HasActivityTag(activity, "pnp_device_event"))
            {
                candidate.Add(0.16, "pnp_device_event");
            }

            if (HasActivityTag(activity, "adapter_reset"))
            {
                candidate.Add(0.15, "adapter_reset_or_disable_enable");
            }

            if (HasActivityTag(activity, "storage_reset"))
            {
                candidate.Add(0.14, "storage_reset");
            }

            if (HasActivityTag(activity, "virtual_adapter_or_hypervisor"))
            {
                candidate.Add(0.13, "virtual_device_or_hypervisor_signal");
            }

            if (HasActivityTag(activity, "device_object", "device_handle"))
            {
                candidate.Add(0.10, "device_object_or_handle");
            }

            if (ContainsAny(text, "device install", "device configured", "device started", "device deleted", "pnp", "re-enumeration", "reenumeration", "surprise removal", "reset"))
            {
                candidate.Add(0.10, "device_stack_change_signal");
            }

            if (IdentifierDomainMatchesActivity(finding, activity))
            {
                candidate.Add(0.08, "identifier_domain_match");
            }

            if (candidate.Score < 0.10)
            {
                candidate.Clear();
            }

            return candidate;
        }

        private bool ShouldEmitAttribution(HardwareChangeAttribution attribution)
        {
            string key = "attribution|" + attribution.IdentityKey + "|" + attribution.OldValue + "|" + attribution.NewValue + "|" + attribution.SuspectedCause + "|" + attribution.RelatedProcess + "|" + attribution.RelatedDriverService + "|" + attribution.RelatedRegistryKey + "|" + attribution.RelatedDeviceEvent;
            lock (_reportedKeys)
            {
                return _reportedKeys.Add(key);
            }
        }

        private static EventSeverity SeverityForAttribution(HardwareChangeAttribution attribution)
        {
            if (attribution.ConfidenceScore >= 0.85) return EventSeverity.Critical;
            if (attribution.ConfidenceScore >= 0.65) return EventSeverity.High;
            if (attribution.ConfidenceScore >= 0.42) return EventSeverity.Medium;
            return EventSeverity.Low;
        }

        private static bool IsAttributableHardwareChangeFinding(HwidIntegrityFinding finding)
        {
            if (finding == null)
            {
                return false;
            }

            if (IsIdentityChangeFinding(finding))
            {
                return true;
            }

            return ContainsAny(finding.Action,
                "VolumeSerialChangedDuringRuntime",
                "HardwareDeviceAppearedDuringRuntime",
                "TransientHardwareDeviceDisappeared",
                "TemporaryVirtualAdapterDuringProtectedRuntime",
                "VirtualHardwareDevicePresent",
                "SuspiciousVirtualStorageLayer",
                "UnusualDeviceFilterDriver");
        }

        private static bool HasDomainSpecificEvidence(
            HwidIntegrityFinding finding,
            AttributionCandidate process,
            AttributionCandidate driver,
            AttributionCandidate registry,
            AttributionCandidate deviceEvent)
        {
            return CandidateHasSignal(process, "identifier_domain_match") ||
                   CandidateHasSignal(driver, "identifier_domain_match") ||
                   CandidateHasSignal(registry, "identifier_domain_match") ||
                   CandidateHasSignal(deviceEvent, "identifier_domain_match");
        }

        private static bool CandidateHasSignal(AttributionCandidate candidate, string signal)
        {
            return candidate != null && candidate.Signals.Contains(signal);
        }

        private static void AddSignals(HardwareChangeAttribution attribution, string prefix, AttributionCandidate candidate)
        {
            if (candidate == null || candidate.Activity == null)
            {
                return;
            }

            foreach (string signal in candidate.Signals)
            {
                attribution.MatchedSignals.Add(prefix + ":" + signal);
            }
        }

        private static string BuildSuspectedCause(
            AttributionCandidate process,
            AttributionCandidate driver,
            AttributionCandidate registry,
            AttributionCandidate deviceEvent)
        {
            List<string> causes = new List<string>();
            if (driver.Score >= 0.18) causes.Add("driver_or_service_activity");
            if (registry.Score >= 0.18) causes.Add("hardware_registry_change");
            if (deviceEvent.Score >= 0.18) causes.Add("device_or_adapter_event");
            if (process.Score >= 0.18) causes.Add("suspicious_process_activity");

            if (causes.Count == 0)
            {
                AttributionCandidate best = new[] { process, driver, registry, deviceEvent }
                    .OrderByDescending(c => c.Score)
                    .FirstOrDefault(c => c.Score > 0);
                if (best == driver) causes.Add("weak_driver_or_service_activity");
                else if (best == registry) causes.Add("weak_hardware_registry_change");
                else if (best == deviceEvent) causes.Add("weak_device_or_adapter_event");
                else if (best == process) causes.Add("weak_suspicious_process_activity");
            }

            return causes.Count == 0
                ? "identity_change_observed_without_correlated_activity"
                : string.Join("+", causes.ToArray());
        }

        private static AttributionCandidate NewCandidate(RelatedActivity activity)
        {
            return new AttributionCandidate { Activity = activity };
        }

        private static bool HasActivityTag(RelatedActivity activity, params string[] tags)
        {
            if (activity == null || tags == null)
            {
                return false;
            }

            foreach (string tag in tags)
            {
                if (activity.Tags.Contains(tag))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IdentifierDomainMatchesActivity(HwidIntegrityFinding finding, RelatedActivity activity)
        {
            string domain = IdentifierDomain(finding);
            string text = ActivityText(activity);
            if (domain == "network")
            {
                return HasActivityTag(activity, "network_identity_registry", "adapter_reset", "virtual_adapter_or_hypervisor") ||
                       ContainsAny(text, "networkaddress", "adapter", "mac", "netsh", "netadapter", "class\\{4d36e972");
            }

            if (domain == "storage")
            {
                return HasActivityTag(activity, "storage_identity_registry", "storage_reset") ||
                       ContainsAny(text, "mounteddevices", "disk", "volume", "usbstor", "storage", "ioctl_storage", "stornvme", "storahci");
            }

            if (domain == "system")
            {
                return HasActivityTag(activity, "machine_guid_registry", "windows_identity_registry", "hardware_identity_registry") ||
                       ContainsAny(text, "smbios", "bios", "baseboard", "uuid", "firmware", "machineguid", "hardware\\description\\system");
            }

            if (domain == "gpu")
            {
                return ContainsAny(text, "display", "gpu", "dxgi", "{4d36e968", "nvidia", "amd", "intel");
            }

            if (domain == "device")
            {
                return HasActivityTag(activity, "pnp_device_event", "device_object", "device_handle", "virtual_adapter_or_hypervisor") ||
                       ContainsAny(text, "pnp", "device", "enum\\", "class\\", "filter", "upperfilters", "lowerfilters");
            }

            return HasActivityTag(activity, "hardware_identity_registry", "hardware_control_command");
        }

        private static string IdentifierDomain(HwidIntegrityFinding finding)
        {
            string text = ((finding == null ? null : finding.IdentifierType) + " " + (finding == null ? null : finding.IdentityKey)).ToLowerInvariant();
            if (ContainsAny(text, "network", "mac", "adapter")) return "network";
            if (ContainsAny(text, "disk", "volume", "storage", "mounteddevice")) return "storage";
            if (ContainsAny(text, "smbios", "bios", "baseboard", "uuid", "firmware", "machineguid", "system.hypervisor")) return "system";
            if (ContainsAny(text, "gpu", "display")) return "gpu";
            if (ContainsAny(text, "device", "monitor", "tpm")) return "device";
            return "hardware";
        }

        private static string DescribeProcessActivity(RelatedActivity activity)
        {
            string path = ActivityPath(activity);
            string name = FirstNonEmpty(ActivityProcessName(activity), Path.GetFileName(path));
            string pid = ActivityProcessId(activity);
            string signer = FirstNonEmpty(
                ActivityDetail(activity, "signature_status"),
                ActivityDetail(activity, "source_signature_status"),
                ActivityDetail(activity, "file_signature_status"));
            return "process=" + name +
                   " pid=" + pid +
                   " path=" + path +
                   (string.IsNullOrWhiteSpace(signer) ? string.Empty : " signature=" + signer) +
                   " signal=" + activity.Category + "/" + activity.Action;
        }

        private static string DescribeDriverServiceActivity(RelatedActivity activity)
        {
            string serviceName = FirstNonEmpty(
                ActivityDetail(activity, "service_name"),
                ActivityDetail(activity, "ServiceName"),
                ActivityDetail(activity, "param1"),
                ActivityDetail(activity, "driver_service_name"));
            string driverPath = FirstNonEmpty(
                ActivityDetail(activity, "driver_path"),
                ActivityDetail(activity, "driver_file"),
                ActivityDetail(activity, "ImagePath"),
                ActivityDetail(activity, "ServiceFileName"),
                ActivityDetail(activity, "param2"),
                ActivityPath(activity));
            return "service=" + serviceName +
                   " driver_path=" + driverPath +
                   " signal=" + activity.Category + "/" + activity.Action;
        }

        private static string DescribeRegistryActivity(RelatedActivity activity)
        {
            string key = FirstNonEmpty(
                activity.Path,
                ActivityDetail(activity, "TargetObject"),
                ActivityDetail(activity, "ObjectName"),
                ActivityDetail(activity, "watch_target"),
                ActivityDetail(activity, "registry_key"),
                ActivityDetail(activity, "key_name"));
            string image = FirstNonEmpty(ActivityDetail(activity, "Image"), ActivityDetail(activity, "ProcessName"), ActivityPath(activity));
            return "key=" + key +
                   " process=" + image +
                   " old=" + Trim(ActivityDetail(activity, "old_value"), 80) +
                   " new=" + Trim(ActivityDetail(activity, "new_value"), 80) +
                   " signal=" + activity.Category + "/" + activity.Action;
        }

        private static string DescribeDeviceEventActivity(RelatedActivity activity)
        {
            string device = FirstNonEmpty(
                ActivityDetail(activity, "object_name"),
                ActivityDetail(activity, "device_name"),
                ActivityDetail(activity, "DeviceName"),
                ActivityDetail(activity, "pnp_device_id"),
                ActivityDetail(activity, "DeviceInstanceId"),
                activity.Path);
            string type = FirstNonEmpty(ActivityDetail(activity, "object_type"), ActivityDetail(activity, "pnp_class"), ActivityDetail(activity, "ClassName"));
            return "device=" + device +
                   " type=" + type +
                   " process=" + ActivityProcessName(activity) +
                   " signal=" + activity.Category + "/" + activity.Action;
        }

        private static string ActivityText(RelatedActivity activity)
        {
            if (activity == null)
            {
                return string.Empty;
            }

            string details = activity.Details == null
                ? string.Empty
                : string.Join(" ", activity.Details.Select(p => p.Key + " " + p.Value).ToArray());
            return ((activity.Category ?? string.Empty) + " " +
                    (activity.Action ?? string.Empty) + " " +
                    (activity.Description ?? string.Empty) + " " +
                    (activity.Path ?? string.Empty) + " " +
                    (activity.ProcessName ?? string.Empty) + " " +
                    string.Join(" ", activity.Tags.ToArray()) + " " +
                    details).ToLowerInvariant();
        }

        private static string ActivityPath(RelatedActivity activity)
        {
            if (activity == null)
            {
                return string.Empty;
            }

            return FirstNonEmpty(
                activity.Path,
                ActivityDetail(activity, "executable_path"),
                ActivityDetail(activity, "Image"),
                ActivityDetail(activity, "SourceImage"),
                ActivityDetail(activity, "source_process_path"),
                ActivityDetail(activity, "driver_path"),
                ActivityDetail(activity, "TargetFilename"));
        }

        private static string ActivityProcessName(RelatedActivity activity)
        {
            if (activity == null)
            {
                return string.Empty;
            }

            return FirstNonEmpty(
                activity.ProcessName,
                ActivityDetail(activity, "process_name"),
                ActivityDetail(activity, "ProcessName"),
                Path.GetFileName(ActivityDetail(activity, "Image")),
                Path.GetFileName(ActivityDetail(activity, "SourceImage")),
                ActivityDetail(activity, "source_process_name"));
        }

        private static string ActivityProcessId(RelatedActivity activity)
        {
            if (activity == null)
            {
                return string.Empty;
            }

            return FirstNonEmpty(
                activity.ProcessId.HasValue ? activity.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : string.Empty,
                ActivityDetail(activity, "process_id"),
                ActivityDetail(activity, "ProcessId"),
                ActivityDetail(activity, "SourceProcessId"),
                ActivityDetail(activity, "source_process_id"));
        }

        private static string ActivityDetail(RelatedActivity activity, string key)
        {
            string value;
            return activity != null &&
                   activity.Details != null &&
                   activity.Details.TryGetValue(key, out value)
                ? value ?? string.Empty
                : string.Empty;
        }

        private static string FormatActivityDetails(RelatedActivity activity)
        {
            if (activity == null || activity.Details == null || activity.Details.Count == 0)
            {
                return string.Empty;
            }

            string[] preferred =
            {
                "Image", "SourceImage", "TargetObject", "watch_target", "ServiceName", "service_name",
                "ImagePath", "driver_path", "object_type", "object_name", "process_id", "parent_process_id",
                "signature_status", "source_signature_status", "old_value", "new_value"
            };

            List<string> parts = new List<string>();
            foreach (string key in preferred)
            {
                string value = ActivityDetail(activity, key);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    parts.Add(key + "=" + Trim(value, 120));
                }
            }

            if (parts.Count == 0)
            {
                foreach (KeyValuePair<string, string> pair in activity.Details.OrderBy(p => p.Key, StringComparer.OrdinalIgnoreCase).Take(8))
                {
                    parts.Add(pair.Key + "=" + Trim(pair.Value, 120));
                }
            }

            return string.Join("; ", parts.Take(12).ToArray());
        }

        private static bool IsIdentityChangeFinding(HwidIntegrityFinding finding)
        {
            if (finding == null)
            {
                return false;
            }

            return finding.Action.Equals("HardwareIdentifierChangedFromBaseline", StringComparison.OrdinalIgnoreCase) ||
                   finding.Action.Equals("RapidHardwareIdentifierRuntimeChange", StringComparison.OrdinalIgnoreCase) ||
                   finding.Action.Equals("HardwareIdentifierRevertedToBaseline", StringComparison.OrdinalIgnoreCase) ||
                   finding.Action.Equals("HardwareIdentifierFirstSeenAfterBaseline", StringComparison.OrdinalIgnoreCase) ||
                   finding.Action.Equals("HardwareIdentifierMissingFromBaseline", StringComparison.OrdinalIgnoreCase);
        }

        private static string FormatProfileDiff(IEnumerable<ProfileDiff> diffs)
        {
            if (diffs == null)
            {
                return string.Empty;
            }

            return string.Join("; ", diffs
                .GroupBy(d => d.IdentityKey + "|" + d.ChangeType, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .Take(18)
                .Select(d => d.IdentifierType + ":" + d.ChangeType +
                             " key=" + Trim(d.IdentityKey, 90) +
                             " before=" + Trim(FirstNonEmpty(d.PreviousValue, d.BaselineValue, "missing"), 70) +
                             " after=" + Trim(d.CurrentValue, 70))
                .ToArray());
        }

        private static string FormatSessionTimeline(LaunchIdentitySession session)
        {
            if (session == null)
            {
                return string.Empty;
            }

            List<string> lines = new List<string>
            {
                session.LaunchTimeUtc.ToString("o", CultureInfo.InvariantCulture) + " launch " + session.ProcessName + " pid=" + session.ProcessId.ToString(CultureInfo.InvariantCulture)
            };

            foreach (RelatedActivity activity in session.PreLaunchActivities.OrderBy(a => a.TimestampUtc).Take(20))
            {
                lines.Add(activity.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + " prelaunch " + activity.Category + "/" + activity.Action + " " + Trim(activity.Description, 120));
            }

            foreach (RelatedActivity activity in session.SessionActivities.OrderBy(a => a.TimestampUtc).Take(30))
            {
                lines.Add(activity.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + " session " + activity.Category + "/" + activity.Action + " " + Trim(activity.Description, 120));
            }

            if (session.ExitTimeUtc.HasValue)
            {
                lines.Add(session.ExitTimeUtc.Value.ToString("o", CultureInfo.InvariantCulture) + " exit " + session.ProcessName + " pid=" + session.ProcessId.ToString(CultureInfo.InvariantCulture));
            }

            foreach (SpooferCleanupTrace trace in session.CleanupTraces.Take(4))
            {
                lines.Add("cleanup_phase " + trace.Phase + " score=" + trace.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) + " " + Trim(trace.Summary, 160));
            }

            return string.Join(" || ", lines.ToArray());
        }

        private static string FormatRelatedArtifacts(LaunchIdentitySession session, IEnumerable<HwidSpooferProfile> profiles)
        {
            HashSet<string> artifacts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (session != null)
            {
                if (!string.IsNullOrWhiteSpace(session.ProcessName)) artifacts.Add("process:" + session.ProcessName);
                if (!string.IsNullOrWhiteSpace(session.ProcessPath)) artifacts.Add("path:" + session.ProcessPath);
                foreach (RelatedActivity activity in session.PreLaunchActivities.Concat(session.SessionActivities))
                {
                    if (!string.IsNullOrWhiteSpace(activity.ProcessName)) artifacts.Add("process:" + activity.ProcessName);
                    if (!string.IsNullOrWhiteSpace(activity.Path)) artifacts.Add("path:" + activity.Path);
                    foreach (string tag in activity.Tags)
                    {
                        artifacts.Add("tag:" + tag);
                    }
                }
            }

            if (profiles != null)
            {
                foreach (HwidSpooferProfile profile in profiles)
                {
                    artifacts.Add("profile:" + profile.ProfileName);
                    foreach (string artifact in profile.RelatedArtifacts)
                    {
                        artifacts.Add(artifact);
                    }
                }
            }

            return string.Join(";", artifacts.OrderBy(v => v).Take(80).ToArray());
        }

        private static string InferSessionProfile(LaunchIdentitySession session, IEnumerable<HwidSpooferProfile> profiles)
        {
            HwidSpooferProfile best = profiles == null
                ? null
                : profiles.OrderByDescending(p => p.ConfidenceScore).FirstOrDefault();
            if (best != null && best.ConfidenceScore >= 0.45)
            {
                return best.ProfileName;
            }

            if (session == null)
            {
                return "unclassified_hwid_session";
            }

            if (session.ObservedProfiles.Count > 0)
            {
                return session.ObservedProfiles.OrderBy(v => v).First();
            }

            if (session.RevertedDiffs.Count > 0 || session.RuntimeDiffs.Count > 0)
            {
                if (session.RuntimeDiffs.Any(d => ContainsAny(d.IdentifierType, "network.mac"))) return "network_mac_spoofer";
                if (session.RuntimeDiffs.Any(d => ContainsAny(d.IdentifierType, "disk", "volume", "storage"))) return "disk_volume_spoofer";
                if (session.RuntimeDiffs.Any(d => ContainsAny(d.IdentifierType, "smbios", "system"))) return "smbios_firmware_spoofer";
                return "temporary_session_spoofer";
            }

            if (HasTag(session.PreLaunchActivities, "mapper_behavior", "vulnerable_driver", "hidden_kernel_indicator", "transient_sys"))
            {
                return "driver_backed_spoofer";
            }

            if (HasTag(session.PreLaunchActivities, "network_identity_registry", "machine_guid_registry", "windows_identity_registry", "storage_identity_registry", "hardware_identity_registry"))
            {
                return "registry_only_spoofer";
            }

            return "unclassified_hwid_session";
        }

        private static HwidIntegrityFinding Finding(string action, EventSeverity severity, string description, IdentityValue value, string baselineValue, string previousValue, string currentValue, double confidence, Dictionary<string, string> details)
        {
            HwidIntegrityFinding finding = new HwidIntegrityFinding
            {
                Action = action,
                Severity = severity,
                Description = description,
                IdentifierType = value.IdentifierType,
                IdentityKey = value.Key,
                Source = value.Source,
                Entity = value.Entity,
                BaselineValue = baselineValue,
                PreviousValue = previousValue,
                CurrentValue = currentValue,
                ConfidenceScore = confidence,
                CaseId = BuildCaseId(value.Key)
            };

            if (details != null)
            {
                foreach (KeyValuePair<string, string> pair in details)
                {
                    finding.Details[pair.Key] = pair.Value;
                }
            }

            return finding;
        }

        private static string BuildCaseId(HwidIntegrityFinding finding)
        {
            return BuildCaseId(finding.IdentityKey);
        }

        private static string BuildCaseId(string key)
        {
            return "HWID-" + DateTime.UtcNow.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + "-" +
                   ReputationStore.HashText(key ?? string.Empty).Substring(0, 8).ToUpperInvariant();
        }

        private static EventSeverity SeverityForIdentifier(string identifierType)
        {
            if (ContainsAny(identifierType, "uuid", "serial", "mac", "firmware_hash", "tpm"))
            {
                return EventSeverity.High;
            }

            return EventSeverity.Medium;
        }

        private static bool IsSensitiveKey(string key)
        {
            return ContainsAny(key, "|serial", "|mac", "|uuid", "|pnp", "|device_id", "mounteddevice", "|firmware_hash", "|edid_hash", "tpm|", "device|", "monitor|");
        }

        private static bool IsHardwareSensitiveKey(string key)
        {
            return ContainsAny(key, "diskdrive", "display", "net", "network", "scsi", "storage", "usbstor", "usb", "hid", "system", "{4d36e972", "{4d36e968", "{4d36e967", "{4d36e97b");
        }

        private static bool IsHardwareSensitiveClass(string pnpClass)
        {
            return ContainsAny(pnpClass, "net", "display", "diskdrive", "scsiadapter", "storage", "usb", "hidclass", "system", "volume", "monitor", "securitydevices");
        }

        private static string InferIdentifierType(string key)
        {
            if (key.IndexOf("network|", StringComparison.OrdinalIgnoreCase) >= 0) return "network.mac";
            if (key.IndexOf("disk|", StringComparison.OrdinalIgnoreCase) >= 0) return "disk.serial";
            if (key.IndexOf("volume|", StringComparison.OrdinalIgnoreCase) >= 0) return "volume.serial";
            if (key.IndexOf("system|", StringComparison.OrdinalIgnoreCase) >= 0) return "smbios.identifier";
            if (key.IndexOf("monitor|", StringComparison.OrdinalIgnoreCase) >= 0) return "monitor.identifier";
            if (key.IndexOf("device|", StringComparison.OrdinalIgnoreCase) >= 0) return "device.stack";
            if (key.IndexOf("tpm|", StringComparison.OrdinalIgnoreCase) >= 0) return "tpm.state";
            return "hardware.identifier";
        }

        private static string StableDeviceId(DeviceStackRecord device)
        {
            return SanitizeKey(device.DeviceId ?? device.ClassGuid ?? device.Name ?? device.PnpClass ?? "unknown");
        }

        private static string SanitizeKey(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "unknown";
            }

            return value.Trim().Replace('\t', '_').Replace('\r', '_').Replace('\n', '_');
        }

        private static bool LooksValidUuid(string value)
        {
            if (HardwareIdentityUtilities.IsBlankOrZero(value))
            {
                return false;
            }

            Guid ignored;
            return Guid.TryParse(value, out ignored);
        }

        private static bool LooksRandomizedIdentifier(string value)
        {
            string normalized = HardwareIdentityUtilities.NormalizeIdentifier(value);
            if (string.IsNullOrWhiteSpace(normalized) || normalized.Length < 10 || normalized.Length > 48)
            {
                return false;
            }

            string compact = new string(normalized.Where(char.IsLetterOrDigit).ToArray());
            if (compact.Length < 10)
            {
                return false;
            }

            int letters = compact.Count(char.IsLetter);
            int digits = compact.Count(char.IsDigit);
            int vowels = compact.Count(c => "AEIOU".IndexOf(char.ToUpperInvariant(c)) >= 0);
            int distinct = compact.Distinct().Count();
            return letters >= 5 && digits >= 3 && distinct >= 8 && vowels <= Math.Max(1, letters / 5);
        }

        private static bool LooksUnusualFilter(string filters)
        {
            if (string.IsNullOrWhiteSpace(filters))
            {
                return false;
            }

            string[] common =
            {
                "kbdclass", "mouclass", "partmgr", "volsnap", "storflt", "wcifs", "luafv",
                "wudfrd", "ndis", "netbt", "tdx", "vwififlt", "bindflt", "fileinfo"
            };

            foreach (string filter in filters.Split(new[] { ';', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string normalized = filter.Trim();
                if (string.IsNullOrWhiteSpace(normalized))
                {
                    continue;
                }

                if (common.Any(c => normalized.Equals(c, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                if (ContainsAny(normalized, "spoof", "hwid", "mapper", "hide", "disk", "serial", "mac", "random", "iqvw", "gdrv", "rtcore", "winio"))
                {
                    return true;
                }

                if (LooksRandomizedIdentifier(normalized))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool NormalizedEquals(string a, string b)
        {
            return string.Equals(HardwareIdentityUtilities.NormalizeIdentifier(a), HardwareIdentityUtilities.NormalizeIdentifier(b), StringComparison.OrdinalIgnoreCase);
        }

        private static string FormatRelatedActivity(IEnumerable<RelatedActivity> activities)
        {
            return string.Join(" || ", activities
                .OrderBy(a => a.TimestampUtc)
                .Take(10)
                .Select(a => a.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + " " + a.Category + "/" + a.Action + " " + Trim(a.Description, 160))
                .ToArray());
        }

        private static string ExtractCaseId(DetectionEvent detectionEvent)
        {
            return FirstNonEmpty(
                Detail(detectionEvent, "case_id"),
                Detail(detectionEvent, "behavior_case_id"),
                Detail(detectionEvent, "capture_id"),
                Detail(detectionEvent, "upstream_case_id"));
        }

        private static string Detail(DetectionEvent detectionEvent, string key)
        {
            string value;
            return detectionEvent != null &&
                   detectionEvent.Details != null &&
                   detectionEvent.Details.TryGetValue(key, out value)
                ? value ?? string.Empty
                : string.Empty;
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

        private static string EventText(DetectionEvent detectionEvent)
        {
            string details = detectionEvent.Details == null
                ? string.Empty
                : string.Join(" ", detectionEvent.Details.Select(p => p.Key + " " + p.Value).ToArray());
            return ((detectionEvent.Category ?? string.Empty) + " " +
                    (detectionEvent.Action ?? string.Empty) + " " +
                    (detectionEvent.Description ?? string.Empty) + " " +
                    (detectionEvent.Path ?? string.Empty) + " " +
                    (detectionEvent.ProcessName ?? string.Empty) + " " +
                    details).ToLowerInvariant();
        }

        private static Dictionary<string, string> SystemDetails(SystemIdentityRecord system)
        {
            return new Dictionary<string, string>
            {
                { "bios_vendor", system.BiosVendor ?? string.Empty },
                { "bios_version", system.BiosVersion ?? string.Empty },
                { "bios_serial", system.BiosSerial ?? string.Empty },
                { "baseboard_vendor", system.BaseboardVendor ?? string.Empty },
                { "baseboard_serial", system.BaseboardSerial ?? string.Empty },
                { "system_vendor", system.SystemVendor ?? string.Empty },
                { "system_product", system.SystemProduct ?? string.Empty },
                { "system_uuid", system.SystemUuid ?? string.Empty },
                { "firmware_hash", system.FirmwareHash ?? string.Empty },
                { "hypervisor_present", system.HypervisorPresent ?? string.Empty }
            };
        }

        private static Dictionary<string, string> GpuDetails(GpuIdentityRecord gpu)
        {
            return new Dictionary<string, string>
            {
                { "gpu_name", gpu.Name ?? string.Empty },
                { "gpu_vendor", gpu.Vendor ?? string.Empty },
                { "gpu_pnp_device_id", gpu.PnpDeviceId ?? string.Empty },
                { "gpu_driver_path", gpu.DriverPath ?? string.Empty },
                { "gpu_signature_status", gpu.SignatureStatus ?? string.Empty },
                { "gpu_signature_subject", gpu.SignatureSubject ?? string.Empty },
                { "gpu_is_virtual", gpu.IsVirtual.ToString() }
            };
        }

        private static Dictionary<string, string> DeviceDetails(DeviceStackRecord device)
        {
            return new Dictionary<string, string>
            {
                { "device_id", device.DeviceId ?? string.Empty },
                { "device_name", device.Name ?? string.Empty },
                { "pnp_class", device.PnpClass ?? string.Empty },
                { "class_guid", device.ClassGuid ?? string.Empty },
                { "manufacturer", device.Manufacturer ?? string.Empty },
                { "service", device.Service ?? string.Empty },
                { "status", device.Status ?? string.Empty },
                { "upper_filters", device.UpperFilters ?? string.Empty },
                { "lower_filters", device.LowerFilters ?? string.Empty },
                { "registry_path", device.RegistryPath ?? string.Empty },
                { "is_virtual", device.IsVirtual.ToString() }
            };
        }

        private static Dictionary<string, string> NetworkDetails(NetworkIdentityRecord adapter)
        {
            return new Dictionary<string, string>
            {
                { "adapter_name", adapter.Name ?? string.Empty },
                { "adapter_description", adapter.Description ?? string.Empty },
                { "adapter_id", adapter.AdapterId ?? string.Empty },
                { "pnp_device_id", adapter.PnpDeviceId ?? string.Empty },
                { "mac", adapter.MacAddress ?? string.Empty },
                { "registry_path", adapter.RegistryPath ?? string.Empty },
                { "is_virtual", adapter.IsVirtual.ToString() },
                { "is_locally_administered", adapter.IsLocallyAdministered.ToString() },
                { "operational_status", adapter.OperationalStatus ?? string.Empty }
            };
        }

        private static Dictionary<string, string> DiskDetails(DiskIdentityRecord disk)
        {
            return new Dictionary<string, string>
            {
                { "disk_source", disk.Source ?? string.Empty },
                { "disk_device_id", disk.DeviceId ?? string.Empty },
                { "disk_index", disk.Index ?? string.Empty },
                { "disk_model", disk.Model ?? string.Empty },
                { "disk_vendor", disk.Vendor ?? string.Empty },
                { "disk_serial", disk.Serial ?? string.Empty },
                { "disk_pnp_device_id", disk.PnpDeviceId ?? string.Empty },
                { "disk_interface_type", disk.InterfaceType ?? string.Empty },
                { "disk_registry_path", disk.RegistryPath ?? string.Empty }
            };
        }

        private static Dictionary<string, string> VolumeDetails(VolumeIdentityRecord volume)
        {
            return new Dictionary<string, string>
            {
                { "drive_name", volume.DriveName ?? string.Empty },
                { "file_system", volume.FileSystem ?? string.Empty },
                { "volume_label", volume.VolumeLabel ?? string.Empty },
                { "volume_serial", volume.VolumeSerial ?? string.Empty }
            };
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
            if (string.IsNullOrWhiteSpace(value)) return "snapshot";
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
            _stopSignal.Set();

            if (_thread != null && _thread.IsAlive)
            {
                _thread.Join(TimeSpan.FromSeconds(2));
            }

            _stopSignal.Dispose();
        }

        private sealed class IdentityValue
        {
            public string Key { get; private set; }
            public string IdentifierType { get; private set; }
            public string Source { get; private set; }
            public string Entity { get; private set; }
            public string Value { get; private set; }
            public bool SessionSensitive { get; private set; }

            public static IdentityValue From(string key, string identifierType, string source, string entity, string value, bool sessionSensitive)
            {
                return new IdentityValue
                {
                    Key = key ?? string.Empty,
                    IdentifierType = identifierType ?? "hardware.identifier",
                    Source = source ?? string.Empty,
                    Entity = entity ?? string.Empty,
                    Value = value ?? string.Empty,
                    SessionSensitive = sessionSensitive
                };
            }
        }

        private sealed class ProfileScore
        {
            public ProfileScore()
            {
                Indicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            public string Name { get; set; }
            public double Score { get; set; }
            public HashSet<string> Indicators { get; private set; }
        }

        private sealed class HwidSpooferProfile
        {
            public HwidSpooferProfile()
            {
                MatchedIndicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Diffs = new List<ProfileDiff>();
                RelatedArtifacts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                EvidenceTimeline = new List<string>();
                CaseLinks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                RelatedActivities = new List<RelatedActivity>();
            }

            public string ProfileName { get; set; }
            public string CaseId { get; set; }
            public EventSeverity Severity { get; set; }
            public double ConfidenceScore { get; set; }
            public HashSet<string> MatchedIndicators { get; private set; }
            public List<ProfileDiff> Diffs { get; private set; }
            public HashSet<string> RelatedArtifacts { get; private set; }
            public List<string> EvidenceTimeline { get; private set; }
            public HashSet<string> CaseLinks { get; private set; }
            public List<RelatedActivity> RelatedActivities { get; private set; }
        }

        private sealed class ProfileDiff
        {
            public string IdentityKey { get; set; }
            public string IdentifierType { get; set; }
            public string BaselineValue { get; set; }
            public string PreviousValue { get; set; }
            public string CurrentValue { get; set; }
            public string ChangeType { get; set; }

            public static ProfileDiff FromFinding(HwidIntegrityFinding finding)
            {
                return new ProfileDiff
                {
                    IdentityKey = finding.IdentityKey,
                    IdentifierType = finding.IdentifierType,
                    BaselineValue = finding.BaselineValue,
                    PreviousValue = finding.PreviousValue,
                    CurrentValue = finding.CurrentValue,
                    ChangeType = finding.Action
                };
            }
        }

        private sealed class LaunchIdentitySession
        {
            public LaunchIdentitySession()
            {
                LaunchValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                LastRuntimeValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                ExitValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                BaselineDiffs = new List<ProfileDiff>();
                LastBootDiffs = new List<ProfileDiff>();
                RuntimeDiffs = new List<ProfileDiff>();
                PostLaunchDiffs = new List<ProfileDiff>();
                PostBaselineDiffs = new List<ProfileDiff>();
                RevertedDiffs = new List<ProfileDiff>();
                PreLaunchActivities = new List<RelatedActivity>();
                SessionActivities = new List<RelatedActivity>();
                CleanupTraces = new List<SpooferCleanupTrace>();
                ObservedProfiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            public string CaseId { get; set; }
            public int ProcessId { get; set; }
            public string ProcessName { get; set; }
            public string ProcessPath { get; set; }
            public string CommandLine { get; set; }
            public DateTimeOffset LaunchTimeUtc { get; set; }
            public DateTimeOffset? ExitTimeUtc { get; set; }
            public string LaunchProcessEvent { get; set; }
            public string ExitProcessEvent { get; set; }
            public string LaunchSnapshotPath { get; set; }
            public string LastRuntimeSnapshotPath { get; set; }
            public string ExitSnapshotPath { get; set; }
            public string LastReportPath { get; set; }
            public int RuntimeSnapshotCount { get; set; }
            public Dictionary<string, string> LaunchValues { get; set; }
            public Dictionary<string, string> LastRuntimeValues { get; set; }
            public Dictionary<string, string> ExitValues { get; set; }
            public List<ProfileDiff> BaselineDiffs { get; set; }
            public List<ProfileDiff> LastBootDiffs { get; set; }
            public List<ProfileDiff> RuntimeDiffs { get; set; }
            public List<ProfileDiff> PostLaunchDiffs { get; set; }
            public List<ProfileDiff> PostBaselineDiffs { get; set; }
            public List<ProfileDiff> RevertedDiffs { get; set; }
            public List<RelatedActivity> PreLaunchActivities { get; set; }
            public List<RelatedActivity> SessionActivities { get; set; }
            public List<SpooferCleanupTrace> CleanupTraces { get; set; }
            public HashSet<string> ObservedProfiles { get; private set; }
        }

        private sealed class SpooferCleanupTrace
        {
            public SpooferCleanupTrace()
            {
                RevertedIdentifiers = new List<string>();
                DeletedArtifacts = new List<string>();
                CleanupActions = new List<string>();
                Timeline = new List<string>();
                MatchedSignals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            public string CaseId { get; set; }
            public string Phase { get; set; }
            public string Stage { get; set; }
            public string Summary { get; set; }
            public EventSeverity Severity { get; set; }
            public double ConfidenceScore { get; set; }
            public List<string> RevertedIdentifiers { get; private set; }
            public List<string> DeletedArtifacts { get; private set; }
            public List<string> CleanupActions { get; private set; }
            public List<string> Timeline { get; private set; }
            public HashSet<string> MatchedSignals { get; private set; }
        }

        private sealed class SpoofSessionScore
        {
            public SpoofSessionScore()
            {
                Reasons = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            public double Score { get; private set; }
            public HashSet<string> Reasons { get; private set; }

            public EventSeverity Severity
            {
                get
                {
                    return Score >= 0.82 ? EventSeverity.Critical :
                        Score >= 0.58 ? EventSeverity.High :
                        Score >= 0.35 ? EventSeverity.Medium : EventSeverity.Low;
                }
            }

            public void Add(double amount, string reason)
            {
                Score = Math.Min(0.99, Score + amount);
                if (!string.IsNullOrWhiteSpace(reason))
                {
                    Reasons.Add(reason);
                }
            }
        }

        private sealed class HardwareChangeAttribution
        {
            public HardwareChangeAttribution()
            {
                MatchedSignals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                EvidenceTimeline = new List<string>();
            }

            public string CaseId { get; set; }
            public string Stage { get; set; }
            public string IdentifierType { get; set; }
            public string IdentityKey { get; set; }
            public string OldValue { get; set; }
            public string NewValue { get; set; }
            public string SuspectedCause { get; set; }
            public string RelatedProcess { get; set; }
            public string RelatedDriverService { get; set; }
            public string RelatedRegistryKey { get; set; }
            public string RelatedDeviceEvent { get; set; }
            public double ConfidenceScore { get; set; }
            public HashSet<string> MatchedSignals { get; private set; }
            public List<string> EvidenceTimeline { get; private set; }
        }

        private sealed class AttributionCandidate
        {
            public AttributionCandidate()
            {
                Signals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            }

            public RelatedActivity Activity { get; set; }
            public double Score { get; private set; }
            public HashSet<string> Signals { get; private set; }

            public void Add(double amount, string signal)
            {
                Score = Math.Min(0.30, Score + amount);
                if (!string.IsNullOrWhiteSpace(signal))
                {
                    Signals.Add(signal);
                }
            }

            public void Clear()
            {
                Score = 0;
                Activity = null;
                Signals.Clear();
            }
        }

        private sealed class HwidIntegrityFinding
        {
            public HwidIntegrityFinding()
            {
                Details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                CorrelationTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                RelatedActivities = new List<RelatedActivity>();
            }

            public string Action { get; set; }
            public EventSeverity Severity { get; set; }
            public string Description { get; set; }
            public string IdentifierType { get; set; }
            public string IdentityKey { get; set; }
            public string Source { get; set; }
            public string Entity { get; set; }
            public string BaselineValue { get; set; }
            public string PreviousValue { get; set; }
            public string CurrentValue { get; set; }
            public double ConfidenceScore { get; set; }
            public string CaseId { get; set; }
            public Dictionary<string, string> Details { get; private set; }
            public HashSet<string> CorrelationTags { get; private set; }
            public List<RelatedActivity> RelatedActivities { get; private set; }
        }

        private sealed class RelatedActivity
        {
            public RelatedActivity()
            {
                Tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }

            public DateTimeOffset TimestampUtc { get; set; }
            public string Category { get; set; }
            public string Action { get; set; }
            public EventSeverity Severity { get; set; }
            public string Description { get; set; }
            public string CaseId { get; set; }
            public string Path { get; set; }
            public int? ProcessId { get; set; }
            public string ProcessName { get; set; }
            public HashSet<string> Tags { get; private set; }
            public Dictionary<string, string> Details { get; private set; }
        }
    }
}
