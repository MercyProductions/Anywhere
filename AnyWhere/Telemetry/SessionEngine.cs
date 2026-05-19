using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal sealed class SessionEngine : IDetectionMonitor
    {
        private static readonly TimeSpan SessionAttachWindow = TimeSpan.FromMinutes(30);
        private static readonly TimeSpan PostExitHoldWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan IdleFinalizeWindow = TimeSpan.FromMinutes(20);
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly ConcurrentDictionary<string, ReconstructedSession> _sessions = new ConcurrentDictionary<string, ReconstructedSession>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _emittedSessions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _writeLock = new object();
        private readonly string _root;
        private readonly string _sessionRoot;
        private readonly string _fingerprintPath;
        private bool _disposed;

        public SessionEngine(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _root = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Session Replay");
            _sessionRoot = Path.Combine(_root, "Sessions");
            _fingerprintPath = Path.Combine(_root, "session-fingerprints.jsonl");
        }

        public string Name
        {
            get { return "Session Reconstruction"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_root);
            Directory.CreateDirectory(_sessionRoot);
            _logger.EventLogged += OnEventLogged;

            _logger.Log(DetectionEvent.Create(
                "SessionReplay",
                "Started",
                EventSeverity.Low,
                "Session reconstruction and replay engine started.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "session_root", _sessionRoot },
                    { "fingerprint_path", _fingerprintPath },
                    { "attach_window_minutes", SessionAttachWindow.TotalMinutes.ToString("0", CultureInfo.InvariantCulture) },
                    { "post_exit_hold_minutes", PostExitHoldWindow.TotalMinutes.ToString("0", CultureInfo.InvariantCulture) },
                    { "safety_rule", "Defensive reconstruction only; no bypassing, blocking, patching, unloading, or stealth logic." }
                }));
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed ||
                detectionEvent == null ||
                detectionEvent.Category.StartsWith("SessionReplay", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            SessionSignal signal = SessionSignal.FromEvent(detectionEvent, _options);
            CleanupExpiredSessions(signal.TimestampUtc);

            bool startsSession = StartsSession(signal);
            List<ReconstructedSession> targets = FindAttachTargets(signal);
            if (startsSession && targets.Count == 0)
            {
                targets.Add(CreateSession(signal));
            }

            if (targets.Count == 0 && ShouldAttachToOpenSuspiciousSession(signal))
            {
                ReconstructedSession latest = _sessions.Values
                    .Where(s => !s.Finalized && signal.TimestampUtc.Subtract(s.LastSeenUtc) <= SessionAttachWindow)
                    .OrderByDescending(s => s.LastSeenUtc)
                    .FirstOrDefault();
                if (latest != null)
                {
                    targets.Add(latest);
                }
            }

            foreach (ReconstructedSession session in targets.Distinct().ToList())
            {
                lock (session.SyncRoot)
                {
                    AddSignal(session, signal);
                    Recalculate(session);

                    if (MarksSessionEnd(signal, session))
                    {
                        if (IsProtectedProcessExit(signal))
                        {
                            session.EndCandidateUtc = signal.TimestampUtc;
                            session.EndReason = "protected_process_exit";
                        }
                        else
                        {
                            session.EndCandidateUtc = signal.TimestampUtc;
                            session.EndReason = EndReason(signal);
                            FinalizeSession(session);
                        }
                    }
                    else if (ShouldEmitInterim(session))
                    {
                        WriteReplay(session, false);
                    }
                }
            }
        }

        private ReconstructedSession CreateSession(SessionSignal signal)
        {
            string sessionId = "SESSION-" + signal.TimestampUtc.UtcDateTime.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" +
                               HashText(signal.EventKey).Substring(0, 8).ToUpperInvariant();
            ReconstructedSession session = new ReconstructedSession
            {
                SessionId = sessionId,
                StartUtc = signal.TimestampUtc,
                LastSeenUtc = signal.TimestampUtc,
                StartReason = StartReason(signal)
            };

            _sessions[sessionId] = session;
            return session;
        }

        private List<ReconstructedSession> FindAttachTargets(SessionSignal signal)
        {
            List<ReconstructedSession> targets = new List<ReconstructedSession>();
            foreach (ReconstructedSession session in _sessions.Values)
            {
                if (session.Finalized || signal.TimestampUtc.Subtract(session.LastSeenUtc) > SessionAttachWindow)
                {
                    continue;
                }

                if (SharesStrongLink(session, signal) || signal.IsHighSignal || signal.Phase != "Unclassified")
                {
                    targets.Add(session);
                }
            }

            return targets.Take(3).ToList();
        }

        private static bool SharesStrongLink(ReconstructedSession session, SessionSignal signal)
        {
            if (!string.IsNullOrWhiteSpace(signal.CaseId) && session.CaseIds.Contains(signal.CaseId)) return true;
            if (signal.ProcessId.HasValue && session.ProcessIds.Contains(signal.ProcessId.Value)) return true;
            if (!string.IsNullOrWhiteSpace(signal.ProcessName) && session.Processes.Contains(signal.ProcessName)) return true;
            if (!string.IsNullOrWhiteSpace(signal.TargetProcessName) && session.Processes.Contains(signal.TargetProcessName)) return true;
            if (!string.IsNullOrWhiteSpace(signal.Path) && session.Files.Contains(signal.Path)) return true;
            if (!string.IsNullOrWhiteSpace(signal.DriverName) && session.Drivers.Contains(signal.DriverName)) return true;
            if (!string.IsNullOrWhiteSpace(signal.IdentifierKey) && session.Identifiers.Contains(signal.IdentifierKey)) return true;
            return false;
        }

        private static bool StartsSession(SessionSignal signal)
        {
            return signal.IsProtectedProcessStart ||
                   signal.IsSuspiciousLoaderStart ||
                   signal.IsHardwareIdentityChange ||
                   signal.IsSuspiciousDriverOrDevice;
        }

        private static bool ShouldAttachToOpenSuspiciousSession(SessionSignal signal)
        {
            return signal.IsHighSignal ||
                   signal.IsCleanup ||
                   signal.IsTargetInteraction ||
                   signal.IsMemoryAnomaly ||
                   signal.IsCommunicationSurface ||
                   signal.IsRegistryChange ||
                   signal.IsFileArtifact;
        }

        private static bool MarksSessionEnd(SessionSignal signal, ReconstructedSession session)
        {
            return IsProtectedProcessExit(signal) ||
                   signal.IsIdentityRevert ||
                   signal.IsCleanup ||
                   signal.IsSuspiciousDriverDisappear ||
                   (session.EndCandidateUtc.HasValue && signal.TimestampUtc.Subtract(session.EndCandidateUtc.Value) >= PostExitHoldWindow);
        }

        private static bool IsProtectedProcessExit(SessionSignal signal)
        {
            return signal.IsProtectedProcessExit;
        }

        private static string StartReason(SessionSignal signal)
        {
            if (signal.IsProtectedProcessStart) return "protected_game_launch";
            if (signal.IsSuspiciousLoaderStart) return "suspicious_loader_start";
            if (signal.IsHardwareIdentityChange) return "hardware_identifier_change";
            if (signal.IsSuspiciousDriverOrDevice) return "suspicious_driver_or_device_activity";
            return "suspicious_activity";
        }

        private static string EndReason(SessionSignal signal)
        {
            if (signal.IsProtectedProcessExit) return "protected_process_exit";
            if (signal.IsIdentityRevert) return "identifier_revert";
            if (signal.IsCleanup) return "cleanup_behavior";
            if (signal.IsSuspiciousDriverDisappear) return "driver_or_service_disappeared";
            return "session_idle_or_surface_closed";
        }

        private void AddSignal(ReconstructedSession session, SessionSignal signal)
        {
            session.LastSeenUtc = signal.TimestampUtc;
            session.Signals.Add(signal);
            if (session.Signals.Count > 350)
            {
                session.Signals.RemoveAt(0);
            }

            if (!string.IsNullOrWhiteSpace(signal.CaseId)) session.CaseIds.Add(signal.CaseId);
            if (signal.ProcessId.HasValue) session.ProcessIds.Add(signal.ProcessId.Value);
            if (!string.IsNullOrWhiteSpace(signal.ProcessName)) session.Processes.Add(signal.ProcessName);
            if (!string.IsNullOrWhiteSpace(signal.TargetProcessName)) session.Processes.Add(signal.TargetProcessName);
            if (!string.IsNullOrWhiteSpace(signal.Path)) session.Files.Add(signal.Path);
            if (!string.IsNullOrWhiteSpace(signal.DriverName)) session.Drivers.Add(signal.DriverName);
            if (!string.IsNullOrWhiteSpace(signal.IdentifierKey)) session.Identifiers.Add(signal.IdentifierKey);

            if (signal.ConfidenceContribution > 0)
            {
                session.ConfidenceScore = Math.Min(0.99, session.ConfidenceScore + signal.ConfidenceContribution);
                session.ConfidenceTimeline.Add(new ConfidencePoint
                {
                    TimestampUtc = signal.TimestampUtc,
                    Score = session.ConfidenceScore,
                    Reason = signal.ConfidenceReason
                });
            }
        }

        private static void Recalculate(ReconstructedSession session)
        {
            session.Phases.Clear();
            foreach (SessionSignal signal in session.Signals.OrderBy(s => s.TimestampUtc))
            {
                if (!session.Phases.ContainsKey(signal.Phase))
                {
                    session.Phases[signal.Phase] = new List<SessionSignal>();
                }

                session.Phases[signal.Phase].Add(signal);
            }

            session.FingerprintFeatures.Clear();
            foreach (SessionSignal signal in session.Signals.OrderBy(s => s.TimestampUtc).Take(200))
            {
                session.FingerprintFeatures.Add("phase:" + signal.Phase);
                session.FingerprintFeatures.Add("action:" + NormalizeFeature(signal.Action));
                if (!string.IsNullOrWhiteSpace(signal.LoaderStyle)) session.FingerprintFeatures.Add("loader:" + signal.LoaderStyle);
                if (!string.IsNullOrWhiteSpace(signal.CleanupStyle)) session.FingerprintFeatures.Add("cleanup:" + signal.CleanupStyle);
                if (!string.IsNullOrWhiteSpace(signal.SpoofingStyle)) session.FingerprintFeatures.Add("spoofing:" + signal.SpoofingStyle);
                if (!string.IsNullOrWhiteSpace(signal.MemoryStyle)) session.FingerprintFeatures.Add("memory:" + signal.MemoryStyle);
                if (!string.IsNullOrWhiteSpace(signal.CommunicationStyle)) session.FingerprintFeatures.Add("communication:" + signal.CommunicationStyle);
            }

            session.FingerprintFeatures.Add("event_order:" + BuildEventOrder(session.Signals));
            session.FingerprintFeatures.Add("duration_bucket:" + DurationBucket(session));
            session.FingerprintSha256 = HashFeatureSet(session.FingerprintFeatures);
            session.Narrative = BuildNarrative(session);
        }

        private bool ShouldEmitInterim(ReconstructedSession session)
        {
            if (session.ConfidenceScore < 0.65)
            {
                return false;
            }

            int version = session.Signals.Count + session.Phases.Count * 3 + session.ConfidenceTimeline.Count;
            if (version <= session.LastEmittedVersion && DateTime.UtcNow.Subtract(session.LastEmittedUtc) < TimeSpan.FromMinutes(5))
            {
                return false;
            }

            session.LastEmittedVersion = version;
            session.LastEmittedUtc = DateTime.UtcNow;
            return true;
        }

        private void CleanupExpiredSessions(DateTimeOffset now)
        {
            foreach (ReconstructedSession session in _sessions.Values.ToList())
            {
                if (session.Finalized)
                {
                    continue;
                }

                lock (session.SyncRoot)
                {
                    if (session.EndCandidateUtc.HasValue && now.Subtract(session.EndCandidateUtc.Value) >= PostExitHoldWindow)
                    {
                        session.EndReason = string.IsNullOrWhiteSpace(session.EndReason) ? "post_exit_hold_elapsed" : session.EndReason;
                        FinalizeSession(session);
                    }
                    else if (now.Subtract(session.LastSeenUtc) >= IdleFinalizeWindow)
                    {
                        session.EndCandidateUtc = session.LastSeenUtc;
                        session.EndReason = "idle_timeout";
                        FinalizeSession(session);
                    }
                }
            }
        }

        private void FinalizeSession(ReconstructedSession session)
        {
            if (session.Finalized)
            {
                return;
            }

            session.Finalized = true;
            Recalculate(session);
            WriteReplay(session, true);
            ReconstructedSession removed;
            _sessions.TryRemove(session.SessionId, out removed);
        }

        private void WriteReplay(ReconstructedSession session, bool final)
        {
            lock (_writeLock)
            {
                string folder = Path.Combine(_sessionRoot, SanitizeFileName(session.SessionId));
                Directory.CreateDirectory(folder);
                string replayPath = Path.Combine(folder, final ? "session-replay.json" : "session-replay-latest.json");
                string summaryPath = Path.Combine(folder, final ? "session-summary.txt" : "session-summary-latest.txt");
                string graphPath = Path.Combine(folder, final ? "event-graph.json" : "event-graph-latest.json");

                File.WriteAllText(replayPath, BuildReplayJson(session, final), Encoding.UTF8);
                File.WriteAllText(summaryPath, session.Narrative ?? string.Empty, Encoding.UTF8);
                File.WriteAllText(graphPath, BuildGraphJson(session), Encoding.UTF8);

                if (final)
                {
                    AppendFingerprint(session);
                }

                string emitKey = session.SessionId + "|" + final + "|" + session.FingerprintSha256;
                if (_emittedSessions.Add(emitKey))
                {
                    _logger.Log(DetectionEvent.Create(
                        "SessionReplay",
                        final ? "SessionReconstructed" : "SessionReplayUpdated",
                        SeverityForSession(session),
                        session.Narrative,
                        replayPath,
                        null,
                        new Dictionary<string, string>
                        {
                            { "session_id", session.SessionId },
                            { "start_reason", session.StartReason ?? string.Empty },
                            { "end_reason", session.EndReason ?? string.Empty },
                            { "final", final.ToString() },
                            { "confidence_score", session.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) },
                            { "phases", string.Join(";", session.Phases.Keys.OrderBy(p => p).ToArray()) },
                            { "involved_processes", string.Join(";", session.Processes.OrderBy(p => p).Take(40).ToArray()) },
                            { "involved_files", string.Join(";", session.Files.OrderBy(p => p).Take(40).ToArray()) },
                            { "involved_drivers", string.Join(";", session.Drivers.OrderBy(p => p).Take(30).ToArray()) },
                            { "involved_identifiers", string.Join(";", session.Identifiers.OrderBy(p => p).Take(30).ToArray()) },
                            { "fingerprint_sha256", session.FingerprintSha256 ?? string.Empty },
                            { "replay_path", replayPath },
                            { "summary_path", summaryPath },
                            { "event_graph_path", graphPath },
                            { "safety_rule", "Session replay is evidence-only and performs no bypassing, blocking, patching, unloading, or stealth actions." }
                        }));
                }
            }
        }

        private static EventSeverity SeverityForSession(ReconstructedSession session)
        {
            if (session.ConfidenceScore >= 0.86) return EventSeverity.Critical;
            if (session.ConfidenceScore >= 0.65) return EventSeverity.High;
            if (session.ConfidenceScore >= 0.40) return EventSeverity.Medium;
            return EventSeverity.Low;
        }

        private string BuildReplayJson(ReconstructedSession session, bool final)
        {
            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "session_id", session.SessionId, ref first);
            JsonUtilities.AppendStringProperty(builder, "final", final.ToString(), ref first);
            JsonUtilities.AppendStringProperty(builder, "start_utc", session.StartUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "last_seen_utc", session.LastSeenUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "start_reason", session.StartReason, ref first);
            JsonUtilities.AppendStringProperty(builder, "end_reason", session.EndReason, ref first);
            JsonUtilities.AppendNumberProperty(builder, "confidence_score", session.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "fingerprint_sha256", session.FingerprintSha256, ref first);
            JsonUtilities.AppendStringProperty(builder, "session_summary", session.Narrative, ref first);
            AppendStringArray(builder, "involved_processes", session.Processes.OrderBy(p => p), ref first);
            AppendStringArray(builder, "involved_files", session.Files.OrderBy(p => p), ref first);
            AppendStringArray(builder, "involved_drivers", session.Drivers.OrderBy(p => p), ref first);
            AppendStringArray(builder, "involved_identifiers", session.Identifiers.OrderBy(p => p), ref first);
            AppendTimeline(builder, session.Signals.OrderBy(s => s.TimestampUtc), ref first);
            AppendPhases(builder, session, ref first);
            AppendConfidence(builder, session.ConfidenceTimeline, ref first);
            AppendStringArray(builder, "fingerprint_features", session.FingerprintFeatures.OrderBy(f => f), ref first);
            builder.Append("}");
            return builder.ToString();
        }

        private static string BuildGraphJson(ReconstructedSession session)
        {
            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "session_id", session.SessionId, ref first);
            if (!first) builder.Append(",");
            builder.Append("\"nodes\":[");
            bool firstNode = true;
            foreach (SessionSignal signal in session.Signals.OrderBy(s => s.TimestampUtc))
            {
                if (!firstNode) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "id", signal.EventId, ref child);
                JsonUtilities.AppendStringProperty(builder, "label", signal.Phase + ":" + signal.Action, ref child);
                JsonUtilities.AppendStringProperty(builder, "type", signal.Category, ref child);
                JsonUtilities.AppendStringProperty(builder, "timestamp_utc", signal.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref child);
                builder.Append("}");
                firstNode = false;
            }
            builder.Append("]");
            first = false;

            builder.Append(",\"edges\":[");
            bool firstEdge = true;
            SessionSignal previous = null;
            foreach (SessionSignal signal in session.Signals.OrderBy(s => s.TimestampUtc))
            {
                if (previous != null)
                {
                    if (!firstEdge) builder.Append(",");
                    bool child = true;
                    builder.Append("{");
                    JsonUtilities.AppendStringProperty(builder, "from", previous.EventId, ref child);
                    JsonUtilities.AppendStringProperty(builder, "to", signal.EventId, ref child);
                    JsonUtilities.AppendStringProperty(builder, "relationship", previous.Phase == signal.Phase ? "same_phase_sequence" : "phase_transition", ref child);
                    builder.Append("}");
                    firstEdge = false;
                }

                previous = signal;
            }
            builder.Append("]}");
            return builder.ToString();
        }

        private void AppendFingerprint(ReconstructedSession session)
        {
            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "timestamp_utc", DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "session_id", session.SessionId, ref first);
            JsonUtilities.AppendStringProperty(builder, "fingerprint_sha256", session.FingerprintSha256, ref first);
            JsonUtilities.AppendNumberProperty(builder, "confidence_score", session.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "start_reason", session.StartReason, ref first);
            JsonUtilities.AppendStringProperty(builder, "end_reason", session.EndReason, ref first);
            JsonUtilities.AppendStringProperty(builder, "event_order", BuildEventOrder(session.Signals), ref first);
            JsonUtilities.AppendStringProperty(builder, "loader_style", MostCommon(session.Signals.Select(s => s.LoaderStyle)), ref first);
            JsonUtilities.AppendStringProperty(builder, "cleanup_style", MostCommon(session.Signals.Select(s => s.CleanupStyle)), ref first);
            JsonUtilities.AppendStringProperty(builder, "spoofing_behavior", MostCommon(session.Signals.Select(s => s.SpoofingStyle)), ref first);
            JsonUtilities.AppendStringProperty(builder, "memory_behavior", MostCommon(session.Signals.Select(s => s.MemoryStyle)), ref first);
            JsonUtilities.AppendStringProperty(builder, "communication_behavior", MostCommon(session.Signals.Select(s => s.CommunicationStyle)), ref first);
            JsonUtilities.AppendStringProperty(builder, "features", string.Join(";", session.FingerprintFeatures.OrderBy(f => f).Take(120).ToArray()), ref first);
            builder.Append("}");
            File.AppendAllText(_fingerprintPath, builder.ToString() + Environment.NewLine, Encoding.UTF8);
        }

        private static string BuildNarrative(ReconstructedSession session)
        {
            List<string> parts = new List<string>();
            SessionSignal loader = FirstPhaseSignal(session, "Loader");
            SessionSignal game = session.Signals.FirstOrDefault(s => s.IsProtectedProcessStart);
            SessionSignal driver = FirstPhaseSignal(session, "DriverMapping");
            SessionSignal spoof = FirstPhaseSignal(session, "Spoofing");
            SessionSignal target = FirstPhaseSignal(session, "TargetInteraction");
            SessionSignal memory = session.Signals.FirstOrDefault(s => s.IsMemoryAnomaly);
            SessionSignal cleanup = FirstPhaseSignal(session, "Cleanup");

            if (loader != null)
            {
                string timing = game == null ? string.Empty : " " + FriendlyDelta(loader.TimestampUtc, game.TimestampUtc) + " before game start";
                parts.Add("Suspicious loader activity appeared" + timing + ": " + Trim(loader.Description, 120));
            }

            if (driver != null)
            {
                parts.Add("Driver, mapping, or device activity followed: " + Trim(driver.Description, 120));
            }

            if (spoof != null)
            {
                parts.Add("Hardware identity or spoofing behavior was observed: " + Trim(spoof.Description, 120));
            }

            if (game != null)
            {
                parts.Add("Protected process launched: " + game.ProcessName);
            }

            if (target != null)
            {
                parts.Add("Protected target interaction was observed: " + Trim(target.Description, 120));
            }

            if (memory != null)
            {
                parts.Add("Memory anomaly appeared during the session: " + Trim(memory.Description, 120));
            }

            if (cleanup != null)
            {
                parts.Add("Cleanup behavior appeared after or near session end: " + Trim(cleanup.Description, 120));
            }

            if (parts.Count == 0)
            {
                parts.Add("Suspicious session activity was reconstructed from correlated telemetry.");
            }

            parts.Add("Confidence reached " + session.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) + " across phases: " + string.Join(", ", session.Phases.Keys.OrderBy(p => p).ToArray()) + ".");
            return string.Join(" ", parts.ToArray());
        }

        private static SessionSignal FirstPhaseSignal(ReconstructedSession session, string phase)
        {
            List<SessionSignal> signals;
            return session.Phases.TryGetValue(phase, out signals)
                ? signals.OrderBy(s => s.TimestampUtc).FirstOrDefault()
                : null;
        }

        private static string FriendlyDelta(DateTimeOffset earlier, DateTimeOffset later)
        {
            TimeSpan delta = later.Subtract(earlier);
            if (delta < TimeSpan.Zero) delta = earlier.Subtract(later);
            if (delta.TotalMinutes >= 1) return ((int)Math.Round(delta.TotalMinutes)).ToString(CultureInfo.InvariantCulture) + " minute(s)";
            return Math.Max(1, (int)Math.Round(delta.TotalSeconds)).ToString(CultureInfo.InvariantCulture) + " second(s)";
        }

        private static void AppendTimeline(StringBuilder builder, IEnumerable<SessionSignal> signals, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"ordered_event_timeline\":[");
            bool firstItem = true;
            foreach (SessionSignal signal in signals)
            {
                if (!firstItem) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "event_id", signal.EventId, ref child);
                JsonUtilities.AppendStringProperty(builder, "timestamp_utc", signal.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref child);
                JsonUtilities.AppendStringProperty(builder, "phase", signal.Phase, ref child);
                JsonUtilities.AppendStringProperty(builder, "category", signal.Category, ref child);
                JsonUtilities.AppendStringProperty(builder, "action", signal.Action, ref child);
                JsonUtilities.AppendStringProperty(builder, "severity", signal.Severity.ToString(), ref child);
                JsonUtilities.AppendStringProperty(builder, "description", signal.Description, ref child);
                JsonUtilities.AppendStringProperty(builder, "process", signal.ProcessName, ref child);
                JsonUtilities.AppendStringProperty(builder, "path", signal.Path, ref child);
                JsonUtilities.AppendStringProperty(builder, "case_id", signal.CaseId, ref child);
                builder.Append("}");
                firstItem = false;
            }
            builder.Append("]");
            first = false;
        }

        private static void AppendPhases(StringBuilder builder, ReconstructedSession session, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"session_phases\":{");
            bool firstPhase = true;
            foreach (KeyValuePair<string, List<SessionSignal>> phase in session.Phases.OrderBy(p => PhaseOrder(p.Key)))
            {
                if (!firstPhase) builder.Append(",");
                builder.Append("\"");
                builder.Append(JsonUtilities.Escape(phase.Key));
                builder.Append("\":[");
                bool firstItem = true;
                foreach (SessionSignal signal in phase.Value.OrderBy(s => s.TimestampUtc).Take(80))
                {
                    if (!firstItem) builder.Append(",");
                    bool child = true;
                    builder.Append("{");
                    JsonUtilities.AppendStringProperty(builder, "timestamp_utc", signal.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref child);
                    JsonUtilities.AppendStringProperty(builder, "action", signal.Action, ref child);
                    JsonUtilities.AppendStringProperty(builder, "description", signal.Description, ref child);
                    builder.Append("}");
                    firstItem = false;
                }
                builder.Append("]");
                firstPhase = false;
            }
            builder.Append("}");
            first = false;
        }

        private static void AppendConfidence(StringBuilder builder, IEnumerable<ConfidencePoint> points, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"confidence_escalation_timeline\":[");
            bool firstPoint = true;
            foreach (ConfidencePoint point in points)
            {
                if (!firstPoint) builder.Append(",");
                bool child = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "timestamp_utc", point.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref child);
                JsonUtilities.AppendNumberProperty(builder, "score", point.Score.ToString("0.00", CultureInfo.InvariantCulture), ref child);
                JsonUtilities.AppendStringProperty(builder, "reason", point.Reason, ref child);
                builder.Append("}");
                firstPoint = false;
            }
            builder.Append("]");
            first = false;
        }

        private static void AppendStringArray(StringBuilder builder, string name, IEnumerable<string> values, ref bool first)
        {
            if (!first) builder.Append(",");
            builder.Append("\"");
            builder.Append(JsonUtilities.Escape(name));
            builder.Append("\":[");
            bool firstValue = true;
            foreach (string value in values.Where(v => !string.IsNullOrWhiteSpace(v)).Take(120))
            {
                if (!firstValue) builder.Append(",");
                builder.Append("\"");
                builder.Append(JsonUtilities.Escape(value));
                builder.Append("\"");
                firstValue = false;
            }
            builder.Append("]");
            first = false;
        }

        private static int PhaseOrder(string phase)
        {
            if (phase == "Preparation") return 0;
            if (phase == "Loader") return 1;
            if (phase == "DriverMapping") return 2;
            if (phase == "Spoofing") return 3;
            if (phase == "TargetInteraction") return 4;
            if (phase == "Cleanup") return 5;
            return 99;
        }

        private static string BuildEventOrder(IEnumerable<SessionSignal> signals)
        {
            return string.Join(">", signals
                .OrderBy(s => s.TimestampUtc)
                .Select(s => s.Phase)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Take(40)
                .ToArray());
        }

        private static string DurationBucket(ReconstructedSession session)
        {
            double minutes = Math.Max(0, session.LastSeenUtc.Subtract(session.StartUtc).TotalMinutes);
            if (minutes < 2) return "under_2m";
            if (minutes < 10) return "2m_to_10m";
            if (minutes < 30) return "10m_to_30m";
            return "over_30m";
        }

        private static string HashFeatureSet(IEnumerable<string> features)
        {
            return HashText(string.Join("\n", features.Where(f => !string.IsNullOrWhiteSpace(f)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(f => f).ToArray()));
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

        private static string NormalizeFeature(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return "unknown";
            string lower = value.ToLowerInvariant();
            StringBuilder builder = new StringBuilder(lower.Length);
            foreach (char c in lower)
            {
                builder.Append(char.IsLetterOrDigit(c) ? c : '_');
            }
            return builder.ToString().Trim('_');
        }

        private static string MostCommon(IEnumerable<string> values)
        {
            return values
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .GroupBy(v => v, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(g => g.Count())
                .Select(g => g.Key)
                .FirstOrDefault() ?? string.Empty;
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

        private static string Detail(DetectionEvent detectionEvent, string key)
        {
            string value;
            return detectionEvent != null &&
                   detectionEvent.Details != null &&
                   detectionEvent.Details.TryGetValue(key, out value)
                ? value ?? string.Empty
                : string.Empty;
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
            if (string.IsNullOrWhiteSpace(value)) return "session";
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

            foreach (ReconstructedSession session in _sessions.Values.ToList())
            {
                lock (session.SyncRoot)
                {
                    session.EndReason = string.IsNullOrWhiteSpace(session.EndReason) ? "monitor_shutdown" : session.EndReason;
                    FinalizeSession(session);
                }
            }
        }

        private sealed class ReconstructedSession
        {
            public ReconstructedSession()
            {
                Signals = new List<SessionSignal>();
                Phases = new Dictionary<string, List<SessionSignal>>(StringComparer.OrdinalIgnoreCase);
                Processes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Drivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Identifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                CaseIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                ProcessIds = new HashSet<int>();
                FingerprintFeatures = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                ConfidenceTimeline = new List<ConfidencePoint>();
            }

            public object SyncRoot { get; } = new object();
            public string SessionId { get; set; }
            public DateTimeOffset StartUtc { get; set; }
            public DateTimeOffset LastSeenUtc { get; set; }
            public DateTimeOffset? EndCandidateUtc { get; set; }
            public string StartReason { get; set; }
            public string EndReason { get; set; }
            public bool Finalized { get; set; }
            public double ConfidenceScore { get; set; }
            public string FingerprintSha256 { get; set; }
            public string Narrative { get; set; }
            public int LastEmittedVersion { get; set; }
            public DateTime LastEmittedUtc { get; set; }
            public List<SessionSignal> Signals { get; private set; }
            public Dictionary<string, List<SessionSignal>> Phases { get; private set; }
            public HashSet<string> Processes { get; private set; }
            public HashSet<string> Files { get; private set; }
            public HashSet<string> Drivers { get; private set; }
            public HashSet<string> Identifiers { get; private set; }
            public HashSet<string> CaseIds { get; private set; }
            public HashSet<int> ProcessIds { get; private set; }
            public HashSet<string> FingerprintFeatures { get; private set; }
            public List<ConfidencePoint> ConfidenceTimeline { get; private set; }
        }

        private sealed class ConfidencePoint
        {
            public DateTimeOffset TimestampUtc { get; set; }
            public double Score { get; set; }
            public string Reason { get; set; }
        }

        private sealed class SessionSignal
        {
            public DateTimeOffset TimestampUtc { get; private set; }
            public string EventId { get; private set; }
            public string EventKey { get; private set; }
            public string Category { get; private set; }
            public string Action { get; private set; }
            public EventSeverity Severity { get; private set; }
            public string Description { get; private set; }
            public string Path { get; private set; }
            public int? ProcessId { get; private set; }
            public string ProcessName { get; private set; }
            public string TargetProcessName { get; private set; }
            public string CaseId { get; private set; }
            public string DriverName { get; private set; }
            public string IdentifierKey { get; private set; }
            public string Phase { get; private set; }
            public string LoaderStyle { get; private set; }
            public string CleanupStyle { get; private set; }
            public string SpoofingStyle { get; private set; }
            public string MemoryStyle { get; private set; }
            public string CommunicationStyle { get; private set; }
            public bool IsProtectedProcessStart { get; private set; }
            public bool IsProtectedProcessExit { get; private set; }
            public bool IsSuspiciousLoaderStart { get; private set; }
            public bool IsHardwareIdentityChange { get; private set; }
            public bool IsIdentityRevert { get; private set; }
            public bool IsSuspiciousDriverOrDevice { get; private set; }
            public bool IsSuspiciousDriverDisappear { get; private set; }
            public bool IsCleanup { get; private set; }
            public bool IsTargetInteraction { get; private set; }
            public bool IsMemoryAnomaly { get; private set; }
            public bool IsCommunicationSurface { get; private set; }
            public bool IsRegistryChange { get; private set; }
            public bool IsFileArtifact { get; private set; }
            public bool IsHighSignal { get; private set; }
            public double ConfidenceContribution { get; private set; }
            public string ConfidenceReason { get; private set; }

            public static SessionSignal FromEvent(DetectionEvent detectionEvent, MonitorOptions options)
            {
                string text = EventText(detectionEvent);
                string processName = FirstNonEmpty(detectionEvent.ProcessName, Detail(detectionEvent, "process_name"), Detail(detectionEvent, "source_process_name"), System.IO.Path.GetFileName(detectionEvent.Path));
                string targetName = FirstNonEmpty(Detail(detectionEvent, "target_process_name"), Detail(detectionEvent, "TargetImage"), System.IO.Path.GetFileName(Detail(detectionEvent, "target_path")));
                bool processStart = ContainsAny(detectionEvent.Action, "Executed", "ProcessCreated", "Started");
                bool processExit = ContainsAny(detectionEvent.Action, "Exited", "ProcessExited");
                bool protectedName = !string.IsNullOrWhiteSpace(processName) && TargetProcessMatcher.IsProtectedProcessName(processName, options.ProtectedProcessNames);

                SessionSignal signal = new SessionSignal
                {
                    TimestampUtc = detectionEvent.TimestampUtc,
                    Category = detectionEvent.Category ?? string.Empty,
                    Action = detectionEvent.Action ?? string.Empty,
                    Severity = detectionEvent.Severity,
                    Description = detectionEvent.Description ?? string.Empty,
                    Path = detectionEvent.Path ?? string.Empty,
                    ProcessId = detectionEvent.ProcessId,
                    ProcessName = processName,
                    TargetProcessName = targetName,
                    CaseId = FirstNonEmpty(Detail(detectionEvent, "case_id"), Detail(detectionEvent, "behavior_case_id"), Detail(detectionEvent, "launch_session_case_id"), Detail(detectionEvent, "capture_id")),
                    DriverName = FirstNonEmpty(Detail(detectionEvent, "driver_file_name"), Detail(detectionEvent, "driver_path"), Detail(detectionEvent, "service_name"), Detail(detectionEvent, "ServiceName")),
                    IdentifierKey = FirstNonEmpty(Detail(detectionEvent, "identity_key"), Detail(detectionEvent, "changed_identifier"), Detail(detectionEvent, "identifier_type")),
                    IsProtectedProcessStart = protectedName && processStart,
                    IsProtectedProcessExit = protectedName && processExit,
                    IsSuspiciousLoaderStart = processStart && (detectionEvent.Severity >= EventSeverity.High || ContainsAny(text, "loader", "mapper", "kdmapper", "unsigned", "downloads", "\\temp\\", "mark_of_the_web")),
                    IsHardwareIdentityChange = detectionEvent.Category.StartsWith("HardwareIdentity", StringComparison.OrdinalIgnoreCase) && ContainsAny(detectionEvent.Action, "HardwareIdentifier", "HwidSpooferProfile", "HardwareChangeAttributed", "SpooferCleanupTraceDetected"),
                    IsIdentityRevert = ContainsAny(detectionEvent.Action, "Reverted", "SpooferCleanupTraceDetected") || ContainsAny(text, "reverted_identifiers", "post_launch_revert"),
                    IsSuspiciousDriverOrDevice = ContainsAny(detectionEvent.Category, "HiddenKernel", "KernelComm") || ContainsAny(detectionEvent.Action, "Driver", "Device", "ServiceInstalled", "ServiceRunningModuleMissing", "SuspiciousDevice"),
                    IsSuspiciousDriverDisappear = ContainsAny(detectionEvent.Action, "DriverFileDeleted", "ShortLivedDriverFileDeleted", "ServiceRemoved", "driver_service_deleted"),
                    IsCleanup = ContainsAny(detectionEvent.Action, "SpooferCleanupTraceDetected", "ShortLivedStagingFileDeleted", "ShortLivedDriverFileDeleted", "AuditLogCleared", "EventLogCleared", "KeyDeleted", "ValueDeleted") || ContainsAny(text, "cleanup", "prefetch", "amcache", "shimcache", "wevtutil cl"),
                    IsTargetInteraction = ContainsAny(detectionEvent.Category, "TargetInteraction") || ContainsAny(detectionEvent.Action, "ProcessOpenedProtectedTarget", "Target", "VM_WRITE", "ProcessAccessed"),
                    IsMemoryAnomaly = ContainsAny(detectionEvent.Action, "PrivateExecutableMemory", "RwxPrivateMemory", "PrivatePeHeader", "UnsignedMappedDll", "ThreadStartOutside"),
                    IsCommunicationSurface = ContainsAny(detectionEvent.Category, "KernelComm") || ContainsAny(detectionEvent.Action, "SuspiciousDeviceObjectHandle", "SuspiciousSharedSectionWithTarget", "CommunicationChainCorrelated", "SuspiciousNamedPipeHandle", "SuspiciousSectionHandle"),
                    IsRegistryChange = detectionEvent.Category.IndexOf("Registry", StringComparison.OrdinalIgnoreCase) >= 0 || ContainsAny(detectionEvent.Action, "Registry"),
                    IsFileArtifact = detectionEvent.Category.Equals("File", StringComparison.OrdinalIgnoreCase) || ContainsAny(detectionEvent.Action, "Downloaded", "FileCreated", "FileDeleted", "ShortLived")
                };

                signal.IsHighSignal = signal.Severity >= EventSeverity.High ||
                                      signal.IsHardwareIdentityChange ||
                                      signal.IsSuspiciousDriverOrDevice ||
                                      signal.IsTargetInteraction ||
                                      signal.IsMemoryAnomaly ||
                                      signal.IsCommunicationSurface ||
                                      signal.IsCleanup;
                signal.Phase = ClassifyPhase(signal, text);
                signal.LoaderStyle = ClassifyLoaderStyle(signal, text);
                signal.CleanupStyle = ClassifyCleanupStyle(signal, text);
                signal.SpoofingStyle = ClassifySpoofingStyle(signal, text);
                signal.MemoryStyle = ClassifyMemoryStyle(signal, text);
                signal.CommunicationStyle = ClassifyCommunicationStyle(signal, text);
                signal.ConfidenceContribution = CalculateConfidenceContribution(signal);
                signal.ConfidenceReason = BuildConfidenceReason(signal);
                signal.EventKey = signal.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) + "|" + signal.Category + "|" + signal.Action + "|" + signal.Description + "|" + signal.Path;
                signal.EventId = "evt-" + HashText(signal.EventKey).Substring(0, 12);
                return signal;
            }

            private static string ClassifyPhase(SessionSignal signal, string text)
            {
                if (signal.IsCleanup || signal.IsIdentityRevert || signal.IsSuspiciousDriverDisappear) return "Cleanup";
                if (signal.IsTargetInteraction || signal.IsMemoryAnomaly) return "TargetInteraction";
                if (signal.IsHardwareIdentityChange || ContainsAny(text, "hwid", "identifier", "mac", "smbios", "machineguid")) return "Spoofing";
                if (signal.IsSuspiciousDriverOrDevice || signal.IsCommunicationSurface) return "DriverMapping";
                if (signal.IsSuspiciousLoaderStart) return "Loader";
                if (signal.IsProtectedProcessStart || signal.IsRegistryChange || signal.IsFileArtifact) return "Preparation";
                return "Unclassified";
            }

            private static string ClassifyLoaderStyle(SessionSignal signal, string text)
            {
                if (!signal.IsSuspiciousLoaderStart && !ContainsAny(text, "loader", "mapper")) return string.Empty;
                if (ContainsAny(text, "kdmapper", "mapper", "manual_map")) return "mapper_style";
                if (ContainsAny(text, "\\temp\\", "\\downloads\\", "mark_of_the_web")) return "download_or_temp_loader";
                if (ContainsAny(text, "unsigned", "untrusted")) return "unsigned_loader";
                return "generic_loader";
            }

            private static string ClassifyCleanupStyle(SessionSignal signal, string text)
            {
                if (!signal.IsCleanup && !signal.IsIdentityRevert) return string.Empty;
                if (ContainsAny(text, "eventlog", "auditlog", "wevtutil", "clear-eventlog")) return "event_log_cleanup";
                if (ContainsAny(text, "shortlived", "short-lived", "deleted artifact")) return "short_lived_artifact_cleanup";
                if (ContainsAny(text, "prefetch", "amcache", "shimcache")) return "trace_store_cleanup";
                if (signal.IsIdentityRevert) return "identifier_revert_cleanup";
                return "generic_cleanup";
            }

            private static string ClassifySpoofingStyle(SessionSignal signal, string text)
            {
                if (!signal.IsHardwareIdentityChange && !ContainsAny(text, "hwid", "identifier", "mac", "smbios", "machineguid")) return string.Empty;
                if (ContainsAny(text, "network.mac", "mac", "adapter")) return "network_mac_spoofing";
                if (ContainsAny(text, "disk", "volume", "storage")) return "disk_volume_spoofing";
                if (ContainsAny(text, "smbios", "bios", "baseboard", "uuid")) return "smbios_spoofing";
                if (ContainsAny(text, "machineguid")) return "registry_identity_spoofing";
                return "generic_hwid_spoofing";
            }

            private static string ClassifyMemoryStyle(SessionSignal signal, string text)
            {
                if (!signal.IsMemoryAnomaly) return string.Empty;
                if (ContainsAny(text, "mem_private", "private executable")) return "private_executable_memory";
                if (ContainsAny(text, "rwx")) return "rwx_memory";
                if (ContainsAny(text, "unsigned mapped dll")) return "unsigned_mapped_dll";
                return "target_memory_anomaly";
            }

            private static string ClassifyCommunicationStyle(SessionSignal signal, string text)
            {
                if (!signal.IsCommunicationSurface) return string.Empty;
                if (ContainsAny(text, "device")) return "device_object_channel";
                if (ContainsAny(text, "section", "shared memory")) return "shared_section_channel";
                if (ContainsAny(text, "pipe")) return "named_pipe_channel";
                return "kernel_communication_surface";
            }

            private static double CalculateConfidenceContribution(SessionSignal signal)
            {
                if (signal.IsCleanup && signal.IsIdentityRevert) return 0.22;
                if (signal.IsMemoryAnomaly || signal.IsTargetInteraction) return 0.16;
                if (signal.IsSuspiciousDriverOrDevice || signal.IsCommunicationSurface) return 0.15;
                if (signal.IsHardwareIdentityChange) return 0.14;
                if (signal.IsSuspiciousLoaderStart) return 0.12;
                if (signal.IsProtectedProcessStart) return 0.08;
                if (signal.Severity >= EventSeverity.High) return 0.07;
                return 0;
            }

            private static string BuildConfidenceReason(SessionSignal signal)
            {
                if (signal.IsCleanup && signal.IsIdentityRevert) return "cleanup_and_identifier_revert";
                if (signal.IsMemoryAnomaly) return "target_memory_anomaly";
                if (signal.IsTargetInteraction) return "target_process_interaction";
                if (signal.IsCommunicationSurface) return "kernel_or_shared_communication_surface";
                if (signal.IsSuspiciousDriverOrDevice) return "driver_or_device_activity";
                if (signal.IsHardwareIdentityChange) return "hardware_identity_change";
                if (signal.IsSuspiciousLoaderStart) return "suspicious_loader_start";
                if (signal.IsProtectedProcessStart) return "protected_process_launch";
                return "high_severity_signal";
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
        }
    }
}
