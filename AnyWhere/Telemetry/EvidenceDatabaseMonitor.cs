using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace AnyWhere.Telemetry
{
    internal sealed class EvidenceDatabaseMonitor : IDetectionMonitor
    {
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly EvidenceDatabase _database;
        private bool _disposed;

        public EvidenceDatabaseMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            string logRoot = Path.GetDirectoryName(logger.JsonLogPath);
            string databasePath = string.IsNullOrWhiteSpace(options.EvidenceDatabasePath)
                ? Path.Combine(logRoot, "AegisEvidence.db")
                : options.EvidenceDatabasePath;
            _database = new EvidenceDatabase(databasePath);
        }

        public string Name
        {
            get { return "Evidence Database"; }
        }

        public EvidenceDatabase Database
        {
            get { return _database; }
        }

        public void Start()
        {
            if (!_options.EvidenceDatabaseEnabled)
            {
                _logger.Log(DetectionEvent.Create(
                    "EvidenceDatabase",
                    "Disabled",
                    EventSeverity.Low,
                    "SQLite evidence database is disabled by configuration.",
                    null,
                    null,
                    null));
                return;
            }

            try
            {
                _database.Initialize();
                ApplyCaseManagementOptions();
                _logger.EventLogged += OnEventLogged;

                _logger.Log(DetectionEvent.Create(
                    "EvidenceDatabase",
                    "Started",
                    EventSeverity.Low,
                    "SQLite evidence database initialized.",
                    _database.DatabasePath,
                    null,
                    new Dictionary<string, string>
                    {
                        { "database_path", _database.DatabasePath },
                        { "storage_model", "SQLite events, details, cases, case notes, tags, artifacts, and artifact-event links." },
                        { "query_surfaces", "timeline;cases;artifacts;fingerprints;historical replay;cross-case search" }
                    }));
            }
            catch (Exception ex)
            {
                _logger.LogException("EvidenceDatabase", "StartFailed", ex, _database.DatabasePath);
            }
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed ||
                detectionEvent == null ||
                detectionEvent.Category.StartsWith("EvidenceDatabase", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            try
            {
                _database.InsertEvent(detectionEvent);
            }
            catch (Exception ex)
            {
                _logger.LogException("EvidenceDatabase", "InsertFailed", ex, detectionEvent.Category + "/" + detectionEvent.Action);
            }
        }

        private void ApplyCaseManagementOptions()
        {
            foreach (string update in _options.CaseStatusUpdates)
            {
                string[] parts = SplitManualValue(update, 3);
                if (parts.Length >= 2)
                {
                    _database.UpdateCaseStatus(parts[0], parts[1], parts.Length >= 3 ? parts[2] : string.Empty);
                }
            }

            foreach (string note in _options.CaseNotes)
            {
                string[] parts = SplitManualValue(note, 2);
                if (parts.Length >= 2)
                {
                    _database.AddCaseNote(parts[0], parts[1], Environment.UserName);
                }
            }

            foreach (string tag in _options.CaseTags)
            {
                string[] parts = SplitManualValue(tag, 2);
                if (parts.Length >= 2)
                {
                    _database.AddCaseTag(parts[0], parts[1]);
                }
            }
        }

        private static string[] SplitManualValue(string value, int maxParts)
        {
            return (value ?? string.Empty).Split(new[] { '|' }, maxParts, StringSplitOptions.None);
        }

        public void Dispose()
        {
            _disposed = true;
            _logger.EventLogged -= OnEventLogged;
        }
    }
}
