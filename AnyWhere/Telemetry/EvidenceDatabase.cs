using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Data.Sqlite;

namespace AnyWhere.Telemetry
{
    internal sealed class EvidenceDatabase
    {
        private readonly object _syncRoot = new object();
        private readonly string _connectionString;
        private bool _initialized;

        public EvidenceDatabase(string databasePath)
        {
            if (!string.IsNullOrWhiteSpace(databasePath) && string.IsNullOrWhiteSpace(Path.GetDirectoryName(databasePath)))
            {
                databasePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, databasePath);
            }

            DatabasePath = databasePath;
            _connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Cache = SqliteCacheMode.Shared
            }.ToString();
        }

        public string DatabasePath { get; private set; }

        public void Initialize()
        {
            lock (_syncRoot)
            {
                if (_initialized)
                {
                    return;
                }

                string directory = Path.GetDirectoryName(DatabasePath);
                Directory.CreateDirectory(directory);
                SQLitePCL.Batteries_V2.Init();

                using (SqliteConnection connection = OpenConnection())
                {
                    ExecuteNonQuery(connection, "PRAGMA journal_mode=WAL;");
                    ExecuteNonQuery(connection, "PRAGMA synchronous=NORMAL;");
                    ExecuteNonQuery(connection, SchemaSql());
                    TryExecuteNonQuery(connection, "ALTER TABLE cases ADD COLUMN severity_rank INTEGER NOT NULL DEFAULT 0;");
                    UpsertMetadata(connection, "schema_version", "1");
                    UpsertMetadata(connection, "created_or_opened_utc", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
                }

                _initialized = true;
            }
        }

        public long InsertEvent(DetectionEvent detectionEvent)
        {
            if (detectionEvent == null)
            {
                return 0;
            }

            lock (_syncRoot)
            {
                EnsureInitialized();
                using (SqliteConnection connection = OpenConnection())
                using (SqliteTransaction transaction = connection.BeginTransaction())
                {
                    string caseId = ExtractCaseId(detectionEvent);
                    string json = EventToJson(detectionEvent);
                    long eventId;

                    using (SqliteCommand command = connection.CreateCommand())
                    {
                        command.Transaction = transaction;
                        command.CommandText =
                            "INSERT INTO events(timestamp_utc, category, action, severity, severity_rank, description, path, process_id, process_name, case_id, json) " +
                            "VALUES($timestamp, $category, $action, $severity, $severityRank, $description, $path, $processId, $processName, $caseId, $json); " +
                            "SELECT last_insert_rowid();";
                        AddParameter(command, "$timestamp", detectionEvent.TimestampUtc.UtcDateTime.ToString("o", CultureInfo.InvariantCulture));
                        AddParameter(command, "$category", detectionEvent.Category);
                        AddParameter(command, "$action", detectionEvent.Action);
                        AddParameter(command, "$severity", detectionEvent.Severity.ToString());
                        AddParameter(command, "$severityRank", (int)detectionEvent.Severity);
                        AddParameter(command, "$description", detectionEvent.Description);
                        AddParameter(command, "$path", detectionEvent.Path);
                        AddParameter(command, "$processId", detectionEvent.ProcessId.HasValue ? (object)detectionEvent.ProcessId.Value : DBNull.Value);
                        AddParameter(command, "$processName", detectionEvent.ProcessName);
                        AddParameter(command, "$caseId", caseId);
                        AddParameter(command, "$json", json);
                        eventId = Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture);
                    }

                    foreach (KeyValuePair<string, string> pair in detectionEvent.Details)
                    {
                        InsertEventDetail(connection, transaction, eventId, pair.Key, pair.Value);
                    }

                    if (!string.IsNullOrWhiteSpace(caseId))
                    {
                        UpsertCaseInternal(connection, transaction, caseId, detectionEvent, eventId);
                        InsertCaseEvent(connection, transaction, caseId, eventId, "source_event");
                    }

                    foreach (ArtifactObservation artifact in ExtractArtifacts(detectionEvent))
                    {
                        long artifactId = UpsertArtifact(connection, transaction, artifact, detectionEvent.TimestampUtc.UtcDateTime, eventId);
                        LinkArtifactEvent(connection, transaction, artifactId, eventId, caseId);
                    }

                    transaction.Commit();
                    return eventId;
                }
            }
        }

        public void UpdateCaseStatus(string caseId, string status, string note)
        {
            if (string.IsNullOrWhiteSpace(caseId) || string.IsNullOrWhiteSpace(status))
            {
                return;
            }

            lock (_syncRoot)
            {
                EnsureInitialized();
                using (SqliteConnection connection = OpenConnection())
                using (SqliteTransaction transaction = connection.BeginTransaction())
                {
                    ExecuteNonQuery(connection, transaction,
                "INSERT INTO cases(case_id, first_seen_utc, last_seen_utc, status, severity, confidence, summary, source, path, evidence_folder, profile, tags) " +
                "VALUES($caseId, $now, $now, $status, '', 0, '', 'manual', '', '', '', '') " +
                        "ON CONFLICT(case_id) DO UPDATE SET status=$status, last_seen_utc=$now;",
                        new Dictionary<string, object>
                        {
                            { "$caseId", caseId },
                            { "$now", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) },
                            { "$status", status }
                        });

                    if (!string.IsNullOrWhiteSpace(note))
                    {
                        AddCaseNoteInternal(connection, transaction, caseId, "status: " + status + " - " + note, "local");
                    }

                    transaction.Commit();
                }
            }
        }

        public void AddCaseNote(string caseId, string note, string analyst)
        {
            if (string.IsNullOrWhiteSpace(caseId) || string.IsNullOrWhiteSpace(note))
            {
                return;
            }

            lock (_syncRoot)
            {
                EnsureInitialized();
                using (SqliteConnection connection = OpenConnection())
                using (SqliteTransaction transaction = connection.BeginTransaction())
                {
                    AddCaseNoteInternal(connection, transaction, caseId, note, string.IsNullOrWhiteSpace(analyst) ? "local" : analyst);
                    transaction.Commit();
                }
            }
        }

        public void AddCaseTag(string caseId, string tag)
        {
            if (string.IsNullOrWhiteSpace(caseId) || string.IsNullOrWhiteSpace(tag))
            {
                return;
            }

            lock (_syncRoot)
            {
                EnsureInitialized();
                using (SqliteConnection connection = OpenConnection())
                using (SqliteTransaction transaction = connection.BeginTransaction())
                {
                    AddCaseTagInternal(connection, transaction, caseId, tag);
                    transaction.Commit();
                }
            }
        }

        public DataTable QueryTable(string sql, IDictionary<string, object> parameters)
        {
            lock (_syncRoot)
            {
                EnsureInitialized();
                using (SqliteConnection connection = OpenConnection())
                using (SqliteCommand command = connection.CreateCommand())
                {
                    command.CommandText = sql;
                    if (parameters != null)
                    {
                        foreach (KeyValuePair<string, object> pair in parameters)
                        {
                            AddParameter(command, pair.Key, pair.Value);
                        }
                    }

                    using (SqliteDataReader reader = command.ExecuteReader())
                    {
                        DataTable table = new DataTable();
                        table.Load(reader);
                        return table;
                    }
                }
            }
        }

        private void EnsureInitialized()
        {
            if (!_initialized)
            {
                Initialize();
            }
        }

        private SqliteConnection OpenConnection()
        {
            SqliteConnection connection = new SqliteConnection(_connectionString);
            connection.Open();
            return connection;
        }

        private static void UpsertCaseInternal(SqliteConnection connection, SqliteTransaction transaction, string caseId, DetectionEvent detectionEvent, long eventId)
        {
            string confidence = FirstNonEmpty(Detail(detectionEvent, "confidence_score"), Detail(detectionEvent, "score"), Detail(detectionEvent, "behavior_confidence"));
            double confidenceValue;
            double.TryParse(confidence, NumberStyles.Float, CultureInfo.InvariantCulture, out confidenceValue);

            string summary = FirstNonEmpty(Detail(detectionEvent, "case_summary"), Detail(detectionEvent, "narrative"), detectionEvent.Description);
            string evidenceFolder = Detail(detectionEvent, "evidence_folder_path");
            string profile = FirstNonEmpty(Detail(detectionEvent, "profile_name"), Detail(detectionEvent, "behavior_profiles"), Detail(detectionEvent, "rule_id"));
            string tags = FirstNonEmpty(Detail(detectionEvent, "behavior_tags"), Detail(detectionEvent, "matched_tags"), Detail(detectionEvent, "case_tags"));

            ExecuteNonQuery(connection, transaction,
                "INSERT INTO cases(case_id, first_seen_utc, last_seen_utc, status, severity, severity_rank, confidence, summary, source, path, evidence_folder, profile, tags) " +
                "VALUES($caseId, $timestamp, $timestamp, 'open', $severity, $severityRank, $confidence, $summary, $source, $path, $evidenceFolder, $profile, $tags) " +
                "ON CONFLICT(case_id) DO UPDATE SET last_seen_utc=$timestamp, severity=CASE WHEN $severityRank > severity_rank THEN $severity ELSE severity END, severity_rank=MAX(severity_rank, $severityRank), " +
                "confidence=MAX(confidence, $confidence), summary=CASE WHEN length($summary) > 0 THEN $summary ELSE summary END, " +
                "path=CASE WHEN length($path) > 0 THEN $path ELSE path END, evidence_folder=CASE WHEN length($evidenceFolder) > 0 THEN $evidenceFolder ELSE evidence_folder END, " +
                "profile=CASE WHEN length($profile) > 0 THEN $profile ELSE profile END, tags=CASE WHEN length($tags) > 0 THEN $tags ELSE tags END;",
                new Dictionary<string, object>
                {
                    { "$caseId", caseId },
                    { "$timestamp", detectionEvent.TimestampUtc.UtcDateTime.ToString("o", CultureInfo.InvariantCulture) },
                    { "$severity", detectionEvent.Severity.ToString() },
                    { "$severityRank", (int)detectionEvent.Severity },
                    { "$confidence", confidenceValue },
                    { "$summary", summary ?? string.Empty },
                    { "$source", detectionEvent.Category + "/" + detectionEvent.Action },
                    { "$path", detectionEvent.Path ?? string.Empty },
                    { "$evidenceFolder", evidenceFolder ?? string.Empty },
                    { "$profile", profile ?? string.Empty },
                    { "$tags", tags ?? string.Empty }
                });

            if (!string.IsNullOrWhiteSpace(tags))
            {
                foreach (string tag in SplitTags(tags))
                {
                    AddCaseTagInternal(connection, transaction, caseId, tag);
                }
            }
        }

        private static void InsertCaseEvent(SqliteConnection connection, SqliteTransaction transaction, string caseId, long eventId, string relation)
        {
            ExecuteNonQuery(connection, transaction,
                "INSERT OR IGNORE INTO case_events(case_id, event_id, relation) VALUES($caseId, $eventId, $relation);",
                new Dictionary<string, object>
                {
                    { "$caseId", caseId },
                    { "$eventId", eventId },
                    { "$relation", relation }
                });
        }

        private static void InsertEventDetail(SqliteConnection connection, SqliteTransaction transaction, long eventId, string key, string value)
        {
            ExecuteNonQuery(connection, transaction,
                "INSERT INTO event_details(event_id, detail_key, detail_value) VALUES($eventId, $key, $value);",
                new Dictionary<string, object>
                {
                    { "$eventId", eventId },
                    { "$key", key ?? string.Empty },
                    { "$value", value ?? string.Empty }
                });
        }

        private static long UpsertArtifact(SqliteConnection connection, SqliteTransaction transaction, ArtifactObservation artifact, DateTime timestampUtc, long eventId)
        {
            ExecuteNonQuery(connection, transaction,
                "INSERT INTO artifacts(artifact_type, value, normalized_value, first_seen_utc, last_seen_utc, seen_count, last_event_id) " +
                "VALUES($type, $value, $normalized, $timestamp, $timestamp, 1, $eventId) " +
                "ON CONFLICT(artifact_type, normalized_value) DO UPDATE SET last_seen_utc=$timestamp, seen_count=seen_count+1, last_event_id=$eventId;",
                new Dictionary<string, object>
                {
                    { "$type", artifact.Type },
                    { "$value", artifact.Value },
                    { "$normalized", artifact.NormalizedValue },
                    { "$timestamp", timestampUtc.ToString("o", CultureInfo.InvariantCulture) },
                    { "$eventId", eventId }
                });

            using (SqliteCommand command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = "SELECT artifact_id FROM artifacts WHERE artifact_type=$type AND normalized_value=$normalized;";
                AddParameter(command, "$type", artifact.Type);
                AddParameter(command, "$normalized", artifact.NormalizedValue);
                object value = command.ExecuteScalar();
                return value == null ? 0 : Convert.ToInt64(value, CultureInfo.InvariantCulture);
            }
        }

        private static void LinkArtifactEvent(SqliteConnection connection, SqliteTransaction transaction, long artifactId, long eventId, string caseId)
        {
            if (artifactId <= 0)
            {
                return;
            }

            ExecuteNonQuery(connection, transaction,
                "INSERT OR IGNORE INTO artifact_events(artifact_id, event_id, case_id) VALUES($artifactId, $eventId, $caseId);",
                new Dictionary<string, object>
                {
                    { "$artifactId", artifactId },
                    { "$eventId", eventId },
                    { "$caseId", caseId ?? string.Empty }
                });
        }

        private static void AddCaseNoteInternal(SqliteConnection connection, SqliteTransaction transaction, string caseId, string note, string analyst)
        {
            ExecuteNonQuery(connection, transaction,
                "INSERT INTO case_notes(case_id, timestamp_utc, analyst, note) VALUES($caseId, $timestamp, $analyst, $note);",
                new Dictionary<string, object>
                {
                    { "$caseId", caseId },
                    { "$timestamp", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) },
                    { "$analyst", analyst ?? "local" },
                    { "$note", note ?? string.Empty }
                });
        }

        private static void AddCaseTagInternal(SqliteConnection connection, SqliteTransaction transaction, string caseId, string tag)
        {
            string normalized = NormalizeTag(tag);
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return;
            }

            ExecuteNonQuery(connection, transaction,
                "INSERT OR IGNORE INTO case_tags(case_id, tag, first_seen_utc) VALUES($caseId, $tag, $timestamp);",
                new Dictionary<string, object>
                {
                    { "$caseId", caseId },
                    { "$tag", normalized },
                    { "$timestamp", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) }
                });
        }

        private static IEnumerable<ArtifactObservation> ExtractArtifacts(DetectionEvent detectionEvent)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            AddArtifact(seen, "file_path", detectionEvent.Path);
            AddArtifact(seen, "process_name", detectionEvent.ProcessName);

            foreach (KeyValuePair<string, string> detail in detectionEvent.Details)
            {
                string key = detail.Key ?? string.Empty;
                string value = detail.Value ?? string.Empty;
                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                if (key.IndexOf("sha256", StringComparison.OrdinalIgnoreCase) >= 0 || key.Equals("hash", StringComparison.OrdinalIgnoreCase))
                {
                    AddArtifact(seen, "sha256", value);
                }
                else if (key.IndexOf("path", StringComparison.OrdinalIgnoreCase) >= 0 || key.IndexOf("file", StringComparison.OrdinalIgnoreCase) >= 0 || key.IndexOf("image", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    foreach (string token in SplitValues(value))
                    {
                        AddArtifact(seen, LooksLikePath(token) ? "file_path" : "file_name", token);
                    }
                }
                else if (key.IndexOf("signature_subject", StringComparison.OrdinalIgnoreCase) >= 0 || key.IndexOf("signer", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddArtifact(seen, "signer_subject", value);
                }
                else if (key.IndexOf("thumbprint", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddArtifact(seen, "certificate_thumbprint", value);
                }
                else if (key.IndexOf("object_name", StringComparison.OrdinalIgnoreCase) >= 0 || key.IndexOf("device", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddArtifact(seen, value.IndexOf("\\Device\\", StringComparison.OrdinalIgnoreCase) >= 0 ? "device_name" : "object_name", value);
                }
                else if (key.IndexOf("section", StringComparison.OrdinalIgnoreCase) >= 0 || key.IndexOf("shared_memory", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddArtifact(seen, "section_name", value);
                }
                else if (key.IndexOf("service", StringComparison.OrdinalIgnoreCase) >= 0 && key.IndexOf("path", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    AddArtifact(seen, "service_name", value);
                }
                else if (key.IndexOf("registry", StringComparison.OrdinalIgnoreCase) >= 0 || key.IndexOf("key", StringComparison.OrdinalIgnoreCase) >= 0 && value.IndexOf("\\", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddArtifact(seen, "registry_key", value);
                }
                else if (key.IndexOf("command", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddArtifact(seen, "command_pattern", value);
                }
                else if (key.IndexOf("fingerprint", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddArtifact(seen, "case_fingerprint", value);
                }
            }

            foreach (string item in seen)
            {
                int split = item.IndexOf('|');
                if (split <= 0)
                {
                    continue;
                }

                string type = item.Substring(0, split);
                string value = item.Substring(split + 1);
                yield return new ArtifactObservation
                {
                    Type = type,
                    Value = value,
                    NormalizedValue = ReputationStore.NormalizeArtifactValue(type, value)
                };
            }
        }

        private static void AddArtifact(ISet<string> seen, string type, string value)
        {
            if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            string normalizedType = ReputationStore.NormalizeArtifactType(type);
            foreach (string token in SplitValues(value))
            {
                string trimmed = token.Trim();
                if (trimmed.Length == 0 || trimmed.Length > 2048)
                {
                    continue;
                }

                seen.Add(normalizedType + "|" + trimmed);
            }
        }

        private static IEnumerable<string> SplitValues(string value)
        {
            return (value ?? string.Empty).Split(new[] { ';', '|', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(v => v.Trim().Trim('"', '\''))
                .Where(v => !string.IsNullOrWhiteSpace(v));
        }

        private static bool LooksLikePath(string value)
        {
            return !string.IsNullOrWhiteSpace(value) &&
                   (value.IndexOf(@":\", StringComparison.OrdinalIgnoreCase) > 0 ||
                    value.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase));
        }

        private static string ExtractCaseId(DetectionEvent detectionEvent)
        {
            string[] keys =
            {
                "case_id",
                "behavior_case_id",
                "session_id",
                "launch_case_id",
                "active_capture_case_id",
                "transient_driver_case_id"
            };

            foreach (string key in keys)
            {
                string value = Detail(detectionEvent, key);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return string.Empty;
        }

        private static string EventToJson(DetectionEvent detectionEvent)
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
            JsonUtilities.AppendStringProperty(builder, "process_name", detectionEvent.ProcessName, ref first);
            JsonUtilities.AppendNumberProperty(builder, "process_id", detectionEvent.ProcessId.HasValue ? detectionEvent.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : "0", ref first);
            builder.Append(",\"details\":{");
            bool firstDetail = true;
            foreach (KeyValuePair<string, string> pair in detectionEvent.Details)
            {
                JsonUtilities.AppendStringProperty(builder, pair.Key, pair.Value, ref firstDetail);
            }
            builder.Append("}}");
            return builder.ToString();
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

        private static IEnumerable<string> SplitTags(string tags)
        {
            return (tags ?? string.Empty).Split(new[] { ';', ',', '|', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(NormalizeTag)
                .Where(t => !string.IsNullOrWhiteSpace(t));
        }

        private static string NormalizeTag(string tag)
        {
            return (tag ?? string.Empty).Trim().ToLowerInvariant().Replace(' ', '_');
        }

        private static void AddParameter(SqliteCommand command, string name, object value)
        {
            SqliteParameter parameter = command.CreateParameter();
            parameter.ParameterName = name;
            parameter.Value = value ?? DBNull.Value;
            command.Parameters.Add(parameter);
        }

        private static void ExecuteNonQuery(SqliteConnection connection, string sql)
        {
            using (SqliteCommand command = connection.CreateCommand())
            {
                command.CommandText = sql;
                command.ExecuteNonQuery();
            }
        }

        private static void TryExecuteNonQuery(SqliteConnection connection, string sql)
        {
            try
            {
                ExecuteNonQuery(connection, sql);
            }
            catch
            {
            }
        }

        private static void ExecuteNonQuery(SqliteConnection connection, SqliteTransaction transaction, string sql, IDictionary<string, object> parameters)
        {
            using (SqliteCommand command = connection.CreateCommand())
            {
                command.Transaction = transaction;
                command.CommandText = sql;
                if (parameters != null)
                {
                    foreach (KeyValuePair<string, object> parameter in parameters)
                    {
                        AddParameter(command, parameter.Key, parameter.Value);
                    }
                }

                command.ExecuteNonQuery();
            }
        }

        private static void UpsertMetadata(SqliteConnection connection, string key, string value)
        {
            using (SqliteCommand command = connection.CreateCommand())
            {
                command.CommandText = "INSERT INTO metadata(key, value) VALUES($key, $value) ON CONFLICT(key) DO UPDATE SET value=$value;";
                AddParameter(command, "$key", key);
                AddParameter(command, "$value", value);
                command.ExecuteNonQuery();
            }
        }

        private static string SchemaSql()
        {
            return @"
CREATE TABLE IF NOT EXISTS metadata(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events(
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp_utc TEXT NOT NULL,
  category TEXT NOT NULL,
  action TEXT NOT NULL,
  severity TEXT NOT NULL,
  severity_rank INTEGER NOT NULL,
  description TEXT,
  path TEXT,
  process_id INTEGER,
  process_name TEXT,
  case_id TEXT,
  json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_details(
  event_id INTEGER NOT NULL,
  detail_key TEXT NOT NULL,
  detail_value TEXT,
  FOREIGN KEY(event_id) REFERENCES events(event_id)
);

CREATE TABLE IF NOT EXISTS cases(
  case_id TEXT PRIMARY KEY,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  severity TEXT,
  severity_rank INTEGER NOT NULL DEFAULT 0,
  confidence REAL NOT NULL DEFAULT 0,
  summary TEXT,
  source TEXT,
  path TEXT,
  evidence_folder TEXT,
  profile TEXT,
  tags TEXT
);

CREATE TABLE IF NOT EXISTS case_events(
  case_id TEXT NOT NULL,
  event_id INTEGER NOT NULL,
  relation TEXT,
  PRIMARY KEY(case_id, event_id, relation)
);

CREATE TABLE IF NOT EXISTS case_notes(
  note_id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL,
  timestamp_utc TEXT NOT NULL,
  analyst TEXT,
  note TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_tags(
  case_id TEXT NOT NULL,
  tag TEXT NOT NULL,
  first_seen_utc TEXT NOT NULL,
  PRIMARY KEY(case_id, tag)
);

CREATE TABLE IF NOT EXISTS artifacts(
  artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_type TEXT NOT NULL,
  value TEXT NOT NULL,
  normalized_value TEXT NOT NULL,
  first_seen_utc TEXT NOT NULL,
  last_seen_utc TEXT NOT NULL,
  seen_count INTEGER NOT NULL DEFAULT 1,
  last_event_id INTEGER,
  UNIQUE(artifact_type, normalized_value)
);

CREATE TABLE IF NOT EXISTS artifact_events(
  artifact_id INTEGER NOT NULL,
  event_id INTEGER NOT NULL,
  case_id TEXT,
  PRIMARY KEY(artifact_id, event_id)
);

CREATE TABLE IF NOT EXISTS case_links(
  case_id TEXT NOT NULL,
  related_case_id TEXT NOT NULL,
  reason TEXT,
  first_seen_utc TEXT NOT NULL,
  PRIMARY KEY(case_id, related_case_id, reason)
);

CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
CREATE INDEX IF NOT EXISTS idx_events_category_action ON events(category, action);
CREATE INDEX IF NOT EXISTS idx_events_process ON events(process_id, process_name);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity_rank);
CREATE INDEX IF NOT EXISTS idx_event_details_key_value ON event_details(detail_key, detail_value);
CREATE INDEX IF NOT EXISTS idx_cases_last_seen ON cases(last_seen_utc);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_artifacts_type_value ON artifacts(artifact_type, normalized_value);
";
        }

        private sealed class ArtifactObservation
        {
            public string Type;
            public string Value;
            public string NormalizedValue;
        }
    }
}
