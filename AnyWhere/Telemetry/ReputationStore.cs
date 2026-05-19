using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal enum ReputationCategory
    {
        Trusted,
        KnownGood,
        Unknown,
        Suspicious,
        ConfirmedCheatArtifact,
        ConfirmedMapper,
        ConfirmedLoader,
        ConfirmedHiddenDriverIndicator,
        FalsePositive
    }

    internal sealed class ReputationObservation
    {
        public string ArtifactType { get; set; }

        public string Value { get; set; }

        public string CaseId { get; set; }

        public string SourceCategory { get; set; }

        public string SourceAction { get; set; }

        public string SourceDescription { get; set; }

        public string SignatureStatus { get; set; }

        public EventSeverity Severity { get; set; }

        public bool Suspicious { get; set; }

        public DateTimeOffset TimestampUtc { get; set; }

        public HashSet<string> Tags { get; private set; }

        public ReputationObservation()
        {
            Tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    internal sealed class ReputationAssessment
    {
        public ReputationRecord Record { get; set; }

        public ReputationCategory CategoryBeforeUpdate { get; set; }

        public int PreviousSeenCount { get; set; }

        public int PreviousSuspiciousSeenCount { get; set; }

        public List<string> PreviousCaseIds { get; set; }

        public bool HasPreviousCase
        {
            get { return PreviousCaseIds != null && PreviousCaseIds.Count > 0; }
        }

        public bool IsConfirmedBad
        {
            get
            {
                return Record != null &&
                       (Record.Category == ReputationCategory.ConfirmedCheatArtifact ||
                        Record.Category == ReputationCategory.ConfirmedMapper ||
                        Record.Category == ReputationCategory.ConfirmedLoader ||
                        Record.Category == ReputationCategory.ConfirmedHiddenDriverIndicator);
            }
        }

        public bool IsKnownGood
        {
            get
            {
                return Record != null &&
                       (Record.Category == ReputationCategory.Trusted ||
                        Record.Category == ReputationCategory.KnownGood ||
                        Record.Category == ReputationCategory.FalsePositive);
            }
        }

        public bool IsRepeatedSuspicious
        {
            get
            {
                return Record != null &&
                       PreviousSeenCount > 0 &&
                       (Record.Category == ReputationCategory.Suspicious ||
                        PreviousSuspiciousSeenCount > 0 ||
                        HasPreviousCase);
            }
        }

        public string LinkText
        {
            get
            {
                if (Record == null || PreviousCaseIds == null || PreviousCaseIds.Count == 0)
                {
                    return string.Empty;
                }

                return "Seen before in Case " + PreviousCaseIds[0] + " as " + ReputationStore.FormatCategory(Record.Category) + ".";
            }
        }

        public string ConfidenceBoostReason
        {
            get
            {
                if (Record == null)
                {
                    return string.Empty;
                }

                if (IsConfirmedBad)
                {
                    return "artifact is locally confirmed as " + ReputationStore.FormatCategory(Record.Category);
                }

                if (Record.Category == ReputationCategory.Suspicious)
                {
                    return "artifact has a suspicious local reputation";
                }

                if (PreviousSuspiciousSeenCount > 0)
                {
                    return "artifact appeared in prior suspicious telemetry";
                }

                if (HasPreviousCase)
                {
                    return "artifact links to previous case evidence";
                }

                return string.Empty;
            }
        }
    }

    internal sealed class ReputationRecord
    {
        public string ArtifactType { get; set; }

        public string Value { get; set; }

        public string NormalizedValue { get; set; }

        public ReputationCategory Category { get; set; }

        public DateTimeOffset FirstSeenUtc { get; set; }

        public DateTimeOffset LastSeenUtc { get; set; }

        public int SeenCount { get; set; }

        public int SuspiciousSeenCount { get; set; }

        public int ConfirmedSeenCount { get; set; }

        public string LastCaseId { get; set; }

        public HashSet<string> CaseIds { get; private set; }

        public HashSet<string> Tags { get; private set; }

        public string Notes { get; set; }

        public string Source { get; set; }

        public ReputationRecord()
        {
            Category = ReputationCategory.Unknown;
            CaseIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            Tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        public string Key
        {
            get { return ReputationStore.BuildKey(ArtifactType, NormalizedValue); }
        }
    }

    internal sealed class ReputationImportResult
    {
        public int Imported { get; set; }

        public int Updated { get; set; }

        public int Skipped { get; set; }
    }

    internal sealed class ReputationStore
    {
        private const string Header = "# Aegis Reputation Store v1";
        private readonly object _syncRoot = new object();
        private readonly Dictionary<string, ReputationRecord> _records;
        private readonly string _storePath;
        private bool _dirty;

        private ReputationStore(string storePath)
        {
            _storePath = storePath;
            _records = new Dictionary<string, ReputationRecord>(StringComparer.OrdinalIgnoreCase);
        }

        public string StorePath
        {
            get { return _storePath; }
        }

        public int Count
        {
            get
            {
                lock (_syncRoot)
                {
                    return _records.Count;
                }
            }
        }

        public static ReputationStore Open(string reputationRoot)
        {
            Directory.CreateDirectory(reputationRoot);
            ReputationStore store = new ReputationStore(Path.Combine(reputationRoot, "reputation-store.tsv"));
            store.Load();
            return store;
        }

        public ReputationAssessment Observe(ReputationObservation observation)
        {
            if (observation == null ||
                string.IsNullOrWhiteSpace(observation.ArtifactType) ||
                string.IsNullOrWhiteSpace(observation.Value))
            {
                return null;
            }

            string artifactType = NormalizeArtifactType(observation.ArtifactType);
            string normalized = NormalizeArtifactValue(artifactType, observation.Value);
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return null;
            }

            string key = BuildKey(artifactType, normalized);
            lock (_syncRoot)
            {
                ReputationRecord record;
                if (!_records.TryGetValue(key, out record))
                {
                    record = new ReputationRecord
                    {
                        ArtifactType = artifactType,
                        Value = observation.Value.Trim(),
                        NormalizedValue = normalized,
                        Category = InitialCategoryFor(artifactType, observation),
                        FirstSeenUtc = observation.TimestampUtc == default(DateTimeOffset) ? DateTimeOffset.UtcNow : observation.TimestampUtc,
                        Source = "observed"
                    };
                    _records[key] = record;
                }

                List<string> previousCases = record.CaseIds
                    .Where(c => !string.Equals(c, observation.CaseId, StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(c => c)
                    .Take(8)
                    .ToList();

                ReputationAssessment assessment = new ReputationAssessment
                {
                    Record = record,
                    CategoryBeforeUpdate = record.Category,
                    PreviousSeenCount = record.SeenCount,
                    PreviousSuspiciousSeenCount = record.SuspiciousSeenCount,
                    PreviousCaseIds = previousCases
                };

                record.SeenCount++;
                record.LastSeenUtc = observation.TimestampUtc == default(DateTimeOffset) ? DateTimeOffset.UtcNow : observation.TimestampUtc;
                if (!string.IsNullOrWhiteSpace(observation.CaseId))
                {
                    record.CaseIds.Add(observation.CaseId.Trim());
                    record.LastCaseId = observation.CaseId.Trim();
                }

                if (observation.Suspicious)
                {
                    record.SuspiciousSeenCount++;
                }

                if (IsConfirmedCategory(record.Category))
                {
                    record.ConfirmedSeenCount++;
                }

                foreach (string tag in observation.Tags)
                {
                    if (!string.IsNullOrWhiteSpace(tag))
                    {
                        record.Tags.Add(tag.Trim());
                    }
                }

                if (ShouldAutoPromote(record, observation))
                {
                    record.Category = ReputationCategory.Suspicious;
                    record.Source = "local_repeat_observation";
                }

                TrimRecord(record);
                _dirty = true;
                return assessment;
            }
        }

        public ReputationRecord ApplyManualMark(string artifactType, string value, ReputationCategory category, string note, string caseId)
        {
            artifactType = NormalizeArtifactType(artifactType);
            string normalized = NormalizeArtifactValue(artifactType, value);
            if (string.IsNullOrWhiteSpace(artifactType) || string.IsNullOrWhiteSpace(normalized))
            {
                return null;
            }

            string key = BuildKey(artifactType, normalized);
            lock (_syncRoot)
            {
                ReputationRecord record;
                if (!_records.TryGetValue(key, out record))
                {
                    record = new ReputationRecord
                    {
                        ArtifactType = artifactType,
                        Value = value == null ? normalized : value.Trim(),
                        NormalizedValue = normalized,
                        FirstSeenUtc = DateTimeOffset.UtcNow
                    };
                    _records[key] = record;
                }

                record.Category = category;
                record.LastSeenUtc = DateTimeOffset.UtcNow;
                record.SeenCount = Math.Max(1, record.SeenCount);
                record.Source = "manual";
                if (!string.IsNullOrWhiteSpace(caseId))
                {
                    record.CaseIds.Add(caseId.Trim());
                    record.LastCaseId = caseId.Trim();
                }

                if (!string.IsNullOrWhiteSpace(note))
                {
                    if (string.IsNullOrWhiteSpace(record.Notes))
                    {
                        record.Notes = note.Trim();
                    }
                    else if (record.Notes.IndexOf(note, StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        record.Notes = record.Notes + " | " + note.Trim();
                    }
                }

                if (category == ReputationCategory.FalsePositive)
                {
                    record.Tags.Add("false_positive");
                }
                else if (category == ReputationCategory.Trusted || category == ReputationCategory.KnownGood)
                {
                    record.Tags.Add("noise_reduction");
                }
                else if (IsConfirmedCategory(category))
                {
                    record.Tags.Add("confirmed_bad");
                }

                TrimRecord(record);
                _dirty = true;
                return record;
            }
        }

        public ReputationImportResult Import(string importPath)
        {
            ReputationImportResult result = new ReputationImportResult();
            if (string.IsNullOrWhiteSpace(importPath) || !File.Exists(importPath))
            {
                result.Skipped++;
                return result;
            }

            foreach (string line in File.ReadLines(importPath))
            {
                ReputationRecord record = TryParsePersistedRecord(line);
                if (record == null)
                {
                    string type;
                    ReputationCategory category;
                    string value;
                    string notes;
                    if (!TryParseSimpleImportLine(line, out type, out category, out value, out notes))
                    {
                        result.Skipped++;
                        continue;
                    }

                    record = new ReputationRecord
                    {
                        ArtifactType = NormalizeArtifactType(type),
                        Value = value,
                        NormalizedValue = NormalizeArtifactValue(type, value),
                        Category = category,
                        FirstSeenUtc = DateTimeOffset.UtcNow,
                        LastSeenUtc = DateTimeOffset.UtcNow,
                        SeenCount = 1,
                        Notes = notes,
                        Source = "import"
                    };
                }

                if (string.IsNullOrWhiteSpace(record.ArtifactType) ||
                    string.IsNullOrWhiteSpace(record.NormalizedValue))
                {
                    result.Skipped++;
                    continue;
                }

                string key = BuildKey(record.ArtifactType, record.NormalizedValue);
                lock (_syncRoot)
                {
                    ReputationRecord existing;
                    if (_records.TryGetValue(key, out existing))
                    {
                        MergeRecord(existing, record);
                        result.Updated++;
                    }
                    else
                    {
                        _records[key] = record;
                        result.Imported++;
                    }

                    _dirty = true;
                }
            }

            return result;
        }

        public void Export(string exportPath)
        {
            if (string.IsNullOrWhiteSpace(exportPath))
            {
                return;
            }

            string finalPath = exportPath;
            if (Directory.Exists(finalPath) || finalPath.EndsWith("\\", StringComparison.OrdinalIgnoreCase))
            {
                Directory.CreateDirectory(finalPath);
                finalPath = Path.Combine(finalPath, "aegis-reputation-export-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + ".tsv");
            }
            else
            {
                string directory = Path.GetDirectoryName(finalPath);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    Directory.CreateDirectory(directory);
                }
            }

            List<ReputationRecord> snapshot;
            lock (_syncRoot)
            {
                snapshot = _records.Values
                    .OrderBy(r => r.ArtifactType, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(r => r.NormalizedValue, StringComparer.OrdinalIgnoreCase)
                    .Select(CloneRecord)
                    .ToList();
            }

            WriteRecords(finalPath, snapshot);
        }

        public void Flush()
        {
            List<ReputationRecord> snapshot;
            lock (_syncRoot)
            {
                if (!_dirty)
                {
                    return;
                }

                snapshot = _records.Values
                    .OrderBy(r => r.ArtifactType, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(r => r.NormalizedValue, StringComparer.OrdinalIgnoreCase)
                    .Select(CloneRecord)
                    .ToList();
                _dirty = false;
            }

            WriteRecords(_storePath, snapshot);
        }

        public static bool TryParseCategory(string value, out ReputationCategory category)
        {
            category = ReputationCategory.Unknown;
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            string normalized = value.Trim()
                .Replace("-", "_")
                .Replace(" ", "_")
                .ToLowerInvariant();

            switch (normalized)
            {
                case "trusted":
                    category = ReputationCategory.Trusted;
                    return true;
                case "known_good":
                case "good":
                case "allow":
                case "allowed":
                    category = ReputationCategory.KnownGood;
                    return true;
                case "unknown":
                    category = ReputationCategory.Unknown;
                    return true;
                case "suspicious":
                    category = ReputationCategory.Suspicious;
                    return true;
                case "confirmed_bad":
                case "confirmed_cheat":
                case "confirmed_cheat_artifact":
                case "known_bad":
                case "bad":
                    category = ReputationCategory.ConfirmedCheatArtifact;
                    return true;
                case "confirmed_mapper":
                case "mapper":
                    category = ReputationCategory.ConfirmedMapper;
                    return true;
                case "confirmed_loader":
                case "loader":
                    category = ReputationCategory.ConfirmedLoader;
                    return true;
                case "confirmed_hidden_driver_indicator":
                case "hidden_driver_indicator":
                case "hidden_driver":
                    category = ReputationCategory.ConfirmedHiddenDriverIndicator;
                    return true;
                case "false_positive":
                case "falsepositive":
                case "fp":
                    category = ReputationCategory.FalsePositive;
                    return true;
                default:
                    return false;
            }
        }

        public static string FormatCategory(ReputationCategory category)
        {
            switch (category)
            {
                case ReputationCategory.Trusted:
                    return "trusted";
                case ReputationCategory.KnownGood:
                    return "known_good";
                case ReputationCategory.Suspicious:
                    return "suspicious";
                case ReputationCategory.ConfirmedCheatArtifact:
                    return "confirmed_cheat_artifact";
                case ReputationCategory.ConfirmedMapper:
                    return "confirmed_mapper";
                case ReputationCategory.ConfirmedLoader:
                    return "confirmed_loader";
                case ReputationCategory.ConfirmedHiddenDriverIndicator:
                    return "confirmed_hidden_driver_indicator";
                case ReputationCategory.FalsePositive:
                    return "false_positive";
                default:
                    return "unknown";
            }
        }

        public static string BuildKey(string artifactType, string normalizedValue)
        {
            return NormalizeArtifactType(artifactType) + "\u001f" + (normalizedValue ?? string.Empty);
        }

        public static string NormalizeArtifactType(string artifactType)
        {
            if (string.IsNullOrWhiteSpace(artifactType))
            {
                return "unknown";
            }

            string normalized = artifactType.Trim()
                .Replace("-", "_")
                .Replace(" ", "_")
                .ToLowerInvariant();

            switch (normalized)
            {
                case "hash":
                case "sha":
                case "sha_256":
                    return "sha256";
                case "path":
                case "file":
                    return "file_path";
                case "filename":
                    return "file_name";
                case "signer":
                    return "signer_subject";
                case "cert_thumbprint":
                case "certificate":
                case "certificate_thumb":
                    return "certificate_thumbprint";
                case "device":
                case "object_device":
                    return "device_name";
                case "section":
                case "shared_memory":
                case "shared_memory_name":
                    return "section_name";
                case "service":
                    return "service_name";
                case "registry":
                case "regkey":
                    return "registry_key";
                case "command":
                case "command_line":
                case "cmdline":
                    return "command_pattern";
                case "profile":
                case "detection_profile":
                    return "detection_profile";
                case "fingerprint":
                    return "case_fingerprint";
                default:
                    return normalized;
            }
        }

        public static string NormalizeArtifactValue(string artifactType, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string type = NormalizeArtifactType(artifactType);
            string trimmed = value.Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(trimmed))
            {
                return string.Empty;
            }

            if (type == "sha256")
            {
                return NormalizeHash(trimmed);
            }

            if (type == "certificate_thumbprint")
            {
                return new string(trimmed.Where(IsHex).ToArray()).ToLowerInvariant();
            }

            if (type == "file_path")
            {
                return trimmed.Replace('/', '\\').ToLowerInvariant();
            }

            if (type == "file_name")
            {
                return Path.GetFileName(trimmed).ToLowerInvariant();
            }

            if (type == "signer_subject")
            {
                return CollapseWhitespace(trimmed).ToLowerInvariant();
            }

            if (type == "command_pattern")
            {
                return NormalizeCommandLine(trimmed);
            }

            if (type == "registry_key")
            {
                return trimmed.Replace('/', '\\').ToLowerInvariant();
            }

            return CollapseWhitespace(trimmed).ToLowerInvariant();
        }

        public static bool IsSha256(string value)
        {
            return !string.IsNullOrWhiteSpace(value) &&
                   value.Length == 64 &&
                   value.All(IsHex);
        }

        private void Load()
        {
            if (!File.Exists(_storePath))
            {
                return;
            }

            foreach (string line in File.ReadLines(_storePath))
            {
                ReputationRecord record = TryParsePersistedRecord(line);
                if (record == null)
                {
                    continue;
                }

                _records[BuildKey(record.ArtifactType, record.NormalizedValue)] = record;
            }
        }

        private static ReputationRecord TryParsePersistedRecord(string line)
        {
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            string[] fields = line.Split('\t');
            if (fields.Length < 14)
            {
                return null;
            }

            ReputationCategory category;
            if (!TryParseCategory(fields[3], out category))
            {
                category = ReputationCategory.Unknown;
            }

            ReputationRecord record = new ReputationRecord
            {
                ArtifactType = NormalizeArtifactType(fields[0]),
                Value = Decode(fields[1]),
                NormalizedValue = Decode(fields[2]),
                Category = category,
                FirstSeenUtc = ParseDate(fields[4]),
                LastSeenUtc = ParseDate(fields[5]),
                SeenCount = ParseInt(fields[6]),
                SuspiciousSeenCount = ParseInt(fields[7]),
                ConfirmedSeenCount = ParseInt(fields[8]),
                LastCaseId = Decode(fields[9]),
                Notes = Decode(fields[12]),
                Source = Decode(fields[13])
            };

            if (string.IsNullOrWhiteSpace(record.NormalizedValue))
            {
                record.NormalizedValue = NormalizeArtifactValue(record.ArtifactType, record.Value);
            }

            foreach (string caseId in SplitList(Decode(fields[10])))
            {
                record.CaseIds.Add(caseId);
            }

            foreach (string tag in SplitList(Decode(fields[11])))
            {
                record.Tags.Add(tag);
            }

            if (record.FirstSeenUtc == default(DateTimeOffset))
            {
                record.FirstSeenUtc = DateTimeOffset.UtcNow;
            }

            if (record.LastSeenUtc == default(DateTimeOffset))
            {
                record.LastSeenUtc = record.FirstSeenUtc;
            }

            return record;
        }

        private static bool TryParseSimpleImportLine(string line, out string artifactType, out ReputationCategory category, out string value, out string notes)
        {
            artifactType = null;
            category = ReputationCategory.Unknown;
            value = null;
            notes = null;

            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith("#", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            string trimmed = line.Trim();
            if (IsSha256(trimmed))
            {
                artifactType = "sha256";
                category = ReputationCategory.ConfirmedCheatArtifact;
                value = trimmed;
                notes = "imported hash list";
                return true;
            }

            char separator = trimmed.IndexOf('|') >= 0 ? '|' : ',';
            string[] parts = trimmed.Split(new[] { separator }, 4, StringSplitOptions.None)
                .Select(p => p.Trim())
                .Where(p => p.Length > 0)
                .ToArray();

            if (parts.Length < 3)
            {
                return false;
            }

            ReputationCategory parsedCategory;
            if (TryParseCategory(parts[1], out parsedCategory))
            {
                artifactType = parts[0];
                category = parsedCategory;
                value = parts[2];
                notes = parts.Length >= 4 ? parts[3] : "imported";
                return true;
            }

            if (TryParseCategory(parts[0], out parsedCategory))
            {
                category = parsedCategory;
                artifactType = parts[1];
                value = parts[2];
                notes = parts.Length >= 4 ? parts[3] : "imported";
                return true;
            }

            return false;
        }

        private static void MergeRecord(ReputationRecord existing, ReputationRecord incoming)
        {
            if (CategoryRank(incoming.Category) >= CategoryRank(existing.Category))
            {
                existing.Category = incoming.Category;
            }

            if (!string.IsNullOrWhiteSpace(incoming.Value))
            {
                existing.Value = incoming.Value;
            }

            existing.FirstSeenUtc = existing.FirstSeenUtc == default(DateTimeOffset)
                ? incoming.FirstSeenUtc
                : Min(existing.FirstSeenUtc, incoming.FirstSeenUtc);
            existing.LastSeenUtc = Max(existing.LastSeenUtc, incoming.LastSeenUtc);
            existing.SeenCount = Math.Max(existing.SeenCount, incoming.SeenCount);
            existing.SuspiciousSeenCount = Math.Max(existing.SuspiciousSeenCount, incoming.SuspiciousSeenCount);
            existing.ConfirmedSeenCount = Math.Max(existing.ConfirmedSeenCount, incoming.ConfirmedSeenCount);
            existing.LastCaseId = string.IsNullOrWhiteSpace(incoming.LastCaseId) ? existing.LastCaseId : incoming.LastCaseId;

            foreach (string caseId in incoming.CaseIds)
            {
                existing.CaseIds.Add(caseId);
            }

            foreach (string tag in incoming.Tags)
            {
                existing.Tags.Add(tag);
            }

            if (!string.IsNullOrWhiteSpace(incoming.Notes) && (existing.Notes ?? string.Empty).IndexOf(incoming.Notes, StringComparison.OrdinalIgnoreCase) < 0)
            {
                existing.Notes = string.IsNullOrWhiteSpace(existing.Notes) ? incoming.Notes : existing.Notes + " | " + incoming.Notes;
            }

            existing.Source = string.IsNullOrWhiteSpace(incoming.Source) ? existing.Source : incoming.Source;
            TrimRecord(existing);
        }

        private static void WriteRecords(string path, IEnumerable<ReputationRecord> records)
        {
            string tempPath = path + ".tmp";
            using (StreamWriter writer = new StreamWriter(new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.Read), Encoding.UTF8))
            {
                writer.WriteLine(Header);
                writer.WriteLine("# artifact_type\tvalue_b64\tnormalized_value_b64\tcategory\tfirst_seen_utc\tlast_seen_utc\tseen_count\tsuspicious_seen_count\tconfirmed_seen_count\tlast_case_id_b64\tcase_ids_b64\ttags_b64\tnotes_b64\tsource_b64");
                foreach (ReputationRecord record in records)
                {
                    writer.WriteLine(RecordToLine(record));
                }
            }

            if (File.Exists(path))
            {
                File.Delete(path);
            }

            File.Move(tempPath, path);
        }

        private static string RecordToLine(ReputationRecord record)
        {
            string[] fields =
            {
                NormalizeArtifactType(record.ArtifactType),
                Encode(record.Value),
                Encode(record.NormalizedValue),
                FormatCategory(record.Category),
                record.FirstSeenUtc.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture),
                record.LastSeenUtc.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture),
                record.SeenCount.ToString(CultureInfo.InvariantCulture),
                record.SuspiciousSeenCount.ToString(CultureInfo.InvariantCulture),
                record.ConfirmedSeenCount.ToString(CultureInfo.InvariantCulture),
                Encode(record.LastCaseId),
                Encode(string.Join(";", record.CaseIds.OrderBy(c => c, StringComparer.OrdinalIgnoreCase).ToArray())),
                Encode(string.Join(";", record.Tags.OrderBy(t => t, StringComparer.OrdinalIgnoreCase).ToArray())),
                Encode(record.Notes),
                Encode(record.Source)
            };

            return string.Join("\t", fields);
        }

        private static ReputationRecord CloneRecord(ReputationRecord source)
        {
            ReputationRecord clone = new ReputationRecord
            {
                ArtifactType = source.ArtifactType,
                Value = source.Value,
                NormalizedValue = source.NormalizedValue,
                Category = source.Category,
                FirstSeenUtc = source.FirstSeenUtc,
                LastSeenUtc = source.LastSeenUtc,
                SeenCount = source.SeenCount,
                SuspiciousSeenCount = source.SuspiciousSeenCount,
                ConfirmedSeenCount = source.ConfirmedSeenCount,
                LastCaseId = source.LastCaseId,
                Notes = source.Notes,
                Source = source.Source
            };

            foreach (string caseId in source.CaseIds)
            {
                clone.CaseIds.Add(caseId);
            }

            foreach (string tag in source.Tags)
            {
                clone.Tags.Add(tag);
            }

            return clone;
        }

        private static bool ShouldAutoPromote(ReputationRecord record, ReputationObservation observation)
        {
            if (record == null || observation == null || !observation.Suspicious)
            {
                return false;
            }

            if (record.Category != ReputationCategory.Unknown)
            {
                return false;
            }

            if (IsAutoSuspiciousArtifact(record.ArtifactType, record.NormalizedValue))
            {
                return true;
            }

            if (record.SuspiciousSeenCount >= 2 && record.CaseIds.Count >= 2)
            {
                return true;
            }

            if ((record.ArtifactType == "device_name" ||
                 record.ArtifactType == "section_name" ||
                 record.ArtifactType == "detection_profile" ||
                 record.ArtifactType == "case_fingerprint") &&
                record.SuspiciousSeenCount >= 2)
            {
                return true;
            }

            return false;
        }

        private static ReputationCategory InitialCategoryFor(string artifactType, ReputationObservation observation)
        {
            string value = NormalizeArtifactValue(artifactType, observation.Value);

            if (IsAutoSuspiciousArtifact(artifactType, value) && observation.Suspicious)
            {
                return ReputationCategory.Suspicious;
            }

            if (artifactType == "signer_subject")
            {
                if (IsTrustedMicrosoftSigner(value))
                {
                    return ReputationCategory.Trusted;
                }

                if (IsKnownGoodSigner(value))
                {
                    return ReputationCategory.KnownGood;
                }
            }

            if (artifactType == "file_path" && IsKnownGoodPath(value))
            {
                return ReputationCategory.KnownGood;
            }

            return ReputationCategory.Unknown;
        }

        private static bool IsAutoSuspiciousArtifact(string artifactType, string normalizedValue)
        {
            if (string.IsNullOrWhiteSpace(normalizedValue))
            {
                return false;
            }

            if (artifactType == "device_name" || artifactType == "service_name" || artifactType == "file_name")
            {
                return ContainsAny(normalizedValue, "iqvw", "gdrv", "capcom", "dbutil", "rtcore", "winio", "mhyprot", "asrdrv", "inpout", "kdu");
            }

            if (artifactType == "command_pattern")
            {
                return ContainsAny(normalizedValue, "kdmapper", "drvmap", "dsefix", "kdu", "modmap", "manualmap");
            }

            if (artifactType == "detection_profile")
            {
                return ContainsAny(normalizedValue, "suspicious_kernel_mapper", "hidden_driver_controller", "manual_map_injector", "unsigned_target_manipulator");
            }

            return false;
        }

        private static bool IsTrustedMicrosoftSigner(string normalizedSigner)
        {
            return ContainsAny(normalizedSigner, "cn=microsoft windows", "cn=microsoft corporation", "o=microsoft corporation");
        }

        private static bool IsKnownGoodSigner(string normalizedSigner)
        {
            return ContainsAny(
                normalizedSigner,
                "easyanticheat",
                "easy anti-cheat",
                "battleye",
                "riot games",
                "valve",
                "epic games",
                "nvidia corporation",
                "advanced micro devices",
                "intel corporation",
                "github, inc.",
                "jetbrains",
                "discord inc.",
                "steam");
        }

        private static bool IsKnownGoodPath(string normalizedPath)
        {
            return ContainsAny(
                normalizedPath,
                "\\windows\\system32\\",
                "\\windows\\syswow64\\",
                "\\program files\\microsoft\\",
                "\\program files (x86)\\microsoft\\",
                "\\program files\\windows defender\\",
                "\\programdata\\microsoft\\windows defender\\",
                "\\steamapps\\common\\",
                "\\epic games\\",
                "\\easyanticheat\\",
                "\\battleye\\");
        }

        private static int CategoryRank(ReputationCategory category)
        {
            switch (category)
            {
                case ReputationCategory.FalsePositive:
                    return 80;
                case ReputationCategory.Trusted:
                    return 75;
                case ReputationCategory.KnownGood:
                    return 70;
                case ReputationCategory.ConfirmedHiddenDriverIndicator:
                case ReputationCategory.ConfirmedMapper:
                case ReputationCategory.ConfirmedLoader:
                case ReputationCategory.ConfirmedCheatArtifact:
                    return 60;
                case ReputationCategory.Suspicious:
                    return 40;
                default:
                    return 10;
            }
        }

        private static bool IsConfirmedCategory(ReputationCategory category)
        {
            return category == ReputationCategory.ConfirmedCheatArtifact ||
                   category == ReputationCategory.ConfirmedMapper ||
                   category == ReputationCategory.ConfirmedLoader ||
                   category == ReputationCategory.ConfirmedHiddenDriverIndicator;
        }

        private static void TrimRecord(ReputationRecord record)
        {
            TrimSet(record.CaseIds, 40);
            TrimSet(record.Tags, 60);
        }

        private static void TrimSet(HashSet<string> values, int limit)
        {
            if (values == null || values.Count <= limit)
            {
                return;
            }

            foreach (string value in values.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).Take(values.Count - limit).ToList())
            {
                values.Remove(value);
            }
        }

        private static IEnumerable<string> SplitList(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                yield break;
            }

            foreach (string part in value.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string trimmed = part.Trim();
                if (!string.IsNullOrWhiteSpace(trimmed))
                {
                    yield return trimmed;
                }
            }
        }

        private static string NormalizeHash(string value)
        {
            string hex = new string((value ?? string.Empty).Where(IsHex).ToArray()).ToLowerInvariant();
            return hex.Length == 64 ? hex : string.Empty;
        }

        private static string NormalizeCommandLine(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
            {
                return string.Empty;
            }

            StringBuilder builder = new StringBuilder(commandLine.Length);
            bool inPath = false;
            bool inWhitespace = false;
            foreach (char c in commandLine.Trim())
            {
                if (char.IsWhiteSpace(c))
                {
                    if (!inWhitespace)
                    {
                        builder.Append(' ');
                    }

                    inWhitespace = true;
                    inPath = false;
                    continue;
                }

                inWhitespace = false;
                if (c == ':' || c == '\\' || c == '/')
                {
                    if (!inPath)
                    {
                        builder.Append("%path%");
                        inPath = true;
                    }

                    continue;
                }

                if (inPath)
                {
                    continue;
                }

                if (char.IsDigit(c))
                {
                    builder.Append('0');
                }
                else if (IsHex(c))
                {
                    builder.Append(char.ToLowerInvariant(c));
                }
                else
                {
                    builder.Append(char.ToLowerInvariant(c));
                }
            }

            return CollapseWhitespace(builder.ToString());
        }

        private static string CollapseWhitespace(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            StringBuilder builder = new StringBuilder(value.Length);
            bool previousWhitespace = false;
            foreach (char c in value)
            {
                if (char.IsWhiteSpace(c))
                {
                    if (!previousWhitespace)
                    {
                        builder.Append(' ');
                    }

                    previousWhitespace = true;
                }
                else
                {
                    builder.Append(c);
                    previousWhitespace = false;
                }
            }

            return builder.ToString().Trim();
        }

        private static bool ContainsAny(string value, params string[] terms)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            foreach (string term in terms)
            {
                if (value.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool IsHex(char c)
        {
            return (c >= '0' && c <= '9') ||
                   (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F');
        }

        private static DateTimeOffset ParseDate(string value)
        {
            DateTimeOffset parsed;
            if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out parsed))
            {
                return parsed.ToUniversalTime();
            }

            return default(DateTimeOffset);
        }

        private static int ParseInt(string value)
        {
            int parsed;
            return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed) ? parsed : 0;
        }

        private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b)
        {
            if (a == default(DateTimeOffset)) return b;
            if (b == default(DateTimeOffset)) return a;
            return a <= b ? a : b;
        }

        private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b)
        {
            if (a == default(DateTimeOffset)) return b;
            if (b == default(DateTimeOffset)) return a;
            return a >= b ? a : b;
        }

        private static string Encode(string value)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(value ?? string.Empty));
        }

        private static string Decode(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(value));
            }
            catch
            {
                return string.Empty;
            }
        }

        public static string HashText(string value)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(value ?? string.Empty));
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                }

                return builder.ToString();
            }
        }
    }
}
