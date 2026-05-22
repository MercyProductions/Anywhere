using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal static class CaseExportBundleWriter
    {
        public static CaseExportResult Export(EvidenceDatabase database, string caseId, string outputPath)
        {
            if (database == null)
            {
                throw new ArgumentNullException("database");
            }

            if (string.IsNullOrWhiteSpace(caseId))
            {
                throw new ArgumentException("A case id is required.", "caseId");
            }

            string normalizedCaseId = caseId.Trim();
            Dictionary<string, object> parameters = new Dictionary<string, object>
            {
                { "$caseId", normalizedCaseId }
            };

            DataTable caseTable = database.QueryTable(
                "SELECT case_id, first_seen_utc, last_seen_utc, status, severity, severity_rank, printf('%.2f', confidence) AS confidence, " +
                "summary, source, path, evidence_folder, profile, tags FROM cases WHERE case_id=$caseId;",
                parameters);
            if (caseTable.Rows.Count == 0)
            {
                throw new InvalidOperationException("Case not found: " + normalizedCaseId);
            }

            DataRow caseRow = caseTable.Rows[0];
            DataTable events = database.QueryTable(
                "SELECT e.event_id, e.timestamp_utc, e.category, e.action, e.severity, e.severity_rank, e.description, e.path, " +
                "e.process_id, e.process_name, e.case_id, GROUP_CONCAT(DISTINCT COALESCE(ce.relation, '')) AS relations, e.json " +
                "FROM events e LEFT JOIN case_events ce ON ce.event_id=e.event_id AND ce.case_id=$caseId " +
                "WHERE e.case_id=$caseId OR ce.case_id=$caseId " +
                "GROUP BY e.event_id ORDER BY e.timestamp_utc ASC, e.event_id ASC;",
                parameters);
            DataTable eventDetails = database.QueryTable(
                "SELECT d.event_id, d.detail_key, d.detail_value FROM event_details d " +
                "WHERE d.event_id IN (SELECT event_id FROM events WHERE case_id=$caseId UNION SELECT event_id FROM case_events WHERE case_id=$caseId) " +
                "ORDER BY d.event_id ASC, d.detail_key ASC;",
                parameters);
            DataTable artifacts = database.QueryTable(
                "SELECT a.artifact_id, a.artifact_type, a.value, a.normalized_value, a.first_seen_utc, a.last_seen_utc, a.seen_count, " +
                "a.last_event_id, GROUP_CONCAT(DISTINCT ae.event_id) AS event_ids, GROUP_CONCAT(DISTINCT ae.case_id) AS case_ids " +
                "FROM artifacts a JOIN artifact_events ae ON ae.artifact_id=a.artifact_id " +
                "WHERE ae.case_id=$caseId OR ae.event_id IN (SELECT event_id FROM events WHERE case_id=$caseId UNION SELECT event_id FROM case_events WHERE case_id=$caseId) " +
                "GROUP BY a.artifact_id ORDER BY a.artifact_type ASC, a.value ASC;",
                parameters);
            DataTable notes = database.QueryTable(
                "SELECT note_id, timestamp_utc, analyst, note FROM case_notes WHERE case_id=$caseId ORDER BY timestamp_utc ASC, note_id ASC;",
                parameters);
            DataTable tags = database.QueryTable(
                "SELECT tag, first_seen_utc FROM case_tags WHERE case_id=$caseId ORDER BY tag ASC;",
                parameters);
            DataTable relatedCases = database.QueryTable(
                "SELECT related_case_id AS case_id, reason, first_seen_utc, 'outbound' AS direction FROM case_links WHERE case_id=$caseId " +
                "UNION SELECT case_id AS case_id, reason, first_seen_utc, 'inbound' AS direction FROM case_links WHERE related_case_id=$caseId " +
                "ORDER BY first_seen_utc ASC;",
                parameters);

            string folder = ResolveExportFolder(normalizedCaseId, outputPath);
            Directory.CreateDirectory(folder);

            string mirroredEvidenceFolder = MirrorEvidenceFolder(caseRow, folder);
            WriteCaseJson(Path.Combine(folder, "case.json"), database.DatabasePath, caseRow, events, eventDetails, artifacts, notes, tags, relatedCases, mirroredEvidenceFolder);
            WriteCsv(Path.Combine(folder, "timeline.csv"), events, new[] { "event_id", "timestamp_utc", "relations", "severity", "category", "action", "process_name", "process_id", "path", "description" });
            WriteCsv(Path.Combine(folder, "event-details.csv"), eventDetails, null);
            WriteCsv(Path.Combine(folder, "artifacts.csv"), artifacts, null);
            WriteCsv(Path.Combine(folder, "notes.csv"), notes, null);
            WriteCsv(Path.Combine(folder, "tags.csv"), tags, null);
            WriteCsv(Path.Combine(folder, "related-cases.csv"), relatedCases, null);
            WriteJsonLines(Path.Combine(folder, "case-events.jsonl"), events);
            WriteTextSummary(Path.Combine(folder, "export-summary.txt"), database.DatabasePath, caseRow, events, artifacts, notes, tags, relatedCases, mirroredEvidenceFolder);
            WriteHtmlSummary(Path.Combine(folder, "summary.html"), database.DatabasePath, caseRow, events, artifacts, notes, tags, relatedCases, mirroredEvidenceFolder);
            WriteEvidenceSources(Path.Combine(folder, "evidence-sources.txt"), database.DatabasePath, caseRow, mirroredEvidenceFolder);

            string manifestPath = CaseIntegrityManifestWriter.WriteManifest(folder);
            string archivePath = CreateArchive(folder, outputPath);

            return new CaseExportResult
            {
                CaseId = normalizedCaseId,
                FolderPath = folder,
                ArchivePath = archivePath,
                ManifestPath = manifestPath,
                EventCount = events.Rows.Count,
                ArtifactCount = artifacts.Rows.Count,
                NoteCount = notes.Rows.Count,
                TagCount = tags.Rows.Count,
                RelatedCaseCount = relatedCases.Rows.Count,
                MirroredEvidenceFolder = mirroredEvidenceFolder
            };
        }

        private static string ResolveExportFolder(string caseId, string outputPath)
        {
            string safeCaseId = SanitizeFileName(caseId);
            string stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            if (string.IsNullOrWhiteSpace(outputPath))
            {
                string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Aegis Logs", "Case Exports");
                return UniqueDirectory(Path.Combine(root, safeCaseId + "-" + stamp));
            }

            string fullOutput = Path.GetFullPath(outputPath.Trim().Trim('"'));
            if (EndsWithZipExtension(fullOutput))
            {
                string parent = Path.GetDirectoryName(fullOutput);
                if (string.IsNullOrWhiteSpace(parent))
                {
                    parent = AppDomain.CurrentDomain.BaseDirectory;
                }

                string name = Path.GetFileNameWithoutExtension(fullOutput);
                return UniqueDirectory(Path.Combine(parent, SanitizeFileName(name)));
            }

            return UniqueDirectory(Path.Combine(fullOutput, safeCaseId + "-" + stamp));
        }

        private static string MirrorEvidenceFolder(DataRow caseRow, string exportFolder)
        {
            string evidenceFolder = GetString(caseRow, "evidence_folder");
            if (string.IsNullOrWhiteSpace(evidenceFolder) || !Directory.Exists(evidenceFolder))
            {
                return string.Empty;
            }

            string fullSource = Path.GetFullPath(evidenceFolder);
            string fullExport = Path.GetFullPath(exportFolder);
            if (IsSameOrChild(fullSource, fullExport))
            {
                return string.Empty;
            }

            return CaseIntegrityManifestWriter.TryMirrorFolder(fullSource, Path.Combine(exportFolder, "source-evidence")) ?? string.Empty;
        }

        private static bool IsSameOrChild(string candidate, string parent)
        {
            string normalizedCandidate = AppendDirectorySeparator(candidate);
            string normalizedParent = AppendDirectorySeparator(parent);
            return normalizedCandidate.StartsWith(normalizedParent, StringComparison.OrdinalIgnoreCase);
        }

        private static void WriteCaseJson(
            string path,
            string databasePath,
            DataRow caseRow,
            DataTable events,
            DataTable eventDetails,
            DataTable artifacts,
            DataTable notes,
            DataTable tags,
            DataTable relatedCases,
            string mirroredEvidenceFolder)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("{");
            bool first = true;
            JsonUtilities.AppendStringProperty(builder, "exported_utc", DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "source_database", databasePath, ref first);
            JsonUtilities.AppendStringProperty(builder, "case_id", GetString(caseRow, "case_id"), ref first);
            JsonUtilities.AppendStringProperty(builder, "mirrored_evidence_folder", mirroredEvidenceFolder, ref first);
            AppendCounts(builder, events, artifacts, notes, tags, relatedCases, ref first);
            AppendRowProperty(builder, "case", caseRow, ref first);
            AppendTableProperty(builder, "timeline", events, ref first);
            AppendTableProperty(builder, "event_details", eventDetails, ref first);
            AppendTableProperty(builder, "artifacts", artifacts, ref first);
            AppendTableProperty(builder, "notes", notes, ref first);
            AppendTableProperty(builder, "tags", tags, ref first);
            AppendTableProperty(builder, "related_cases", relatedCases, ref first);
            builder.Append("}");
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
        }

        private static void AppendCounts(
            StringBuilder builder,
            DataTable events,
            DataTable artifacts,
            DataTable notes,
            DataTable tags,
            DataTable relatedCases,
            ref bool first)
        {
            if (!first)
            {
                builder.Append(",");
            }

            builder.Append("\"counts\":{");
            bool firstCount = true;
            JsonUtilities.AppendNumberProperty(builder, "events", events.Rows.Count.ToString(CultureInfo.InvariantCulture), ref firstCount);
            JsonUtilities.AppendNumberProperty(builder, "artifacts", artifacts.Rows.Count.ToString(CultureInfo.InvariantCulture), ref firstCount);
            JsonUtilities.AppendNumberProperty(builder, "notes", notes.Rows.Count.ToString(CultureInfo.InvariantCulture), ref firstCount);
            JsonUtilities.AppendNumberProperty(builder, "tags", tags.Rows.Count.ToString(CultureInfo.InvariantCulture), ref firstCount);
            JsonUtilities.AppendNumberProperty(builder, "related_cases", relatedCases.Rows.Count.ToString(CultureInfo.InvariantCulture), ref firstCount);
            builder.Append("}");
            first = false;
        }

        private static void AppendRowProperty(StringBuilder builder, string name, DataRow row, ref bool first)
        {
            if (!first)
            {
                builder.Append(",");
            }

            builder.Append("\"");
            builder.Append(JsonUtilities.Escape(name));
            builder.Append("\":");
            AppendRowObject(builder, row);
            first = false;
        }

        private static void AppendTableProperty(StringBuilder builder, string name, DataTable table, ref bool first)
        {
            if (!first)
            {
                builder.Append(",");
            }

            builder.Append("\"");
            builder.Append(JsonUtilities.Escape(name));
            builder.Append("\":[");
            for (int i = 0; i < table.Rows.Count; i++)
            {
                if (i > 0)
                {
                    builder.Append(",");
                }

                AppendRowObject(builder, table.Rows[i]);
            }

            builder.Append("]");
            first = false;
        }

        private static void AppendRowObject(StringBuilder builder, DataRow row)
        {
            builder.Append("{");
            bool first = true;
            foreach (DataColumn column in row.Table.Columns)
            {
                JsonUtilities.AppendStringProperty(builder, column.ColumnName, GetString(row, column.ColumnName), ref first);
            }

            builder.Append("}");
        }

        private static void WriteCsv(string path, DataTable table, string[] selectedColumns)
        {
            List<string> columns = BuildColumnList(table, selectedColumns);
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < columns.Count; i++)
            {
                if (i > 0)
                {
                    builder.Append(",");
                }

                builder.Append(CsvEscape(columns[i]));
            }

            builder.AppendLine();
            foreach (DataRow row in table.Rows)
            {
                for (int i = 0; i < columns.Count; i++)
                {
                    if (i > 0)
                    {
                        builder.Append(",");
                    }

                    builder.Append(CsvEscape(GetString(row, columns[i])));
                }

                builder.AppendLine();
            }

            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
        }

        private static List<string> BuildColumnList(DataTable table, string[] selectedColumns)
        {
            if (selectedColumns == null || selectedColumns.Length == 0)
            {
                return table.Columns.Cast<DataColumn>().Select(c => c.ColumnName).ToList();
            }

            List<string> columns = new List<string>();
            foreach (string column in selectedColumns)
            {
                if (table.Columns.Contains(column))
                {
                    columns.Add(column);
                }
            }

            return columns;
        }

        private static void WriteJsonLines(string path, DataTable events)
        {
            using (StreamWriter writer = new StreamWriter(path, false, Encoding.UTF8))
            {
                foreach (DataRow row in events.Rows)
                {
                    string json = GetString(row, "json");
                    if (!string.IsNullOrWhiteSpace(json))
                    {
                        writer.WriteLine(json);
                    }
                }
            }
        }

        private static void WriteTextSummary(
            string path,
            string databasePath,
            DataRow caseRow,
            DataTable events,
            DataTable artifacts,
            DataTable notes,
            DataTable tags,
            DataTable relatedCases,
            string mirroredEvidenceFolder)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("Aegis case export");
            builder.AppendLine("=================");
            builder.AppendLine("Case: " + GetString(caseRow, "case_id"));
            builder.AppendLine("Status: " + GetString(caseRow, "status"));
            builder.AppendLine("Severity: " + GetString(caseRow, "severity"));
            builder.AppendLine("Confidence: " + GetString(caseRow, "confidence"));
            builder.AppendLine("First seen UTC: " + GetString(caseRow, "first_seen_utc"));
            builder.AppendLine("Last seen UTC: " + GetString(caseRow, "last_seen_utc"));
            builder.AppendLine("Profile: " + GetString(caseRow, "profile"));
            builder.AppendLine("Tags: " + BuildTagSummary(caseRow, tags));
            builder.AppendLine("Source database: " + databasePath);
            builder.AppendLine("Source evidence folder: " + GetString(caseRow, "evidence_folder"));
            builder.AppendLine("Mirrored evidence folder: " + mirroredEvidenceFolder);
            builder.AppendLine();
            builder.AppendLine("Summary");
            builder.AppendLine("-------");
            builder.AppendLine(GetString(caseRow, "summary"));
            builder.AppendLine();
            builder.AppendLine("Counts");
            builder.AppendLine("------");
            builder.AppendLine("Events: " + events.Rows.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Artifacts: " + artifacts.Rows.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Notes: " + notes.Rows.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Tags: " + tags.Rows.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Related cases: " + relatedCases.Rows.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine();
            builder.AppendLine("Key files");
            builder.AppendLine("---------");
            builder.AppendLine("summary.html");
            builder.AppendLine("case.json");
            builder.AppendLine("timeline.csv");
            builder.AppendLine("case-events.jsonl");
            builder.AppendLine("artifacts.csv");
            builder.AppendLine("event-details.csv");
            builder.AppendLine("notes.csv");
            builder.AppendLine("tags.csv");
            builder.AppendLine("related-cases.csv");
            builder.AppendLine("evidence-sources.txt");
            builder.AppendLine("case-integrity-manifest.json");
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
        }

        private static void WriteEvidenceSources(string path, string databasePath, DataRow caseRow, string mirroredEvidenceFolder)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("Source database: " + databasePath);
            builder.AppendLine("Case id: " + GetString(caseRow, "case_id"));
            builder.AppendLine("Case path: " + GetString(caseRow, "path"));
            builder.AppendLine("Recorded evidence folder: " + GetString(caseRow, "evidence_folder"));
            builder.AppendLine("Mirrored evidence folder: " + mirroredEvidenceFolder);
            builder.AppendLine("Exported UTC: " + DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
        }

        private static void WriteHtmlSummary(
            string path,
            string databasePath,
            DataRow caseRow,
            DataTable events,
            DataTable artifacts,
            DataTable notes,
            DataTable tags,
            DataTable relatedCases,
            string mirroredEvidenceFolder)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("<!doctype html>");
            builder.AppendLine("<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Aegis Case Export</title>");
            builder.AppendLine("<style>");
            builder.AppendLine("body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#172033;background:#f7f9fc;line-height:1.45}");
            builder.AppendLine("h1,h2{margin:0 0 12px}h1{font-size:28px}h2{font-size:18px;margin-top:28px}");
            builder.AppendLine(".panel{background:#fff;border:1px solid #d8dee9;border-radius:8px;padding:18px;margin:0 0 18px}");
            builder.AppendLine(".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.metric{border:1px solid #e4e9f2;border-radius:6px;padding:10px;background:#fbfcff}");
            builder.AppendLine(".label{font-size:12px;text-transform:uppercase;color:#667085;letter-spacing:.04em}.value{font-size:15px;font-weight:600;word-break:break-word}");
            builder.AppendLine("table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d8dee9}th,td{border-bottom:1px solid #e4e9f2;padding:8px;text-align:left;vertical-align:top;font-size:13px}th{background:#eef3f8;color:#344054}td{word-break:break-word}");
            builder.AppendLine(".muted{color:#667085}.summary{white-space:pre-wrap}");
            builder.AppendLine("</style></head><body>");
            builder.AppendLine("<h1>Aegis Case Export</h1>");
            builder.AppendLine("<p class=\"muted\">" + HtmlEscape(GetString(caseRow, "case_id")) + " exported " + HtmlEscape(DateTime.UtcNow.ToString("u", CultureInfo.InvariantCulture)) + "</p>");

            builder.AppendLine("<div class=\"panel\"><div class=\"grid\">");
            AppendMetric(builder, "Status", GetString(caseRow, "status"));
            AppendMetric(builder, "Severity", GetString(caseRow, "severity"));
            AppendMetric(builder, "Confidence", GetString(caseRow, "confidence"));
            AppendMetric(builder, "Events", events.Rows.Count.ToString(CultureInfo.InvariantCulture));
            AppendMetric(builder, "Artifacts", artifacts.Rows.Count.ToString(CultureInfo.InvariantCulture));
            AppendMetric(builder, "Notes", notes.Rows.Count.ToString(CultureInfo.InvariantCulture));
            AppendMetric(builder, "Tags", BuildTagSummary(caseRow, tags));
            AppendMetric(builder, "Profile", GetString(caseRow, "profile"));
            AppendMetric(builder, "First Seen UTC", GetString(caseRow, "first_seen_utc"));
            AppendMetric(builder, "Last Seen UTC", GetString(caseRow, "last_seen_utc"));
            builder.AppendLine("</div></div>");

            builder.AppendLine("<div class=\"panel\"><h2>Summary</h2><div class=\"summary\">" + HtmlEscape(GetString(caseRow, "summary")) + "</div></div>");
            builder.AppendLine("<div class=\"panel\"><h2>Sources</h2><p><strong>Database:</strong> " + HtmlEscape(databasePath) + "</p><p><strong>Evidence folder:</strong> " + HtmlEscape(GetString(caseRow, "evidence_folder")) + "</p><p><strong>Mirrored folder:</strong> " + HtmlEscape(mirroredEvidenceFolder) + "</p></div>");

            AppendTable(builder, "Timeline", events, new[] { "timestamp_utc", "severity", "category", "action", "process_name", "path", "description" }, 300);
            AppendTable(builder, "Artifacts", artifacts, new[] { "artifact_type", "value", "seen_count", "first_seen_utc", "last_seen_utc" }, 300);
            AppendTable(builder, "Notes", notes, new[] { "timestamp_utc", "analyst", "note" }, 100);
            AppendTable(builder, "Tags", tags, new[] { "tag", "first_seen_utc" }, 100);
            AppendTable(builder, "Related Cases", relatedCases, null, 100);

            builder.AppendLine("</body></html>");
            File.WriteAllText(path, builder.ToString(), Encoding.UTF8);
        }

        private static void AppendMetric(StringBuilder builder, string label, string value)
        {
            builder.Append("<div class=\"metric\"><div class=\"label\">");
            builder.Append(HtmlEscape(label));
            builder.Append("</div><div class=\"value\">");
            builder.Append(HtmlEscape(value));
            builder.AppendLine("</div></div>");
        }

        private static void AppendTable(StringBuilder builder, string title, DataTable table, string[] selectedColumns, int maxRows)
        {
            List<string> columns = BuildColumnList(table, selectedColumns);
            builder.AppendLine("<h2>" + HtmlEscape(title) + "</h2>");
            builder.AppendLine("<table><thead><tr>");
            foreach (string column in columns)
            {
                builder.Append("<th>");
                builder.Append(HtmlEscape(column));
                builder.AppendLine("</th>");
            }

            builder.AppendLine("</tr></thead><tbody>");
            int written = 0;
            foreach (DataRow row in table.Rows)
            {
                if (written >= maxRows)
                {
                    break;
                }

                builder.AppendLine("<tr>");
                foreach (string column in columns)
                {
                    builder.Append("<td>");
                    builder.Append(HtmlEscape(GetString(row, column)));
                    builder.AppendLine("</td>");
                }

                builder.AppendLine("</tr>");
                written++;
            }

            if (table.Rows.Count > maxRows)
            {
                builder.AppendLine("<tr><td colspan=\"" + columns.Count.ToString(CultureInfo.InvariantCulture) + "\" class=\"muted\">Showing " + maxRows.ToString(CultureInfo.InvariantCulture) + " of " + table.Rows.Count.ToString(CultureInfo.InvariantCulture) + " rows. Full data is in the CSV and JSON files.</td></tr>");
            }

            builder.AppendLine("</tbody></table>");
        }

        private static string CreateArchive(string folder, string outputPath)
        {
            if (string.IsNullOrWhiteSpace(outputPath) || !EndsWithZipExtension(outputPath))
            {
                return CaseIntegrityManifestWriter.TryCreateArchive(folder);
            }

            try
            {
                string archivePath = ResolveUniqueFilePath(Path.GetFullPath(outputPath.Trim().Trim('"')));
                string parent = Path.GetDirectoryName(archivePath);
                if (!string.IsNullOrWhiteSpace(parent))
                {
                    Directory.CreateDirectory(parent);
                }

                ZipFile.CreateFromDirectory(folder, archivePath, CompressionLevel.Optimal, false);
                return archivePath;
            }
            catch
            {
                return CaseIntegrityManifestWriter.TryCreateArchive(folder);
            }
        }

        private static string BuildTagSummary(DataRow caseRow, DataTable tags)
        {
            List<string> values = new List<string>();
            foreach (DataRow row in tags.Rows)
            {
                string tag = GetString(row, "tag");
                if (!string.IsNullOrWhiteSpace(tag))
                {
                    values.Add(tag);
                }
            }

            if (values.Count > 0)
            {
                return string.Join("; ", values.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(t => t).ToArray());
            }

            return GetString(caseRow, "tags");
        }

        private static string GetString(DataRow row, string columnName)
        {
            if (row == null || row.Table == null || !row.Table.Columns.Contains(columnName))
            {
                return string.Empty;
            }

            object value = row[columnName];
            return value == null || value == DBNull.Value ? string.Empty : Convert.ToString(value, CultureInfo.InvariantCulture);
        }

        private static string CsvEscape(string value)
        {
            string text = value ?? string.Empty;
            bool mustQuote = text.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0;
            if (!mustQuote)
            {
                return text;
            }

            return "\"" + text.Replace("\"", "\"\"") + "\"";
        }

        private static string HtmlEscape(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            return value.Replace("&", "&amp;")
                .Replace("<", "&lt;")
                .Replace(">", "&gt;")
                .Replace("\"", "&quot;")
                .Replace("'", "&#39;");
        }

        private static string ResolveUniqueFilePath(string path)
        {
            if (!File.Exists(path))
            {
                return path;
            }

            string parent = Path.GetDirectoryName(path);
            string name = Path.GetFileNameWithoutExtension(path);
            string extension = Path.GetExtension(path);
            string stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            string candidate = Path.Combine(parent ?? string.Empty, name + "-" + stamp + extension);
            int counter = 2;
            while (File.Exists(candidate))
            {
                candidate = Path.Combine(parent ?? string.Empty, name + "-" + stamp + "-" + counter.ToString(CultureInfo.InvariantCulture) + extension);
                counter++;
            }

            return candidate;
        }

        private static string UniqueDirectory(string path)
        {
            string candidate = path;
            int counter = 2;
            while (Directory.Exists(candidate))
            {
                candidate = path + "-" + counter.ToString(CultureInfo.InvariantCulture);
                counter++;
            }

            return candidate;
        }

        private static bool EndsWithZipExtension(string path)
        {
            return string.Equals(Path.GetExtension(path), ".zip", StringComparison.OrdinalIgnoreCase);
        }

        private static string SanitizeFileName(string value)
        {
            string text = string.IsNullOrWhiteSpace(value) ? "case-export" : value.Trim();
            foreach (char invalid in Path.GetInvalidFileNameChars())
            {
                text = text.Replace(invalid, '_');
            }

            return text.Length == 0 ? "case-export" : text;
        }

        private static string AppendDirectorySeparator(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            return path.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.OrdinalIgnoreCase)
                ? path
                : path + Path.DirectorySeparatorChar;
        }
    }

    internal sealed class CaseExportResult
    {
        public string CaseId { get; set; }

        public string FolderPath { get; set; }

        public string ArchivePath { get; set; }

        public string ManifestPath { get; set; }

        public int EventCount { get; set; }

        public int ArtifactCount { get; set; }

        public int NoteCount { get; set; }

        public int TagCount { get; set; }

        public int RelatedCaseCount { get; set; }

        public string MirroredEvidenceFolder { get; set; }
    }
}
