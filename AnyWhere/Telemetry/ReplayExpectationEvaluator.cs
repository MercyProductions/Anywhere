using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal static class ReplayExpectationEvaluator
    {
        public static ReplayExpectationEvaluation Evaluate(
            string expectationPath,
            DetectionReplayResult replayResult,
            IEnumerable<DetectionEvent> events,
            string outputDirectory)
        {
            ReplayExpectationEvaluation evaluation = new ReplayExpectationEvaluation
            {
                ExpectationPath = expectationPath,
                ReportPath = string.IsNullOrWhiteSpace(outputDirectory)
                    ? null
                    : Path.Combine(outputDirectory, "replay-expectations.txt")
            };

            ReplayExpectationFile expectationFile = LoadExpectationFile(expectationPath, evaluation);
            if (expectationFile == null)
            {
                evaluation.Passed = false;
                WriteReport(evaluation);
                return evaluation;
            }

            List<DetectionEvent> eventList = (events ?? Enumerable.Empty<DetectionEvent>()).Where(e => e != null).ToList();
            CheckCounter(evaluation, "files_read", replayResult.FilesRead, expectationFile.MinFilesRead, null);
            CheckCounter(evaluation, "lines_read", replayResult.LinesRead, expectationFile.MinLinesRead, null);
            CheckCounter(evaluation, "parsed_events", replayResult.ParsedEvents, expectationFile.MinParsedEvents, null);
            CheckCounter(evaluation, "replayed_events", replayResult.ReplayedEvents, expectationFile.MinReplayedEvents, null);
            CheckCounter(evaluation, "skipped_derived_events", replayResult.SkippedDerivedEvents, null, expectationFile.MaxSkippedDerivedEvents);
            CheckCounter(evaluation, "parse_failures", replayResult.ParseFailures, null, expectationFile.MaxParseFailures);

            foreach (ReplayEventExpectation expectation in expectationFile.ExpectedEvents ?? new List<ReplayEventExpectation>())
            {
                long count = eventList.Count(e => EventMatches(e, expectation));
                CheckCountRange(evaluation, "event", expectation.Name, count, expectation.MinCountOrDefault(), expectation.MaxCount);
            }

            foreach (ReplayCaseExpectation expectation in expectationFile.ExpectedCases ?? new List<ReplayCaseExpectation>())
            {
                List<ReplayCaseObservation> matchingCases = BuildCases(eventList)
                    .Where(c => CaseMatches(c, expectation))
                    .ToList();

                CheckCountRange(evaluation, "case", expectation.Name, matchingCases.Count, expectation.MinCountOrDefault(), expectation.MaxCount);
                if (expectation.MinConfidence.HasValue && matchingCases.Count > 0)
                {
                    double maxConfidence = matchingCases.Max(c => c.MaxConfidence);
                    if (maxConfidence < expectation.MinConfidence.Value)
                    {
                        evaluation.Failures.Add(
                            Label("case", expectation.Name) +
                            " expected min_confidence >= " + expectation.MinConfidence.Value.ToString("0.00", CultureInfo.InvariantCulture) +
                            " but highest match was " + maxConfidence.ToString("0.00", CultureInfo.InvariantCulture) + ".");
                    }
                }
            }

            evaluation.Passed = evaluation.Failures.Count == 0;
            WriteReport(evaluation);
            return evaluation;
        }

        private static ReplayExpectationFile LoadExpectationFile(string expectationPath, ReplayExpectationEvaluation evaluation)
        {
            string expandedPath = Environment.ExpandEnvironmentVariables(expectationPath ?? string.Empty).Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(expandedPath))
            {
                evaluation.Failures.Add("Replay expectation path is empty.");
                return null;
            }

            if (!File.Exists(expandedPath))
            {
                evaluation.Failures.Add("Replay expectation file was not found: " + expandedPath);
                return null;
            }

            evaluation.ExpectationPath = Path.GetFullPath(expandedPath);

            try
            {
                string json = File.ReadAllText(expandedPath, Encoding.UTF8);
                if (!string.IsNullOrEmpty(json) && json[0] == '\uFEFF')
                {
                    json = json.Substring(1);
                }

                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(ReplayExpectationFile));
                using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    return serializer.ReadObject(stream) as ReplayExpectationFile;
                }
            }
            catch (Exception ex)
            {
                evaluation.Failures.Add("Could not parse replay expectation file: " + ex.GetType().Name + ": " + ex.Message);
                return null;
            }
        }

        private static void CheckCounter(ReplayExpectationEvaluation evaluation, string name, long actual, long? min, long? max)
        {
            if (min.HasValue && actual < min.Value)
            {
                evaluation.Failures.Add(name + " expected >= " + min.Value.ToString(CultureInfo.InvariantCulture) +
                                        " but was " + actual.ToString(CultureInfo.InvariantCulture) + ".");
            }

            if (max.HasValue && actual > max.Value)
            {
                evaluation.Failures.Add(name + " expected <= " + max.Value.ToString(CultureInfo.InvariantCulture) +
                                        " but was " + actual.ToString(CultureInfo.InvariantCulture) + ".");
            }
        }

        private static void CheckCountRange(ReplayExpectationEvaluation evaluation, string kind, string name, long actual, long min, long? max)
        {
            bool passed = true;
            if (actual < min)
            {
                passed = false;
                evaluation.Failures.Add(Label(kind, name) + " expected count >= " +
                                        min.ToString(CultureInfo.InvariantCulture) + " but was " +
                                        actual.ToString(CultureInfo.InvariantCulture) + ".");
            }

            if (max.HasValue && actual > max.Value)
            {
                passed = false;
                evaluation.Failures.Add(Label(kind, name) + " expected count <= " +
                                        max.Value.ToString(CultureInfo.InvariantCulture) + " but was " +
                                        actual.ToString(CultureInfo.InvariantCulture) + ".");
            }

            if (passed)
            {
                evaluation.PassedChecks.Add(Label(kind, name) + " matched " + actual.ToString(CultureInfo.InvariantCulture) + ".");
            }
        }

        private static bool EventMatches(DetectionEvent detectionEvent, ReplayEventExpectation expectation)
        {
            if (!MatchesExact(detectionEvent.Category, expectation.Category) ||
                !MatchesExact(detectionEvent.Action, expectation.Action) ||
                !MatchesExact(detectionEvent.Path, expectation.Path) ||
                !MatchesContains(detectionEvent.Path, expectation.PathContains) ||
                !MatchesContains(detectionEvent.Description, expectation.DescriptionContains))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(expectation.Severity))
            {
                EventSeverity severity;
                if (!Enum.TryParse(expectation.Severity, true, out severity) || detectionEvent.Severity != severity)
                {
                    return false;
                }
            }

            if (!string.IsNullOrWhiteSpace(expectation.MinSeverity))
            {
                EventSeverity severity;
                if (!Enum.TryParse(expectation.MinSeverity, true, out severity) || detectionEvent.Severity < severity)
                {
                    return false;
                }
            }

            if (!string.IsNullOrWhiteSpace(expectation.DetailKey))
            {
                string detailValue;
                if (!detectionEvent.Details.TryGetValue(expectation.DetailKey, out detailValue))
                {
                    return false;
                }

                if (!MatchesExact(detailValue, expectation.DetailValue) ||
                    !MatchesContains(detailValue, expectation.DetailContains))
                {
                    return false;
                }
            }

            return true;
        }

        private static IEnumerable<ReplayCaseObservation> BuildCases(IEnumerable<DetectionEvent> events)
        {
            Dictionary<string, ReplayCaseObservation> cases = new Dictionary<string, ReplayCaseObservation>(StringComparer.OrdinalIgnoreCase);
            foreach (DetectionEvent detectionEvent in events)
            {
                string caseId = Detail(detectionEvent, "case_id");
                if (string.IsNullOrWhiteSpace(caseId))
                {
                    continue;
                }

                ReplayCaseObservation observation;
                if (!cases.TryGetValue(caseId, out observation))
                {
                    observation = new ReplayCaseObservation { CaseId = caseId };
                    cases[caseId] = observation;
                }

                observation.EventCount++;
                observation.Categories.Add(detectionEvent.Category ?? string.Empty);
                observation.Actions.Add(detectionEvent.Action ?? string.Empty);
                observation.Paths.Add(detectionEvent.Path ?? string.Empty);
                observation.Summaries.Add(FirstNonEmpty(Detail(detectionEvent, "case_summary"), detectionEvent.Description));
                observation.RuleIds.Add(Detail(detectionEvent, "rule_id"));
                observation.Profiles.Add(FirstNonEmpty(Detail(detectionEvent, "profile"), Detail(detectionEvent, "profile_name"), Detail(detectionEvent, "detection_profile")));
                observation.Tags.AddRange(SplitList(FirstNonEmpty(Detail(detectionEvent, "matched_tags"), Detail(detectionEvent, "behavior_tags"), Detail(detectionEvent, "case_tags"))));

                if (detectionEvent.Severity > observation.MaxSeverity)
                {
                    observation.MaxSeverity = detectionEvent.Severity;
                }

                double confidence;
                if (double.TryParse(
                        FirstNonEmpty(Detail(detectionEvent, "confidence_score"), Detail(detectionEvent, "score"), Detail(detectionEvent, "behavior_confidence")),
                        NumberStyles.Float,
                        CultureInfo.InvariantCulture,
                        out confidence) &&
                    confidence > observation.MaxConfidence)
                {
                    observation.MaxConfidence = confidence;
                }
            }

            return cases.Values;
        }

        private static bool CaseMatches(ReplayCaseObservation observation, ReplayCaseExpectation expectation)
        {
            if (!MatchesExact(observation.CaseId, expectation.CaseId) ||
                !MatchesPrefix(observation.CaseId, expectation.CaseIdPrefix) ||
                !ContainsAnyExact(observation.Categories, expectation.Category) ||
                !ContainsAnyExact(observation.Actions, expectation.Action) ||
                !ContainsAnyExact(observation.RuleIds, expectation.RuleId) ||
                !ContainsAnyExact(observation.Profiles, expectation.Profile) ||
                !ContainsAnyExact(observation.Tags, expectation.RequiredTag) ||
                !ContainsAnyContains(observation.Summaries, expectation.SummaryContains) ||
                !ContainsAnyContains(observation.Paths, expectation.PathContains))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(expectation.MinSeverity))
            {
                EventSeverity severity;
                if (!Enum.TryParse(expectation.MinSeverity, true, out severity) || observation.MaxSeverity < severity)
                {
                    return false;
                }
            }

            if (expectation.MinConfidence.HasValue && observation.MaxConfidence < expectation.MinConfidence.Value)
            {
                return false;
            }

            return true;
        }

        private static bool MatchesExact(string actual, string expected)
        {
            return string.IsNullOrWhiteSpace(expected) ||
                   string.Equals(actual ?? string.Empty, expected, StringComparison.OrdinalIgnoreCase);
        }

        private static bool MatchesPrefix(string actual, string expectedPrefix)
        {
            return string.IsNullOrWhiteSpace(expectedPrefix) ||
                   (actual ?? string.Empty).StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase);
        }

        private static bool MatchesContains(string actual, string expectedSubstring)
        {
            return string.IsNullOrWhiteSpace(expectedSubstring) ||
                   (actual ?? string.Empty).IndexOf(expectedSubstring, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool ContainsAnyExact(IEnumerable<string> values, string expected)
        {
            return string.IsNullOrWhiteSpace(expected) ||
                   values.Any(v => string.Equals(v ?? string.Empty, expected, StringComparison.OrdinalIgnoreCase));
        }

        private static bool ContainsAnyContains(IEnumerable<string> values, string expectedSubstring)
        {
            return string.IsNullOrWhiteSpace(expectedSubstring) ||
                   values.Any(v => (v ?? string.Empty).IndexOf(expectedSubstring, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static string Detail(DetectionEvent detectionEvent, string key)
        {
            string value;
            return detectionEvent != null && detectionEvent.Details.TryGetValue(key, out value) ? value : string.Empty;
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

        private static IEnumerable<string> SplitList(string value)
        {
            return (value ?? string.Empty)
                .Split(new[] { ';', ',', '|' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(v => v.Trim())
                .Where(v => v.Length > 0);
        }

        private static string Label(string kind, string name)
        {
            return kind + " expectation" + (string.IsNullOrWhiteSpace(name) ? string.Empty : " '" + name + "'");
        }

        private static void WriteReport(ReplayExpectationEvaluation evaluation)
        {
            if (string.IsNullOrWhiteSpace(evaluation.ReportPath))
            {
                return;
            }

            Directory.CreateDirectory(Path.GetDirectoryName(evaluation.ReportPath));
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("Aegis replay expectation report");
            builder.AppendLine("Generated UTC: " + DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture));
            builder.AppendLine("Expectation file: " + (evaluation.ExpectationPath ?? string.Empty));
            builder.AppendLine("Result: " + (evaluation.Passed ? "PASS" : "FAIL"));
            builder.AppendLine("Failures: " + evaluation.Failures.Count.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine();

            if (evaluation.Failures.Count > 0)
            {
                builder.AppendLine("Failed checks:");
                foreach (string failure in evaluation.Failures)
                {
                    builder.AppendLine("- " + failure);
                }

                builder.AppendLine();
            }

            if (evaluation.PassedChecks.Count > 0)
            {
                builder.AppendLine("Matched checks:");
                foreach (string passed in evaluation.PassedChecks)
                {
                    builder.AppendLine("- " + passed);
                }
            }

            File.WriteAllText(evaluation.ReportPath, builder.ToString(), Encoding.UTF8);
        }

        private sealed class ReplayCaseObservation
        {
            public ReplayCaseObservation()
            {
                Categories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Actions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                RuleIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Profiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                Tags = new List<string>();
                Summaries = new List<string>();
                Paths = new List<string>();
            }

            public string CaseId { get; set; }

            public long EventCount { get; set; }

            public EventSeverity MaxSeverity { get; set; }

            public double MaxConfidence { get; set; }

            public HashSet<string> Categories { get; private set; }

            public HashSet<string> Actions { get; private set; }

            public HashSet<string> RuleIds { get; private set; }

            public HashSet<string> Profiles { get; private set; }

            public List<string> Tags { get; private set; }

            public List<string> Summaries { get; private set; }

            public List<string> Paths { get; private set; }
        }
    }

    internal sealed class ReplayExpectationEvaluation
    {
        public ReplayExpectationEvaluation()
        {
            PassedChecks = new List<string>();
            Failures = new List<string>();
        }

        public string ExpectationPath { get; set; }

        public string ReportPath { get; set; }

        public bool Passed { get; set; }

        public List<string> PassedChecks { get; private set; }

        public List<string> Failures { get; private set; }
    }

    [DataContract]
    internal sealed class ReplayExpectationFile
    {
        [DataMember(Name = "description")]
        public string Description { get; set; }

        [DataMember(Name = "min_files_read")]
        public long? MinFilesRead { get; set; }

        [DataMember(Name = "min_lines_read")]
        public long? MinLinesRead { get; set; }

        [DataMember(Name = "min_parsed_events")]
        public long? MinParsedEvents { get; set; }

        [DataMember(Name = "min_replayed_events")]
        public long? MinReplayedEvents { get; set; }

        [DataMember(Name = "max_skipped_derived_events")]
        public long? MaxSkippedDerivedEvents { get; set; }

        [DataMember(Name = "max_parse_failures")]
        public long? MaxParseFailures { get; set; }

        [DataMember(Name = "expected_events")]
        public List<ReplayEventExpectation> ExpectedEvents { get; set; }

        [DataMember(Name = "expected_cases")]
        public List<ReplayCaseExpectation> ExpectedCases { get; set; }
    }

    [DataContract]
    internal sealed class ReplayEventExpectation
    {
        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "category")]
        public string Category { get; set; }

        [DataMember(Name = "action")]
        public string Action { get; set; }

        [DataMember(Name = "severity")]
        public string Severity { get; set; }

        [DataMember(Name = "min_severity")]
        public string MinSeverity { get; set; }

        [DataMember(Name = "path")]
        public string Path { get; set; }

        [DataMember(Name = "path_contains")]
        public string PathContains { get; set; }

        [DataMember(Name = "description_contains")]
        public string DescriptionContains { get; set; }

        [DataMember(Name = "detail_key")]
        public string DetailKey { get; set; }

        [DataMember(Name = "detail_value")]
        public string DetailValue { get; set; }

        [DataMember(Name = "detail_contains")]
        public string DetailContains { get; set; }

        [DataMember(Name = "min_count")]
        public long? MinCount { get; set; }

        [DataMember(Name = "max_count")]
        public long? MaxCount { get; set; }

        public long MinCountOrDefault()
        {
            return MinCount ?? 1;
        }
    }

    [DataContract]
    internal sealed class ReplayCaseExpectation
    {
        [DataMember(Name = "name")]
        public string Name { get; set; }

        [DataMember(Name = "case_id")]
        public string CaseId { get; set; }

        [DataMember(Name = "case_id_prefix")]
        public string CaseIdPrefix { get; set; }

        [DataMember(Name = "category")]
        public string Category { get; set; }

        [DataMember(Name = "action")]
        public string Action { get; set; }

        [DataMember(Name = "rule_id")]
        public string RuleId { get; set; }

        [DataMember(Name = "profile")]
        public string Profile { get; set; }

        [DataMember(Name = "required_tag")]
        public string RequiredTag { get; set; }

        [DataMember(Name = "summary_contains")]
        public string SummaryContains { get; set; }

        [DataMember(Name = "path_contains")]
        public string PathContains { get; set; }

        [DataMember(Name = "min_severity")]
        public string MinSeverity { get; set; }

        [DataMember(Name = "min_confidence")]
        public double? MinConfidence { get; set; }

        [DataMember(Name = "min_count")]
        public long? MinCount { get; set; }

        [DataMember(Name = "max_count")]
        public long? MaxCount { get; set; }

        public long MinCountOrDefault()
        {
            return MinCount ?? 1;
        }
    }
}
