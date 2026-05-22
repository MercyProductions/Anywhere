using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal static class DetectionReplayRunner
    {
        private static readonly string[] DerivedCategoryPrefixes =
        {
            "Monitor",
            "EvidenceDatabase",
            "Replay",
            "DetectionEngine",
            "BehaviorProfile",
            "BehavioralProfile",
            "BaselineLearning",
            "Reputation",
            "SessionReplay",
            "ActiveCapture"
        };

        public static DetectionReplayResult Replay(MonitorOptions options, EventLogger logger)
        {
            DetectionReplayResult result = new DetectionReplayResult
            {
                OutputDirectory = Path.GetDirectoryName(logger.JsonLogPath)
            };

            object eventCaptureLock = new object();
            List<DetectionEvent> capturedEvents = new List<DetectionEvent>();
            Action<DetectionEvent> captureEvent = delegate(DetectionEvent detectionEvent)
            {
                if (detectionEvent == null)
                {
                    return;
                }

                lock (eventCaptureLock)
                {
                    capturedEvents.Add(detectionEvent);
                }
            };
            logger.EventLogged += captureEvent;

            List<string> inputFiles = ResolveInputFiles(options.ReplayInputPaths, result);
            result.InputFiles.AddRange(inputFiles);

            try
            {
                logger.Log(DetectionEvent.Create(
                    "Replay",
                    "Started",
                    EventSeverity.Low,
                    "Detection replay started.",
                    null,
                    null,
                    new Dictionary<string, string>
                    {
                        { "input_file_count", inputFiles.Count.ToString(CultureInfo.InvariantCulture) },
                        { "output_directory", result.OutputDirectory },
                        { "include_derived_events", options.ReplayIncludeDerivedEvents.ToString() },
                        { "rebase_timestamps", options.ReplayRebaseTimestamps.ToString() },
                        { "expectation_path", options.ReplayExpectationPath ?? string.Empty }
                    }));

                if (inputFiles.Count == 0)
                {
                    logger.Log(DetectionEvent.Create(
                        "Replay",
                        "NoInputFiles",
                        EventSeverity.Medium,
                        "No replay input JSONL files were found.",
                        null,
                        null,
                        new Dictionary<string, string>
                        {
                            { "requested_inputs", string.Join(";", options.ReplayInputPaths.ToArray()) },
                            { "missing_inputs", string.Join(";", result.MissingInputs.ToArray()) }
                        }));
                    EvaluateExpectations(options, logger, result, capturedEvents, eventCaptureLock);
                    WriteSummary(result);
                    return result;
                }

                DateTimeOffset? firstOriginalTimestamp = null;
                DateTimeOffset replayBaseTimestamp = DateTimeOffset.UtcNow;
                int parseFailureLogs = 0;

                foreach (string inputFile in inputFiles)
                {
                    result.FilesRead++;
                    long lineNumber = 0;

                    foreach (string line in File.ReadLines(inputFile))
                    {
                        lineNumber++;
                        result.LinesRead++;

                        if (string.IsNullOrWhiteSpace(line))
                        {
                            continue;
                        }

                        DetectionEvent detectionEvent;
                        string parseError;
                        if (!ReplayEventReader.TryParse(line, out detectionEvent, out parseError))
                        {
                            result.ParseFailures++;
                            if (parseFailureLogs < 25)
                            {
                                parseFailureLogs++;
                                logger.Log(DetectionEvent.Create(
                                    "Replay",
                                    "EventParseFailed",
                                    EventSeverity.Medium,
                                    "Replay input line could not be parsed.",
                                    inputFile,
                                    null,
                                    new Dictionary<string, string>
                                    {
                                        { "line_number", lineNumber.ToString(CultureInfo.InvariantCulture) },
                                        { "error", parseError ?? "unknown parse error" }
                                    }));
                            }

                            continue;
                        }

                        result.ParsedEvents++;
                        if (!options.ReplayIncludeDerivedEvents && IsDerivedEvent(detectionEvent))
                        {
                            result.SkippedDerivedEvents++;
                            continue;
                        }

                        DateTimeOffset originalTimestamp = detectionEvent.TimestampUtc;
                        if (options.ReplayRebaseTimestamps)
                        {
                            if (!firstOriginalTimestamp.HasValue)
                            {
                                firstOriginalTimestamp = originalTimestamp;
                                replayBaseTimestamp = DateTimeOffset.UtcNow;
                            }

                            TimeSpan delta = originalTimestamp.Subtract(firstOriginalTimestamp.Value);
                            detectionEvent = DetectionEvent.CreateReplayed(
                                replayBaseTimestamp.Add(delta),
                                detectionEvent.Category,
                                detectionEvent.Action,
                                detectionEvent.Severity,
                                detectionEvent.Description,
                                detectionEvent.Path,
                                detectionEvent.ProcessId,
                                detectionEvent.ProcessName,
                                detectionEvent.Details);
                        }

                        detectionEvent.Details["replay_source_file"] = inputFile;
                        detectionEvent.Details["replay_source_line"] = lineNumber.ToString(CultureInfo.InvariantCulture);
                        detectionEvent.Details["replay_original_timestamp_utc"] = originalTimestamp.ToString("o", CultureInfo.InvariantCulture);

                        logger.Log(detectionEvent);
                        result.ReplayedEvents++;
                    }
                }

                EvaluateExpectations(options, logger, result, capturedEvents, eventCaptureLock);
                WriteSummary(result);

                logger.Log(DetectionEvent.Create(
                    "Replay",
                    "Completed",
                    result.ExpectationsEvaluated && !result.ExpectationsPassed
                        ? EventSeverity.High
                        : result.ParseFailures == 0 ? EventSeverity.Low : EventSeverity.Medium,
                    "Detection replay completed.",
                    result.SummaryPath,
                    null,
                    new Dictionary<string, string>
                    {
                        { "files_read", result.FilesRead.ToString(CultureInfo.InvariantCulture) },
                        { "lines_read", result.LinesRead.ToString(CultureInfo.InvariantCulture) },
                        { "parsed_events", result.ParsedEvents.ToString(CultureInfo.InvariantCulture) },
                        { "replayed_events", result.ReplayedEvents.ToString(CultureInfo.InvariantCulture) },
                        { "skipped_derived_events", result.SkippedDerivedEvents.ToString(CultureInfo.InvariantCulture) },
                        { "parse_failures", result.ParseFailures.ToString(CultureInfo.InvariantCulture) },
                        { "expectations_evaluated", result.ExpectationsEvaluated.ToString() },
                        { "expectations_passed", result.ExpectationsPassed.ToString() },
                        { "expectation_failure_count", result.ExpectationFailureCount.ToString(CultureInfo.InvariantCulture) },
                        { "summary_path", result.SummaryPath ?? string.Empty },
                        { "expectation_report_path", result.ExpectationReportPath ?? string.Empty }
                    }));

                return result;
            }
            finally
            {
                logger.EventLogged -= captureEvent;
            }
        }

        private static void EvaluateExpectations(
            MonitorOptions options,
            EventLogger logger,
            DetectionReplayResult result,
            List<DetectionEvent> capturedEvents,
            object eventCaptureLock)
        {
            if (string.IsNullOrWhiteSpace(options.ReplayExpectationPath))
            {
                return;
            }

            List<DetectionEvent> snapshot;
            lock (eventCaptureLock)
            {
                snapshot = capturedEvents.ToList();
            }

            ReplayExpectationEvaluation evaluation = ReplayExpectationEvaluator.Evaluate(
                options.ReplayExpectationPath,
                result,
                snapshot,
                result.OutputDirectory);

            result.ExpectationsEvaluated = true;
            result.ExpectationsPassed = evaluation.Passed;
            result.ExpectationPath = evaluation.ExpectationPath;
            result.ExpectationReportPath = evaluation.ReportPath;
            result.ExpectationFailureCount = evaluation.Failures.Count;

            logger.Log(DetectionEvent.Create(
                "Replay",
                evaluation.Passed ? "ExpectationsPassed" : "ExpectationsFailed",
                evaluation.Passed ? EventSeverity.Low : EventSeverity.High,
                evaluation.Passed
                    ? "Replay expectations passed."
                    : "Replay expectations failed.",
                evaluation.ReportPath,
                null,
                new Dictionary<string, string>
                {
                    { "expectation_path", evaluation.ExpectationPath ?? string.Empty },
                    { "expectation_report_path", evaluation.ReportPath ?? string.Empty },
                    { "failure_count", evaluation.Failures.Count.ToString(CultureInfo.InvariantCulture) }
                }));
        }

        private static bool IsDerivedEvent(DetectionEvent detectionEvent)
        {
            if (detectionEvent == null || string.IsNullOrWhiteSpace(detectionEvent.Category))
            {
                return false;
            }

            return DerivedCategoryPrefixes.Any(prefix =>
                detectionEvent.Category.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        }

        private static List<string> ResolveInputFiles(IEnumerable<string> rawInputs, DetectionReplayResult result)
        {
            SortedSet<string> files = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string rawInput in rawInputs ?? Enumerable.Empty<string>())
            {
                string input = Environment.ExpandEnvironmentVariables(rawInput ?? string.Empty).Trim().Trim('"');
                if (string.IsNullOrWhiteSpace(input))
                {
                    continue;
                }

                if (HasWildcard(input))
                {
                    string directory = Path.GetDirectoryName(input);
                    string pattern = Path.GetFileName(input);
                    if (string.IsNullOrWhiteSpace(directory))
                    {
                        directory = Directory.GetCurrentDirectory();
                    }

                    if (Directory.Exists(directory))
                    {
                        foreach (string file in Directory.GetFiles(directory, pattern, SearchOption.TopDirectoryOnly))
                        {
                            AddJsonLogFile(files, file);
                        }
                    }
                    else
                    {
                        result.MissingInputs.Add(input);
                    }
                }
                else if (Directory.Exists(input))
                {
                    string[] eventLogs = Directory.GetFiles(input, "aegis-events-*.jsonl", SearchOption.AllDirectories);
                    if (eventLogs.Length == 0)
                    {
                        eventLogs = Directory.GetFiles(input, "*.jsonl", SearchOption.AllDirectories);
                    }

                    foreach (string file in eventLogs)
                    {
                        AddJsonLogFile(files, file);
                    }
                }
                else if (File.Exists(input))
                {
                    AddJsonLogFile(files, input);
                }
                else
                {
                    result.MissingInputs.Add(input);
                }
            }

            return files.ToList();
        }

        private static void AddJsonLogFile(ISet<string> files, string file)
        {
            if (string.IsNullOrWhiteSpace(file) ||
                file.EndsWith(".chain.jsonl", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            files.Add(Path.GetFullPath(file));
        }

        private static bool HasWildcard(string path)
        {
            return path.IndexOf('*') >= 0 || path.IndexOf('?') >= 0;
        }

        private static void WriteSummary(DetectionReplayResult result)
        {
            if (string.IsNullOrWhiteSpace(result.OutputDirectory))
            {
                return;
            }

            Directory.CreateDirectory(result.OutputDirectory);
            result.SummaryPath = Path.Combine(result.OutputDirectory, "replay-summary.txt");

            StringBuilder builder = new StringBuilder();
            builder.AppendLine("Aegis detection replay summary");
            builder.AppendLine("Generated UTC: " + DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture));
            builder.AppendLine("Output directory: " + result.OutputDirectory);
            builder.AppendLine("Files read: " + result.FilesRead.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Lines read: " + result.LinesRead.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Parsed events: " + result.ParsedEvents.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Replayed events: " + result.ReplayedEvents.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Skipped derived events: " + result.SkippedDerivedEvents.ToString(CultureInfo.InvariantCulture));
            builder.AppendLine("Parse failures: " + result.ParseFailures.ToString(CultureInfo.InvariantCulture));
            if (result.ExpectationsEvaluated)
            {
                builder.AppendLine("Expectations: " + (result.ExpectationsPassed ? "PASS" : "FAIL"));
                builder.AppendLine("Expectation file: " + (result.ExpectationPath ?? string.Empty));
                builder.AppendLine("Expectation report: " + (result.ExpectationReportPath ?? string.Empty));
                builder.AppendLine("Expectation failures: " + result.ExpectationFailureCount.ToString(CultureInfo.InvariantCulture));
            }

            builder.AppendLine();
            builder.AppendLine("Input files:");
            foreach (string file in result.InputFiles)
            {
                builder.AppendLine("- " + file);
            }

            if (result.MissingInputs.Count > 0)
            {
                builder.AppendLine();
                builder.AppendLine("Missing inputs:");
                foreach (string input in result.MissingInputs)
                {
                    builder.AppendLine("- " + input);
                }
            }

            File.WriteAllText(result.SummaryPath, builder.ToString(), Encoding.UTF8);
        }
    }

    internal sealed class DetectionReplayResult
    {
        public DetectionReplayResult()
        {
            InputFiles = new List<string>();
            MissingInputs = new List<string>();
        }

        public string OutputDirectory { get; set; }

        public string SummaryPath { get; set; }

        public List<string> InputFiles { get; private set; }

        public List<string> MissingInputs { get; private set; }

        public int FilesRead { get; set; }

        public long LinesRead { get; set; }

        public long ParsedEvents { get; set; }

        public long ReplayedEvents { get; set; }

        public long SkippedDerivedEvents { get; set; }

        public long ParseFailures { get; set; }

        public bool ExpectationsEvaluated { get; set; }

        public bool ExpectationsPassed { get; set; }

        public string ExpectationPath { get; set; }

        public string ExpectationReportPath { get; set; }

        public int ExpectationFailureCount { get; set; }
    }
}
