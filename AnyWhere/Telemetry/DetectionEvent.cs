using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace AnyWhere.Telemetry
{
    internal sealed class DetectionEvent
    {
        private DetectionEvent()
        {
            TimestampUtc = DateTimeOffset.UtcNow;
            Details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public DateTimeOffset TimestampUtc { get; private set; }

        public string Category { get; private set; }

        public string Action { get; private set; }

        public EventSeverity Severity { get; private set; }

        public string Description { get; private set; }

        public string Path { get; private set; }

        public string ProcessName { get; private set; }

        public int? ProcessId { get; private set; }

        public Dictionary<string, string> Details { get; private set; }

        public static DetectionEvent Create(
            string category,
            string action,
            EventSeverity severity,
            string description,
            string path,
            Process process,
            IDictionary<string, string> details)
        {
            DetectionEvent detectionEvent = new DetectionEvent
            {
                Category = category ?? "General",
                Action = action ?? "Observed",
                Severity = severity,
                Description = description ?? string.Empty,
                Path = path
            };

            if (process != null)
            {
                detectionEvent.ProcessId = SafeGetProcessId(process);
                detectionEvent.ProcessName = SafeGetProcessName(process);
            }

            if (details != null)
            {
                foreach (KeyValuePair<string, string> pair in details)
                {
                    detectionEvent.Details[pair.Key] = pair.Value;
                }
            }

            return detectionEvent;
        }

        public static DetectionEvent CreateForProcess(
            string category,
            string action,
            EventSeverity severity,
            string description,
            string path,
            int processId,
            string processName,
            IDictionary<string, string> details)
        {
            DetectionEvent detectionEvent = Create(category, action, severity, description, path, null, details);
            detectionEvent.ProcessId = processId;
            detectionEvent.ProcessName = processName;
            return detectionEvent;
        }

        private static int? SafeGetProcessId(Process process)
        {
            try
            {
                return process.Id;
            }
            catch
            {
                return null;
            }
        }

        private static string SafeGetProcessName(Process process)
        {
            try
            {
                return process.ProcessName;
            }
            catch
            {
                return null;
            }
        }
    }
}
