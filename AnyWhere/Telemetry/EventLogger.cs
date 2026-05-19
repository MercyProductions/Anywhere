using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal sealed class EventLogger : IDisposable
    {
        private readonly object _syncRoot = new object();
        private readonly StreamWriter _chainWriter;
        private readonly StreamWriter _jsonWriter;
        private readonly StreamWriter _textWriter;
        private readonly bool _verboseConsole;
        private string _previousJsonHash;
        private long _sequence;

        public event Action<DetectionEvent> EventLogged;

        public EventLogger(string logRoot, bool verboseConsole)
        {
            _verboseConsole = verboseConsole;
            Directory.CreateDirectory(logRoot);

            string stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
            JsonLogPath = Path.Combine(logRoot, "aegis-events-" + stamp + ".jsonl");
            TextLogPath = Path.Combine(logRoot, "aegis-events-" + stamp + ".log");
            HashChainPath = Path.Combine(logRoot, "aegis-events-" + stamp + ".chain.jsonl");

            _jsonWriter = new StreamWriter(new FileStream(JsonLogPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite), Encoding.UTF8);
            _textWriter = new StreamWriter(new FileStream(TextLogPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite), Encoding.UTF8);
            _chainWriter = new StreamWriter(new FileStream(HashChainPath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite), Encoding.UTF8);
            _jsonWriter.AutoFlush = true;
            _textWriter.AutoFlush = true;
            _chainWriter.AutoFlush = true;
            _previousJsonHash = new string('0', 64);
        }

        public string JsonLogPath { get; private set; }

        public string TextLogPath { get; private set; }

        public string HashChainPath { get; private set; }

        public void Log(DetectionEvent detectionEvent)
        {
            if (detectionEvent == null)
            {
                return;
            }

            lock (_syncRoot)
            {
                string line = FormatText(detectionEvent);
                string json = ToJson(detectionEvent);
                _textWriter.WriteLine(line);
                _jsonWriter.WriteLine(json);
                AppendHashChain(json);

                if (_verboseConsole || detectionEvent.Severity >= EventSeverity.Medium)
                {
                    ConsoleColor previous = Console.ForegroundColor;
                    Console.ForegroundColor = GetColor(detectionEvent.Severity);
                    Console.WriteLine(line);
                    Console.ForegroundColor = previous;
                }
            }

            Action<DetectionEvent> handler = EventLogged;
            if (handler != null)
            {
                try
                {
                    handler(detectionEvent);
                }
                catch
                {
                    // Subscribers must never break primary evidence logging.
                }
            }
        }

        private void AppendHashChain(string jsonLine)
        {
            _sequence++;
            string eventHash = Sha256Hex(jsonLine);
            string chainHash = Sha256Hex(_previousJsonHash + "|" + eventHash + "|" + _sequence.ToString(CultureInfo.InvariantCulture));

            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            AppendJsonProperty(builder, "sequence", _sequence.ToString(CultureInfo.InvariantCulture), first);
            first = false;
            AppendJsonProperty(builder, "timestamp_utc", DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture), first);
            AppendJsonProperty(builder, "previous_chain_hash", _previousJsonHash, false);
            AppendJsonProperty(builder, "event_sha256", eventHash, false);
            AppendJsonProperty(builder, "chain_sha256", chainHash, false);
            builder.Append("}");
            _chainWriter.WriteLine(builder.ToString());
            _previousJsonHash = chainHash;
        }

        private static string Sha256Hex(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(bytes);
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                }

                return builder.ToString();
            }
        }

        public void LogException(string category, string action, Exception ex, string subject)
        {
            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "exception_type", ex.GetType().FullName },
                { "exception_message", ex.Message }
            };

            Log(DetectionEvent.Create(
                category,
                action,
                EventSeverity.Medium,
                subject == null ? ex.Message : subject + ": " + ex.Message,
                null,
                null,
                details));
        }

        private static ConsoleColor GetColor(EventSeverity severity)
        {
            switch (severity)
            {
                case EventSeverity.Critical:
                    return ConsoleColor.Magenta;
                case EventSeverity.High:
                    return ConsoleColor.Red;
                case EventSeverity.Medium:
                    return ConsoleColor.Yellow;
                default:
                    return ConsoleColor.Gray;
            }
        }

        private static string FormatText(DetectionEvent detectionEvent)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append(detectionEvent.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff zzz", CultureInfo.InvariantCulture));
            builder.Append(" [");
            builder.Append(detectionEvent.Severity);
            builder.Append("] ");
            builder.Append(detectionEvent.Category);
            builder.Append("/");
            builder.Append(detectionEvent.Action);
            builder.Append(" - ");
            builder.Append(detectionEvent.Description);

            if (!string.IsNullOrWhiteSpace(detectionEvent.Path))
            {
                builder.Append(" | Path: ");
                builder.Append(detectionEvent.Path);
            }

            if (detectionEvent.ProcessId.HasValue || !string.IsNullOrWhiteSpace(detectionEvent.ProcessName))
            {
                builder.Append(" | Process: ");
                builder.Append(detectionEvent.ProcessName ?? "unknown");
                if (detectionEvent.ProcessId.HasValue)
                {
                    builder.Append(" (");
                    builder.Append(detectionEvent.ProcessId.Value);
                    builder.Append(")");
                }
            }

            return builder.ToString();
        }

        private static string ToJson(DetectionEvent detectionEvent)
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("{");
            AppendJsonProperty(builder, "timestamp_utc", detectionEvent.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), true);
            AppendJsonProperty(builder, "category", detectionEvent.Category, false);
            AppendJsonProperty(builder, "action", detectionEvent.Action, false);
            AppendJsonProperty(builder, "severity", detectionEvent.Severity.ToString(), false);
            AppendJsonProperty(builder, "description", detectionEvent.Description, false);
            AppendJsonProperty(builder, "path", detectionEvent.Path, false);
            AppendJsonProperty(builder, "process_name", detectionEvent.ProcessName, false);

            builder.Append(",\"process_id\":");
            if (detectionEvent.ProcessId.HasValue)
            {
                builder.Append(detectionEvent.ProcessId.Value.ToString(CultureInfo.InvariantCulture));
            }
            else
            {
                builder.Append("null");
            }

            builder.Append(",\"details\":{");
            bool firstDetail = true;
            foreach (KeyValuePair<string, string> pair in detectionEvent.Details)
            {
                AppendJsonProperty(builder, pair.Key, pair.Value, firstDetail);
                firstDetail = false;
            }
            builder.Append("}}");
            return builder.ToString();
        }

        private static void AppendJsonProperty(StringBuilder builder, string name, string value, bool first)
        {
            if (!first)
            {
                builder.Append(",");
            }

            builder.Append("\"");
            builder.Append(EscapeJson(name));
            builder.Append("\":");

            if (value == null)
            {
                builder.Append("null");
            }
            else
            {
                builder.Append("\"");
                builder.Append(EscapeJson(value));
                builder.Append("\"");
            }
        }

        private static string EscapeJson(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            StringBuilder builder = new StringBuilder(value.Length + 8);
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\':
                        builder.Append("\\\\");
                        break;
                    case '"':
                        builder.Append("\\\"");
                        break;
                    case '\b':
                        builder.Append("\\b");
                        break;
                    case '\f':
                        builder.Append("\\f");
                        break;
                    case '\n':
                        builder.Append("\\n");
                        break;
                    case '\r':
                        builder.Append("\\r");
                        break;
                    case '\t':
                        builder.Append("\\t");
                        break;
                    default:
                        if (c < 32)
                        {
                            builder.Append("\\u");
                            builder.Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        }
                        else
                        {
                            builder.Append(c);
                        }
                        break;
                }
            }

            return builder.ToString();
        }

        public void Dispose()
        {
            lock (_syncRoot)
            {
                _jsonWriter.Dispose();
                _textWriter.Dispose();
                _chainWriter.Dispose();
            }
        }
    }
}
