using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal static class ReplayEventReader
    {
        private static readonly DataContractJsonSerializer Serializer =
            new DataContractJsonSerializer(typeof(ReplayEventRecord));

        public static bool TryParse(string jsonLine, out DetectionEvent detectionEvent, out string error)
        {
            detectionEvent = null;
            error = null;

            if (string.IsNullOrWhiteSpace(jsonLine))
            {
                error = "empty line";
                return false;
            }

            try
            {
                ReplayEventRecord record;
                using (MemoryStream stream = new MemoryStream(Encoding.UTF8.GetBytes(jsonLine.Trim())))
                {
                    record = Serializer.ReadObject(stream) as ReplayEventRecord;
                }

                if (record == null)
                {
                    error = "JSON line did not contain an event record.";
                    return false;
                }

                DateTimeOffset timestampUtc;
                if (!DateTimeOffset.TryParse(
                        record.TimestampUtc,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                        out timestampUtc))
                {
                    timestampUtc = DateTimeOffset.UtcNow;
                }

                EventSeverity severity;
                if (!Enum.TryParse(record.Severity ?? string.Empty, true, out severity))
                {
                    severity = EventSeverity.Low;
                }

                detectionEvent = DetectionEvent.CreateReplayed(
                    timestampUtc,
                    record.Category,
                    record.Action,
                    severity,
                    record.Description,
                    record.Path,
                    record.ProcessId,
                    record.ProcessName,
                    ParseDetails(jsonLine));
                return true;
            }
            catch (Exception ex)
            {
                error = ex.GetType().Name + ": " + ex.Message;
                return false;
            }
        }

        private static Dictionary<string, string> ParseDetails(string jsonLine)
        {
            Dictionary<string, string> details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            int detailsName = jsonLine.IndexOf("\"details\"", StringComparison.OrdinalIgnoreCase);
            if (detailsName < 0)
            {
                return details;
            }

            int colon = jsonLine.IndexOf(':', detailsName);
            if (colon < 0)
            {
                return details;
            }

            int index = SkipWhitespace(jsonLine, colon + 1);
            if (index >= jsonLine.Length || jsonLine[index] != '{')
            {
                return details;
            }

            index++;
            while (index < jsonLine.Length)
            {
                index = SkipWhitespace(jsonLine, index);
                if (index >= jsonLine.Length || jsonLine[index] == '}')
                {
                    break;
                }

                string key;
                if (!TryReadJsonString(jsonLine, ref index, out key))
                {
                    break;
                }

                index = SkipWhitespace(jsonLine, index);
                if (index >= jsonLine.Length || jsonLine[index] != ':')
                {
                    break;
                }

                index = SkipWhitespace(jsonLine, index + 1);
                string value = null;
                if (index < jsonLine.Length && jsonLine[index] == '"')
                {
                    TryReadJsonString(jsonLine, ref index, out value);
                }
                else
                {
                    int valueStart = index;
                    while (index < jsonLine.Length && jsonLine[index] != ',' && jsonLine[index] != '}')
                    {
                        index++;
                    }

                    string rawValue = jsonLine.Substring(valueStart, index - valueStart).Trim();
                    if (!rawValue.Equals("null", StringComparison.OrdinalIgnoreCase))
                    {
                        value = rawValue;
                    }
                }

                if (!string.IsNullOrWhiteSpace(key))
                {
                    details[key] = value;
                }

                index = SkipWhitespace(jsonLine, index);
                if (index < jsonLine.Length && jsonLine[index] == ',')
                {
                    index++;
                }
            }

            return details;
        }

        private static int SkipWhitespace(string value, int index)
        {
            while (index < value.Length && char.IsWhiteSpace(value[index]))
            {
                index++;
            }

            return index;
        }

        private static bool TryReadJsonString(string value, ref int index, out string result)
        {
            result = null;
            if (index >= value.Length || value[index] != '"')
            {
                return false;
            }

            index++;
            StringBuilder builder = new StringBuilder();
            while (index < value.Length)
            {
                char c = value[index++];
                if (c == '"')
                {
                    result = builder.ToString();
                    return true;
                }

                if (c != '\\')
                {
                    builder.Append(c);
                    continue;
                }

                if (index >= value.Length)
                {
                    break;
                }

                char escaped = value[index++];
                switch (escaped)
                {
                    case '"':
                    case '\\':
                    case '/':
                        builder.Append(escaped);
                        break;
                    case 'b':
                        builder.Append('\b');
                        break;
                    case 'f':
                        builder.Append('\f');
                        break;
                    case 'n':
                        builder.Append('\n');
                        break;
                    case 'r':
                        builder.Append('\r');
                        break;
                    case 't':
                        builder.Append('\t');
                        break;
                    case 'u':
                        if (index + 4 <= value.Length)
                        {
                            string hex = value.Substring(index, 4);
                            int codePoint;
                            if (int.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out codePoint))
                            {
                                builder.Append((char)codePoint);
                                index += 4;
                            }
                        }
                        break;
                    default:
                        builder.Append(escaped);
                        break;
                }
            }

            return false;
        }

        [DataContract]
        private sealed class ReplayEventRecord
        {
            [DataMember(Name = "timestamp_utc")]
            public string TimestampUtc { get; set; }

            [DataMember(Name = "category")]
            public string Category { get; set; }

            [DataMember(Name = "action")]
            public string Action { get; set; }

            [DataMember(Name = "severity")]
            public string Severity { get; set; }

            [DataMember(Name = "description")]
            public string Description { get; set; }

            [DataMember(Name = "path")]
            public string Path { get; set; }

            [DataMember(Name = "process_id")]
            public int? ProcessId { get; set; }

            [DataMember(Name = "process_name")]
            public string ProcessName { get; set; }
        }
    }
}
