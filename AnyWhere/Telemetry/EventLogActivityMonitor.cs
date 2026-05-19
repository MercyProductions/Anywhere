using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace AnyWhere.Telemetry
{
    internal sealed class EventLogActivityMonitor : IDetectionMonitor
    {
        private static readonly XNamespace EventNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";

        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly List<EventLogWatcher> _watchers = new List<EventLogWatcher>();
        private bool _disposed;

        public EventLogActivityMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
        }

        public string Name
        {
            get { return "Windows Event Logs"; }
        }

        public void Start()
        {
            foreach (EventLogSubscriptionTarget target in BuildTargets())
            {
                TryStartWatcher(target);
            }

            _logger.Log(DetectionEvent.Create(
                "EventLog",
                "Baseline",
                EventSeverity.Low,
                "Windows event-log monitor started with " + _watchers.Count.ToString(CultureInfo.InvariantCulture) + " active subscriptions.",
                null,
                null,
                null));
        }

        private void TryStartWatcher(EventLogSubscriptionTarget target)
        {
            try
            {
                EventLogQuery query = new EventLogQuery(target.LogName, PathType.LogName, target.Query)
                {
                    ReverseDirection = false,
                    TolerateQueryErrors = true
                };

                EventLogWatcher watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += delegate(object sender, EventRecordWrittenEventArgs eventArgs)
                {
                    OnEventRecord(target, eventArgs);
                };
                watcher.Enabled = true;
                _watchers.Add(watcher);

                _logger.Log(DetectionEvent.Create(
                    "EventLog",
                    "Subscribed",
                    EventSeverity.Low,
                    "Subscribed to " + target.Name + ".",
                    target.LogName,
                    null,
                    null));
            }
            catch (Exception ex)
            {
                _logger.Log(DetectionEvent.Create(
                    "EventLog",
                    "SubscriptionFailed",
                    EventSeverity.Medium,
                    "Could not subscribe to " + target.Name + ".",
                    target.LogName,
                    null,
                    new Dictionary<string, string>
                    {
                        { "exception_type", ex.GetType().FullName },
                        { "exception_message", ex.Message },
                        { "note", "This can happen when the log is disabled, missing, or requires elevation." }
                    }));
            }
        }

        private void OnEventRecord(EventLogSubscriptionTarget target, EventRecordWrittenEventArgs eventArgs)
        {
            if (_disposed)
            {
                return;
            }

            if (eventArgs.EventException != null)
            {
                _logger.LogException("EventLog", "DeliveryFailed", eventArgs.EventException, target.Name);
                return;
            }

            using (EventRecord record = eventArgs.EventRecord)
            {
                if (record == null)
                {
                    return;
                }

                try
                {
                    ParsedEventLogRecord parsed = ParseRecord(record, target);
                    DetectionEvent detectionEvent = ConvertRecord(parsed);
                    if (detectionEvent != null)
                    {
                        _logger.Log(detectionEvent);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogException("EventLog", "ParseFailed", ex, target.Name);
                }
            }
        }

        private DetectionEvent ConvertRecord(ParsedEventLogRecord parsed)
        {
            if (parsed.LogName.Equals("Security", StringComparison.OrdinalIgnoreCase))
            {
                return ConvertSecurityEvent(parsed);
            }

            if (parsed.LogName.Equals("Microsoft-Windows-Sysmon/Operational", StringComparison.OrdinalIgnoreCase))
            {
                return ConvertSysmonEvent(parsed);
            }

            if (parsed.LogName.Equals("Microsoft-Windows-PowerShell/Operational", StringComparison.OrdinalIgnoreCase))
            {
                return ConvertPowerShellEvent(parsed);
            }

            if (parsed.LogName.Equals("Microsoft-Windows-CodeIntegrity/Operational", StringComparison.OrdinalIgnoreCase))
            {
                return ConvertCodeIntegrityEvent(parsed);
            }

            if (parsed.LogName.Equals("System", StringComparison.OrdinalIgnoreCase))
            {
                return ConvertSystemEvent(parsed);
            }

            return DetectionEvent.Create(
                "EventLog",
                "Observed",
                EventSeverity.Low,
                parsed.ProviderName + " event " + parsed.EventId.ToString(CultureInfo.InvariantCulture),
                null,
                null,
                parsed.ToDetails());
        }

        private DetectionEvent ConvertSecurityEvent(ParsedEventLogRecord parsed)
        {
            Dictionary<string, string> data = parsed.Data;
            string path = FirstValue(data, "NewProcessName", "ObjectName", "ServiceFileName", "ProcessName");
            string subject = FirstValue(data, "SubjectUserName", "AccountName", "TargetUserName");
            EventSeverity severity = EventSeverity.Medium;
            string action;
            string description;

            switch (parsed.EventId)
            {
                case 4688:
                    action = "ProcessCreated";
                    description = "Security audit process creation: " + SafeFileName(path);
                    AddFileClassifierDetails(path, data, includeHash: false);
                    severity = ClassifyPathSignal(path, EventSeverity.Low, EventSeverity.High);
                    break;
                case 4689:
                    action = "ProcessExited";
                    description = "Security audit process exit: " + SafeFileName(path);
                    severity = EventSeverity.Low;
                    break;
                case 4657:
                    action = "RegistryValueModified";
                    description = "Security audit registry value modified: " + path;
                    severity = EventSeverity.High;
                    break;
                case 4663:
                    action = IsDeleteAccess(data) ? "FileDeletedOrModified" : "FileAccessed";
                    description = "Security object access: " + path;
                    severity = IsDeleteAccess(data) ? EventSeverity.High : EventSeverity.Medium;
                    break;
                case 4670:
                    action = "PermissionsChanged";
                    description = "Security permissions changed: " + path;
                    severity = EventSeverity.High;
                    break;
                case 4697:
                    action = "ServiceInstalled";
                    description = "Security audit service installed: " + FirstValue(data, "ServiceName");
                    severity = EventSeverity.High;
                    break;
                case 4719:
                    action = "AuditPolicyChanged";
                    description = "Security audit policy changed.";
                    severity = EventSeverity.High;
                    break;
                case 1102:
                    action = "AuditLogCleared";
                    description = "The Security audit log was cleared.";
                    severity = EventSeverity.Critical;
                    break;
                default:
                    action = "Observed";
                    description = "Security audit event " + parsed.EventId.ToString(CultureInfo.InvariantCulture);
                    break;
            }

            if (!string.IsNullOrWhiteSpace(subject))
            {
                data["subject_user"] = subject;
            }

            return DetectionEvent.Create(
                "EventLog.Security",
                action,
                severity,
                description,
                path,
                null,
                parsed.ToDetails());
        }

        private DetectionEvent ConvertSysmonEvent(ParsedEventLogRecord parsed)
        {
            Dictionary<string, string> data = parsed.Data;
            string path = FirstValue(data, "Image", "TargetFilename", "ImageLoaded", "TargetObject", "DestinationHostname", "QueryName");
            EventSeverity severity = EventSeverity.Medium;
            string action;
            string description;

            switch (parsed.EventId)
            {
                case 1:
                    action = "ProcessCreated";
                    description = "Sysmon process creation: " + SafeFileName(path);
                    AddFileClassifierDetails(path, data, includeHash: false);
                    severity = ClassifyPathSignal(path, EventSeverity.Low, EventSeverity.High);
                    break;
                case 2:
                    action = "FileCreationTimeChanged";
                    description = "Sysmon file creation time changed: " + path;
                    severity = EventSeverity.Medium;
                    break;
                case 3:
                    action = "NetworkConnection";
                    description = "Sysmon network connection: " + FirstValue(data, "Image") + " -> " + FirstValue(data, "DestinationIp", "DestinationHostname");
                    severity = EventSeverity.Medium;
                    break;
                case 6:
                    action = "DriverLoaded";
                    description = "Sysmon driver loaded: " + path;
                    AddFileClassifierDetails(path, data, includeHash: false);
                    severity = ClassifyPathSignal(path, EventSeverity.High, EventSeverity.Critical);
                    break;
                case 7:
                    action = "ImageLoaded";
                    description = "Sysmon image loaded: " + path;
                    AddFileClassifierDetails(path, data, includeHash: false);
                    severity = ClassifyPathSignal(path, EventSeverity.Low, EventSeverity.High);
                    break;
                case 10:
                    action = "ProcessAccessed";
                    description = "Sysmon process access: " + FirstValue(data, "SourceImage") + " -> " + FirstValue(data, "TargetImage");
                    severity = EventSeverity.High;
                    break;
                case 11:
                    action = "FileCreated";
                    description = "Sysmon file created: " + path;
                    AddFileClassifierDetails(path, data, includeHash: false);
                    severity = ClassifyPathSignal(path, EventSeverity.Medium, EventSeverity.High);
                    break;
                case 12:
                    action = "RegistryObjectCreatedOrDeleted";
                    description = "Sysmon registry object changed: " + path;
                    severity = EventSeverity.High;
                    break;
                case 13:
                    action = "RegistryValueSet";
                    description = "Sysmon registry value set: " + path;
                    severity = EventSeverity.High;
                    break;
                case 14:
                    action = "RegistryObjectRenamed";
                    description = "Sysmon registry object renamed: " + path;
                    severity = EventSeverity.High;
                    break;
                case 15:
                    action = "FileCreateStreamHash";
                    description = "Sysmon alternate data stream created: " + path;
                    severity = EventSeverity.High;
                    break;
                case 22:
                    action = "DnsQuery";
                    description = "Sysmon DNS query: " + FirstValue(data, "QueryName");
                    severity = EventSeverity.Medium;
                    break;
                case 23:
                case 26:
                    action = "FileDeleted";
                    description = "Sysmon file deleted: " + path;
                    severity = EventSeverity.High;
                    break;
                case 25:
                    action = "ProcessTampering";
                    description = "Sysmon process tampering: " + path;
                    severity = EventSeverity.Critical;
                    break;
                default:
                    action = "Observed";
                    description = "Sysmon event " + parsed.EventId.ToString(CultureInfo.InvariantCulture);
                    break;
            }

            return DetectionEvent.Create(
                "EventLog.Sysmon",
                action,
                severity,
                description,
                path,
                null,
                parsed.ToDetails());
        }

        private DetectionEvent ConvertPowerShellEvent(ParsedEventLogRecord parsed)
        {
            EventSeverity severity = parsed.EventId == 4104 ? EventSeverity.High : EventSeverity.Medium;
            string scriptText = FirstValue(parsed.Data, "ScriptBlockText", "Payload", "Message");
            string description = parsed.EventId == 4104
                ? "PowerShell script block logged."
                : "PowerShell module or command activity logged.";

            if (!string.IsNullOrWhiteSpace(scriptText))
            {
                parsed.Data["script_preview"] = Truncate(scriptText, 1200);
            }

            return DetectionEvent.Create(
                "EventLog.PowerShell",
                parsed.EventId == 4104 ? "ScriptBlock" : "CommandActivity",
                severity,
                description,
                null,
                null,
                parsed.ToDetails());
        }

        private DetectionEvent ConvertCodeIntegrityEvent(ParsedEventLogRecord parsed)
        {
            string path = FirstValue(parsed.Data, "FileName", "FilePath", "ImageName", "ProcessName", "param1", "param2");
            string action = "CodeIntegritySignal";
            EventSeverity severity = EventSeverity.High;

            if (parsed.EventId == 3077 || parsed.EventId == 3033)
            {
                action = "CodeIntegrityBlocked";
                severity = EventSeverity.Critical;
            }
            else if (parsed.EventId == 3076 || parsed.EventId == 3065 || parsed.EventId == 3066)
            {
                action = "CodeIntegrityAudit";
                severity = EventSeverity.High;
            }

            if (!string.IsNullOrWhiteSpace(path))
            {
                AddFileClassifierDetails(path, parsed.Data, includeHash: false);
            }

            return DetectionEvent.Create(
                "EventLog.CodeIntegrity",
                action,
                severity,
                "Code Integrity event " + parsed.EventId.ToString(CultureInfo.InvariantCulture) + ": " + (path ?? "no path"),
                path,
                null,
                parsed.ToDetails());
        }

        private DetectionEvent ConvertSystemEvent(ParsedEventLogRecord parsed)
        {
            if (parsed.EventId == 7045)
            {
                string serviceName = FirstValue(parsed.Data, "ServiceName", "param1");
                string servicePath = FirstValue(parsed.Data, "ImagePath", "ServiceFileName", "param2");
                return DetectionEvent.Create(
                    "EventLog.System",
                    "ServiceInstalled",
                    EventSeverity.High,
                    "Service installed: " + serviceName,
                    servicePath,
                    null,
                    parsed.ToDetails());
            }

            if (parsed.EventId == 7000 || parsed.EventId == 7009 || parsed.EventId == 7011)
            {
                return DetectionEvent.Create(
                    "EventLog.System",
                    "DriverOrServiceLoadFailure",
                    EventSeverity.High,
                    "Service Control Manager reported a load/start failure.",
                    null,
                    null,
                    parsed.ToDetails());
            }

            if (parsed.EventId == 7035 || parsed.EventId == 7036)
            {
                return DetectionEvent.Create(
                    "EventLog.System",
                    "ServiceControlStateChange",
                    EventSeverity.Medium,
                    "Service Control Manager reported a service control/state change.",
                    null,
                    null,
                    parsed.ToDetails());
            }

            return DetectionEvent.Create(
                "EventLog.System",
                "Observed",
                EventSeverity.Medium,
                "System event " + parsed.EventId.ToString(CultureInfo.InvariantCulture),
                null,
                null,
                parsed.ToDetails());
        }

        private void AddFileClassifierDetails(string path, IDictionary<string, string> data, bool includeHash)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            Dictionary<string, string> fileDetails = FileClassifier.BuildFileDetails(path, _options, includeHash);
            foreach (KeyValuePair<string, string> pair in fileDetails)
            {
                data["file_" + pair.Key] = pair.Value;
            }
        }

        private static EventSeverity ClassifyPathSignal(string path, EventSeverity normalSeverity, EventSeverity suspiciousSeverity)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return normalSeverity;
            }

            if (FileClassifier.IsLikelyDownloadLocation(path) ||
                FileClassifier.IsHighValuePersistencePath(path) ||
                FileClassifier.HasMarkOfTheWeb(path))
            {
                return suspiciousSeverity;
            }

            return normalSeverity;
        }

        private static bool IsDeleteAccess(IDictionary<string, string> data)
        {
            string accessList = FirstValue(data, "AccessList", "AccessMask", "Accesses");
            if (string.IsNullOrWhiteSpace(accessList))
            {
                return false;
            }

            return accessList.IndexOf("DELETE", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   accessList.IndexOf("%%1537", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   accessList.IndexOf("0x10000", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static ParsedEventLogRecord ParseRecord(EventRecord record, EventLogSubscriptionTarget target)
        {
            ParsedEventLogRecord parsed = new ParsedEventLogRecord
            {
                TargetName = target.Name,
                LogName = target.LogName,
                EventId = record.Id,
                ProviderName = record.ProviderName,
                RecordId = record.RecordId,
                MachineName = record.MachineName,
                TimeCreatedUtc = record.TimeCreated.HasValue ? record.TimeCreated.Value.ToUniversalTime() : (DateTime?)null
            };

            string xml = record.ToXml();
            parsed.RawXml = xml;

            XDocument document = XDocument.Parse(xml);
            XElement eventData = document.Descendants(EventNamespace + "EventData").FirstOrDefault();
            if (eventData != null)
            {
                int unnamedIndex = 0;
                foreach (XElement dataElement in eventData.Elements(EventNamespace + "Data"))
                {
                    string name = (string)dataElement.Attribute("Name");
                    if (string.IsNullOrWhiteSpace(name))
                    {
                        name = "param" + unnamedIndex.ToString(CultureInfo.InvariantCulture);
                        unnamedIndex++;
                    }

                    parsed.Data[name] = dataElement.Value ?? string.Empty;
                }
            }

            XElement userData = document.Descendants(EventNamespace + "UserData").FirstOrDefault();
            if (userData != null)
            {
                foreach (XElement valueElement in userData.Descendants().Where(e => !e.HasElements))
                {
                    string name = valueElement.Name.LocalName;
                    if (!string.IsNullOrWhiteSpace(name) && !parsed.Data.ContainsKey(name))
                    {
                        parsed.Data[name] = valueElement.Value ?? string.Empty;
                    }
                }
            }

            return parsed;
        }

        private static IEnumerable<EventLogSubscriptionTarget> BuildTargets()
        {
            yield return new EventLogSubscriptionTarget(
                "Security Audit",
                "Security",
                "*[System[(EventID=4688 or EventID=4689 or EventID=4657 or EventID=4663 or EventID=4670 or EventID=4697 or EventID=4719 or EventID=1102)]]");

            yield return new EventLogSubscriptionTarget(
                "Sysmon Operational",
                "Microsoft-Windows-Sysmon/Operational",
                "*[System[(EventID=1 or EventID=2 or EventID=3 or EventID=6 or EventID=7 or EventID=10 or EventID=11 or EventID=12 or EventID=13 or EventID=14 or EventID=15 or EventID=22 or EventID=23 or EventID=25 or EventID=26)]]");

            yield return new EventLogSubscriptionTarget(
                "PowerShell Operational",
                "Microsoft-Windows-PowerShell/Operational",
                "*[System[(EventID=4103 or EventID=4104)]]");

            yield return new EventLogSubscriptionTarget(
                "Code Integrity Operational",
                "Microsoft-Windows-CodeIntegrity/Operational",
                "*[System[(EventID=3001 or EventID=3002 or EventID=3003 or EventID=3004 or EventID=3010 or EventID=3023 or EventID=3033 or EventID=3063 or EventID=3065 or EventID=3066 or EventID=3076 or EventID=3077 or EventID=3089)]]");

            yield return new EventLogSubscriptionTarget(
                "System Service Control Manager",
                "System",
                "*[System[(EventID=7000 or EventID=7009 or EventID=7011 or EventID=7035 or EventID=7036 or EventID=7045)]]");
        }

        private static string FirstValue(IDictionary<string, string> data, params string[] keys)
        {
            foreach (string key in keys)
            {
                string value;
                if (data.TryGetValue(key, out value) && !string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return null;
        }

        private static string SafeFileName(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return "unknown";
            }

            try
            {
                return Path.GetFileName(path);
            }
            catch
            {
                return path;
            }
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
            {
                return value;
            }

            return value.Substring(0, maxLength) + "...";
        }

        public void Dispose()
        {
            _disposed = true;
            foreach (EventLogWatcher watcher in _watchers)
            {
                try
                {
                    watcher.Enabled = false;
                    watcher.Dispose();
                }
                catch
                {
                }
            }

            _watchers.Clear();
        }

        private sealed class ParsedEventLogRecord
        {
            public ParsedEventLogRecord()
            {
                Data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }

            public string TargetName { get; set; }

            public string LogName { get; set; }

            public int EventId { get; set; }

            public string ProviderName { get; set; }

            public long? RecordId { get; set; }

            public string MachineName { get; set; }

            public DateTime? TimeCreatedUtc { get; set; }

            public string RawXml { get; set; }

            public Dictionary<string, string> Data { get; private set; }

            public Dictionary<string, string> ToDetails()
            {
                Dictionary<string, string> details = new Dictionary<string, string>(Data, StringComparer.OrdinalIgnoreCase)
                {
                    { "event_log", LogName },
                    { "event_source", ProviderName ?? string.Empty },
                    { "event_id", EventId.ToString(CultureInfo.InvariantCulture) },
                    { "subscription", TargetName ?? string.Empty }
                };

                if (RecordId.HasValue)
                {
                    details["record_id"] = RecordId.Value.ToString(CultureInfo.InvariantCulture);
                }

                if (!string.IsNullOrWhiteSpace(MachineName))
                {
                    details["machine_name"] = MachineName;
                }

                if (TimeCreatedUtc.HasValue)
                {
                    details["event_time_utc"] = TimeCreatedUtc.Value.ToString("o", CultureInfo.InvariantCulture);
                }

                return details;
            }
        }
    }
}
