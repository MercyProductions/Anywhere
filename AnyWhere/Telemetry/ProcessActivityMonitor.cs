using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Management;

namespace AnyWhere.Telemetry
{
    internal sealed class ProcessActivityMonitor : IDetectionMonitor
    {
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly HashSet<int> _knownProcessIds = new HashSet<int>();
        private ManagementEventWatcher _startWatcher;
        private ManagementEventWatcher _stopWatcher;
        private bool _disposed;

        public ProcessActivityMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
        }

        public string Name
        {
            get { return "Process Activity"; }
        }

        public void Start()
        {
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    _knownProcessIds.Add(process.Id);
                }
                catch
                {
                    // Process exited during baseline.
                }
                finally
                {
                    process.Dispose();
                }
            }

            _startWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            _startWatcher.EventArrived += OnProcessStarted;
            _startWatcher.Start();

            _stopWatcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
            _stopWatcher.EventArrived += OnProcessStopped;
            _stopWatcher.Start();

            _logger.Log(DetectionEvent.Create(
                "Process",
                "Baseline",
                EventSeverity.Low,
                "Process monitor started with " + _knownProcessIds.Count.ToString(CultureInfo.InvariantCulture) + " existing processes.",
                null,
                null,
                null));
        }

        private void OnProcessStarted(object sender, EventArrivedEventArgs eventArgs)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                int processId = Convert.ToInt32(eventArgs.NewEvent["ProcessID"], CultureInfo.InvariantCulture);
                string processName = Convert.ToString(eventArgs.NewEvent["ProcessName"], CultureInfo.InvariantCulture);

                lock (_knownProcessIds)
                {
                    _knownProcessIds.Add(processId);
                }

                Dictionary<string, string> details = QueryProcessDetails(processId);
                if (!details.ContainsKey("process_name") && !string.IsNullOrWhiteSpace(processName))
                {
                    details["process_name"] = processName;
                }

                string path = GetDetail(details, "executable_path");
                if (!string.IsNullOrWhiteSpace(path))
                {
                    AddFileDetails(path, details);
                }

                EventSeverity severity = ClassifyExecution(path, details);
                string description = "Process executed: " + (string.IsNullOrWhiteSpace(processName) ? "unknown" : processName);

                _logger.Log(DetectionEvent.CreateForProcess(
                    "Process",
                    "Executed",
                    severity,
                    description,
                    path,
                    processId,
                    processName,
                    details));
            }
            catch (Exception ex)
            {
                _logger.LogException("Process", "StartTraceFailed", ex, null);
            }
        }

        private void OnProcessStopped(object sender, EventArrivedEventArgs eventArgs)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                int processId = Convert.ToInt32(eventArgs.NewEvent["ProcessID"], CultureInfo.InvariantCulture);
                string processName = Convert.ToString(eventArgs.NewEvent["ProcessName"], CultureInfo.InvariantCulture);

                lock (_knownProcessIds)
                {
                    _knownProcessIds.Remove(processId);
                }

                _logger.Log(DetectionEvent.CreateForProcess(
                    "Process",
                    "Exited",
                    EventSeverity.Low,
                    "Process exited: " + (string.IsNullOrWhiteSpace(processName) ? "unknown" : processName),
                    null,
                    processId,
                    processName,
                    null));
            }
            catch (Exception ex)
            {
                _logger.LogException("Process", "StopTraceFailed", ex, null);
            }
        }

        private void AddFileDetails(string path, IDictionary<string, string> details)
        {
            Dictionary<string, string> fileDetails = FileClassifier.BuildFileDetails(path, _options, true);
            foreach (KeyValuePair<string, string> pair in fileDetails)
            {
                details[pair.Key] = pair.Value;
            }

            if (FileClassifier.IsLikelyExecutable(path) &&
                (FileClassifier.IsLikelyDownloadLocation(path) || FileClassifier.HasMarkOfTheWeb(path)))
            {
                string evidencePath = FileClassifier.TryCopyEvidence(path, Path.GetDirectoryName(_logger.JsonLogPath), "Executed");
                if (!string.IsNullOrWhiteSpace(evidencePath))
                {
                    details["evidence_copy"] = evidencePath;
                }
            }
        }

        private static EventSeverity ClassifyExecution(string path, IDictionary<string, string> details)
        {
            bool hasMotw = details.ContainsKey("has_mark_of_the_web");
            bool downloadLocation = details.ContainsKey("is_download_location") &&
                                    details["is_download_location"].Equals("True", StringComparison.OrdinalIgnoreCase);
            bool persistenceLocation = details.ContainsKey("is_persistence_location") &&
                                       details["is_persistence_location"].Equals("True", StringComparison.OrdinalIgnoreCase);

            if (hasMotw || (downloadLocation && FileClassifier.IsLikelyExecutable(path)))
            {
                return EventSeverity.High;
            }

            if (persistenceLocation)
            {
                return EventSeverity.Medium;
            }

            return EventSeverity.Low;
        }

        private static Dictionary<string, string> QueryProcessDetails(int processId)
        {
            Dictionary<string, string> details = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "process_id", processId.ToString(CultureInfo.InvariantCulture) }
            };

            try
            {
                string query = "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process WHERE ProcessId = " +
                               processId.ToString(CultureInfo.InvariantCulture);

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(query))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject process in results)
                    {
                        using (process)
                        {
                            AddManagementValue(details, process, "Name", "process_name");
                            AddManagementValue(details, process, "ExecutablePath", "executable_path");
                            AddManagementValue(details, process, "CommandLine", "command_line");
                            AddManagementValue(details, process, "ParentProcessId", "parent_process_id");

                            string parentProcessId = GetDetail(details, "parent_process_id");
                            int parentId;
                            if (int.TryParse(parentProcessId, NumberStyles.Integer, CultureInfo.InvariantCulture, out parentId))
                            {
                                string parentName = TryGetProcessName(parentId);
                                if (!string.IsNullOrWhiteSpace(parentName))
                                {
                                    details["parent_process_name"] = parentName;
                                }
                            }

                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                details["process_query_error"] = ex.Message;
            }

            return details;
        }

        private static void AddManagementValue(IDictionary<string, string> details, ManagementBaseObject obj, string sourceName, string detailName)
        {
            object value = obj[sourceName];
            if (value != null)
            {
                details[detailName] = Convert.ToString(value, CultureInfo.InvariantCulture);
            }
        }

        private static string TryGetProcessName(int processId)
        {
            try
            {
                using (Process process = Process.GetProcessById(processId))
                {
                    return process.ProcessName;
                }
            }
            catch
            {
                return null;
            }
        }

        private static string GetDetail(IDictionary<string, string> details, string key)
        {
            string value;
            return details.TryGetValue(key, out value) ? value : null;
        }

        public void Dispose()
        {
            _disposed = true;

            if (_startWatcher != null)
            {
                try
                {
                    _startWatcher.Stop();
                }
                catch
                {
                }

                _startWatcher.Dispose();
                _startWatcher = null;
            }

            if (_stopWatcher != null)
            {
                try
                {
                    _stopWatcher.Stop();
                }
                catch
                {
                }

                _stopWatcher.Dispose();
                _stopWatcher = null;
            }
        }
    }
}
