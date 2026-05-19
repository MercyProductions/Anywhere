using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal sealed class NativeAbuseMonitor : IDetectionMonitor
    {
        private static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(15);

        private static readonly HashSet<string> NativeToolNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "mshta.exe",
            "wscript.exe",
            "cscript.exe",
            "installutil.exe",
            "schtasks.exe",
            "sc.exe",
            "reg.exe",
            "pnputil.exe",
            "fltmc.exe",
            "netsh.exe",
            "wevtutil.exe",
            "bcdedit.exe",
            "certutil.exe",
            "bitsadmin.exe",
            "wmic.exe",
            "msiexec.exe"
        };

        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly ConcurrentQueue<NativeSignal> _recentSignals = new ConcurrentQueue<NativeSignal>();
        private readonly ConcurrentDictionary<string, NativeCase> _cases = new ConcurrentDictionary<string, NativeCase>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _writeLock = new object();
        private readonly string _caseRoot;
        private bool _disposed;

        public NativeAbuseMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _caseRoot = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Native Abuse Cases");
        }

        public string Name
        {
            get { return "LOLBIN and Native Abuse"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_caseRoot);
            _logger.EventLogged += OnEventLogged;

            _logger.Log(DetectionEvent.Create(
                "NativeAbuse",
                "Started",
                EventSeverity.Low,
                "LOLBIN and native Windows abuse monitor started in evidence-only mode.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "native_tools", string.Join(";", NativeToolNames.OrderBy(n => n).ToArray()) },
                    { "correlation_window_minutes", CorrelationWindow.TotalMinutes.ToString("0", CultureInfo.InvariantCulture) },
                    { "case_root", _caseRoot },
                    { "safety_rule", "Detection and evidence correlation only; no blocking, bypassing, injection, or tampering." }
                }));
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed ||
                detectionEvent == null ||
                detectionEvent.Category.StartsWith("NativeAbuse", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            NativeSignal signal = NativeSignal.FromEvent(detectionEvent);
            if (IsRelevantSignal(signal))
            {
                _recentSignals.Enqueue(signal);
            }

            TryEvaluateLolbin(signal);
            TryEvaluatePowerShell(signal);
            TryEvaluateLocalController(signal);
            CleanupRecentSignals();
        }

        private void TryEvaluateLolbin(NativeSignal signal)
        {
            if (!IsProcessCreationSignal(signal))
            {
                return;
            }

            string toolName = NormalizeProcessName(FirstNonEmpty(signal.ProcessName, signal.FileName, signal.ImagePath));
            if (!NativeToolNames.Contains(toolName))
            {
                return;
            }

            List<string> indicators = BuildAbuseIndicators(toolName, signal.CommandLine, signal.ImagePath, signal.Text);
            if (indicators.Count == 0)
            {
                return;
            }

            double confidence = ScoreLolbin(signal, toolName, indicators);
            if (confidence < 0.45)
            {
                return;
            }

            string key = "lolbin|" + toolName + "|" + signal.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + ReputationStore.HashText(signal.CommandLine ?? signal.Text ?? string.Empty);
            if (!RememberReportedKey(key))
            {
                return;
            }

            string caseId = GetOrCreateCase(BuildCaseKey(signal, toolName), "LolbinExecution");
            Dictionary<string, string> details = BuildBaseDetails(signal, caseId);
            details["native_tool"] = toolName;
            details["abuse_indicators"] = string.Join(";", indicators.ToArray());
            details["confidence_score"] = confidence.ToString("0.00", CultureInfo.InvariantCulture);
            details["related_recent_evidence"] = SummarizeRecentSignals(signal.ProcessId);
            details["case_summary"] = BuildLolbinSummary(toolName, indicators, signal);

            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                "NativeAbuse",
                "SuspiciousLolbinExecution",
                confidence >= 0.85 ? EventSeverity.Critical : confidence >= 0.65 ? EventSeverity.High : EventSeverity.Medium,
                "Suspicious native Windows tool execution: " + toolName,
                signal.ImagePath,
                signal.ProcessId,
                toolName,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
            AddNativeSignal("lolbin", detectionEvent, signal.ProcessId, toolName, signal.ImagePath);
            TryEmitNativeChain(caseId, signal.ProcessId, toolName, signal.ImagePath);
        }

        private void TryEvaluatePowerShell(NativeSignal signal)
        {
            if (!signal.Category.Equals("EventLog.PowerShell", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            string script = FirstNonEmpty(signal.Detail("script_preview"), signal.Detail("ScriptBlockText"), signal.Detail("Payload"), signal.Text);
            List<string> indicators = BuildAbuseIndicators("powershell.exe", script, signal.ImagePath, script);
            if (indicators.Count == 0)
            {
                return;
            }

            double confidence = 0.55 + Math.Min(0.30, indicators.Count * 0.06);
            if (HasRecentTerm("driver") || HasRecentTerm("targetinteraction") || HasRecentTerm("hwid")) confidence += 0.10;
            confidence = Math.Min(0.99, confidence);

            string key = "powershell|" + ReputationStore.HashText(script ?? string.Empty);
            if (!RememberReportedKey(key))
            {
                return;
            }

            string caseId = GetOrCreateCase("powershell|" + ReputationStore.HashText(script ?? string.Empty).Substring(0, 12), "PowerShellActivity");
            Dictionary<string, string> details = BuildBaseDetails(signal, caseId);
            details["native_tool"] = "powershell.exe";
            details["script_preview"] = Truncate(script, 1200);
            details["abuse_indicators"] = string.Join(";", indicators.ToArray());
            details["confidence_score"] = confidence.ToString("0.00", CultureInfo.InvariantCulture);
            details["related_recent_evidence"] = SummarizeRecentSignals(0);

            DetectionEvent detectionEvent = DetectionEvent.Create(
                "NativeAbuse",
                "SuspiciousPowerShellActivity",
                confidence >= 0.85 ? EventSeverity.Critical : EventSeverity.High,
                "Suspicious PowerShell activity observed in event logs.",
                null,
                null,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
            AddNativeSignal("lolbin", detectionEvent, 0, "powershell.exe", null);
            TryEmitNativeChain(caseId, 0, "powershell.exe", null);
        }

        private void TryEvaluateLocalController(NativeSignal signal)
        {
            bool isNetworkSignal = signal.Category.Equals("EventLog.Sysmon", StringComparison.OrdinalIgnoreCase) &&
                                   signal.Action.Equals("NetworkConnection", StringComparison.OrdinalIgnoreCase);
            bool commandMentionsLocalController = ContainsAny(signal.CommandLine + " " + signal.Text,
                "127.0.0.1", "localhost", "::1", "ws://", "wss://", "websocket", "--port", "-port", "listen");

            if (!isNetworkSignal && !commandMentionsLocalController)
            {
                return;
            }

            string destination = FirstNonEmpty(signal.Detail("DestinationIp"), signal.Detail("DestinationHostname"), signal.Detail("DestinationPort"), signal.Text);
            bool loopback = ContainsAny(destination, "127.0.0.1", "localhost", "::1") || commandMentionsLocalController;
            if (!loopback)
            {
                return;
            }

            bool nearSuspicious = HasRecentTerm("kernelcomm") ||
                                  HasRecentTerm("targetinteraction") ||
                                  HasRecentTerm("transientdrivermapping") ||
                                  HasRecentTerm("hiddenkernel") ||
                                  HasRecentTerm("hwid") ||
                                  HasRecentTerm("driver") ||
                                  HasRecentTerm("trustedprocessabuse");

            bool suspiciousProcess = IsSuspiciousProcessName(signal.ProcessName, signal.ImagePath) ||
                                     NativeToolNames.Contains(NormalizeProcessName(signal.ProcessName)) ||
                                     NativeToolNames.Contains(NormalizeProcessName(signal.ImagePath));

            if (!nearSuspicious && !suspiciousProcess)
            {
                return;
            }

            string key = "localcontroller|" + signal.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" +
                         ReputationStore.HashText(destination + "|" + signal.CommandLine);
            if (!RememberReportedKey(key))
            {
                return;
            }

            string caseId = GetOrCreateCase(BuildCaseKey(signal, "local-controller"), "LocalController");
            double confidence = 0.58;
            if (nearSuspicious) confidence += 0.18;
            if (suspiciousProcess) confidence += 0.12;
            if (ContainsAny(signal.CommandLine + " " + signal.Text, "websocket", "ws://", "wss://")) confidence += 0.08;
            confidence = Math.Min(0.99, confidence);

            Dictionary<string, string> details = BuildBaseDetails(signal, caseId);
            details["controller_destination"] = destination;
            details["loopback_or_websocket"] = loopback.ToString();
            details["near_suspicious_activity"] = nearSuspicious.ToString();
            details["suspicious_process_context"] = suspiciousProcess.ToString();
            details["confidence_score"] = confidence.ToString("0.00", CultureInfo.InvariantCulture);
            details["related_recent_evidence"] = SummarizeRecentSignals(signal.ProcessId);

            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                "NativeAbuse",
                "LocalControllerChannelObserved",
                confidence >= 0.75 ? EventSeverity.High : EventSeverity.Medium,
                "Suspicious localhost/controller-style communication observed.",
                signal.ImagePath,
                signal.ProcessId,
                signal.ProcessName,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
            AddNativeSignal("local_controller", detectionEvent, signal.ProcessId, signal.ProcessName, signal.ImagePath);
            TryEmitNativeChain(caseId, signal.ProcessId, signal.ProcessName, signal.ImagePath);
        }

        private void TryEmitNativeChain(string caseId, int processId, string processName, string path)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            List<NativeSignal> signals = _recentSignals
                .Where(s => s.TimestampUtc >= cutoff &&
                            (processId <= 0 || s.ProcessId == processId || s.SignalType != null && !s.SignalType.Equals("other", StringComparison.OrdinalIgnoreCase)))
                .OrderBy(s => s.TimestampUtc)
                .ToList();

            HashSet<string> types = new HashSet<string>(signals.Select(s => s.SignalType), StringComparer.OrdinalIgnoreCase);
            bool strong = types.Contains("lolbin") &&
                          (types.Contains("driver") ||
                           types.Contains("target") ||
                           types.Contains("hardware_identity") ||
                           types.Contains("kernel_comm") ||
                           types.Contains("cleanup") ||
                           types.Contains("local_controller"));

            if (!strong && !(types.Contains("local_controller") && (types.Contains("target") || types.Contains("kernel_comm"))))
            {
                return;
            }

            string typeKey = string.Join(",", types.Where(t => !string.IsNullOrWhiteSpace(t)).OrderBy(t => t).ToArray());
            string key = "chain|" + caseId + "|" + typeKey;
            if (!RememberReportedKey(key))
            {
                return;
            }

            double confidence = 0.70 + Math.Min(0.22, types.Count * 0.035);
            if (types.Contains("driver") && types.Contains("target")) confidence += 0.06;
            if (types.Contains("cleanup")) confidence += 0.05;
            confidence = Math.Min(0.99, confidence);

            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "case_id", caseId },
                { "evidence_folder_path", GetCaseFolder(caseId) },
                { "source_process_id", processId.ToString(CultureInfo.InvariantCulture) },
                { "source_process_name", processName ?? string.Empty },
                { "source_path", path ?? string.Empty },
                { "signal_types", typeKey },
                { "timeline_summary", string.Join(" || ", signals.Select(s => s.Summary).Take(20).ToArray()) },
                { "confidence_score", confidence.ToString("0.00", CultureInfo.InvariantCulture) },
                { "case_summary", BuildNativeChainSummary(processName, types) },
                { "safety_rule", "Native abuse correlation is passive and evidence-only." }
            };

            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                "NativeAbuse",
                "NativeAbuseChainCorrelated",
                confidence >= 0.88 ? EventSeverity.Critical : EventSeverity.High,
                "Native Windows tool abuse chain correlated with suspicious case evidence.",
                path,
                processId,
                processName,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
        }

        private static List<string> BuildAbuseIndicators(string toolName, string commandLine, string imagePath, string text)
        {
            HashSet<string> indicators = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string combined = (toolName + " " + commandLine + " " + imagePath + " " + text).ToLowerInvariant();

            if (ContainsAny(combined, "-enc", "-encodedcommand", "frombase64string", "-nop", "bypass", "-w hidden", "windowstyle hidden"))
            {
                indicators.Add("encoded_or_hidden_script_execution");
            }

            if (ContainsAny(combined, "http://", "https://", "downloadstring", "invoke-webrequest", "iwr ", "curl ", "bitsadmin", "certutil -urlcache"))
            {
                indicators.Add("download_or_remote_script");
            }

            if (toolName.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase) && ContainsAny(combined, ".dll", "javascript:", "shell32", "url.dll"))
            {
                indicators.Add("rundll32_proxy_execution");
            }

            if (toolName.Equals("regsvr32.exe", StringComparison.OrdinalIgnoreCase) && ContainsAny(combined, "/i:", "scrobj.dll", "http://", "https://", ".sct"))
            {
                indicators.Add("regsvr32_scriptlet_or_remote_execution");
            }

            if (toolName.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase) && ContainsAny(combined, "http://", "https://", "javascript:", "vbscript:", ".hta"))
            {
                indicators.Add("mshta_script_execution");
            }

            if ((toolName.Equals("wscript.exe", StringComparison.OrdinalIgnoreCase) || toolName.Equals("cscript.exe", StringComparison.OrdinalIgnoreCase)) &&
                ContainsAny(combined, ".vbs", ".js", ".jse", ".wsf", "temp", "appdata", "downloads"))
            {
                indicators.Add("script_host_staging_execution");
            }

            if (toolName.Equals("installutil.exe", StringComparison.OrdinalIgnoreCase))
            {
                indicators.Add("installutil_proxy_execution");
            }

            if (toolName.Equals("sc.exe", StringComparison.OrdinalIgnoreCase) &&
                ContainsAny(combined, " create ", " delete ", " config ", " start ", " stop ", "type= kernel", ".sys"))
            {
                indicators.Add("service_or_driver_control");
            }

            if (toolName.Equals("schtasks.exe", StringComparison.OrdinalIgnoreCase) && ContainsAny(combined, "/create", "/delete", "/run", "/tn"))
            {
                indicators.Add("scheduled_task_control");
            }

            if (toolName.Equals("reg.exe", StringComparison.OrdinalIgnoreCase) &&
                ContainsAny(combined, " add ", " delete ", "machineguid", "networkaddress", "mounteddevices", "hardware profiles", "services\\", "class\\{4d36e972"))
            {
                indicators.Add("registry_identity_or_service_edit");
            }

            if ((toolName.Equals("pnputil.exe", StringComparison.OrdinalIgnoreCase) || toolName.Equals("fltmc.exe", StringComparison.OrdinalIgnoreCase)) &&
                ContainsAny(combined, ".sys", "add-driver", "/add-driver", "load", "unload"))
            {
                indicators.Add("driver_or_filter_control");
            }

            if (toolName.Equals("netsh.exe", StringComparison.OrdinalIgnoreCase) &&
                ContainsAny(combined, "interface", "set", "disable", "enable", "reset", "winsock"))
            {
                indicators.Add("network_adapter_or_stack_reset");
            }

            if (toolName.Equals("wevtutil.exe", StringComparison.OrdinalIgnoreCase) ||
                ContainsAny(combined, "clear-eventlog", "wevtutil cl", "auditpol", "set-mppreference", "add-mppreference", "powershelllogging", "sysmon"))
            {
                indicators.Add("telemetry_or_defender_tamper");
            }

            if (toolName.Equals("bcdedit.exe", StringComparison.OrdinalIgnoreCase) &&
                ContainsAny(combined, "testsigning", "nointegritychecks", "debug", "hypervisorlaunchtype"))
            {
                indicators.Add("boot_or_code_integrity_setting_change");
            }

            if (ContainsAny(combined, "del ", "erase ", "remove-item", "rd /s", "prefetch", "amcache", "shimcache", "recent\\", "$recycle.bin"))
            {
                indicators.Add("cleanup_or_trace_wipe");
            }

            if (ContainsAny(combined, ".sys", ".dll", "kdmapper", "iqvw", "gdrv", "capcom", "dbutil", "rtcore", "winio", "mhyprot"))
            {
                indicators.Add("driver_mapper_or_payload_reference");
            }

            return indicators.OrderBy(i => i).ToList();
        }

        private double ScoreLolbin(NativeSignal signal, string toolName, ICollection<string> indicators)
        {
            double score = 0.35 + Math.Min(0.32, indicators.Count * 0.07);
            if (ContainsAny(signal.ImagePath, "\\temp\\", "\\appdata\\", "\\downloads\\", "\\desktop\\")) score += 0.10;
            if (HasRecentTerm("targetinteraction") || HasRecentTerm("protected target")) score += 0.08;
            if (HasRecentTerm("transientdrivermapping") || HasRecentTerm("hiddenkernel") || HasRecentTerm("driver")) score += 0.10;
            if (HasRecentTerm("hardwareidentity") || HasRecentTerm("hwid") || HasRecentTerm("spoof")) score += 0.08;
            if (indicators.Contains("telemetry_or_defender_tamper")) score += 0.10;
            if (toolName.Equals("sc.exe", StringComparison.OrdinalIgnoreCase) && indicators.Contains("service_or_driver_control")) score += 0.10;
            return Math.Min(0.99, score);
        }

        private bool IsRelevantSignal(NativeSignal signal)
        {
            if (signal.Severity >= EventSeverity.High)
            {
                signal.SignalType = ClassifySignalType(signal);
                return true;
            }

            signal.SignalType = ClassifySignalType(signal);
            return !signal.SignalType.Equals("other", StringComparison.OrdinalIgnoreCase);
        }

        private static string ClassifySignalType(NativeSignal signal)
        {
            string text = signal.Text.ToLowerInvariant();
            if (ContainsAny(text, "nativeabuse", "powershell", "rundll32", "regsvr32", "mshta", "wscript", "cscript", "installutil", "schtasks", "sc.exe", "wevtutil"))
            {
                return "lolbin";
            }

            if (ContainsAny(text, "kernelcomm", "\\device\\", "section", "namedpipe", "alpc"))
            {
                return "kernel_comm";
            }

            if (ContainsAny(text, "targetinteraction", "protected target", "process_vm_write", "vm_operation", "create_thread"))
            {
                return "target";
            }

            if (ContainsAny(text, "transientdrivermapping", "hiddenkernel", ".sys", "driver", "vulnerable"))
            {
                return "driver";
            }

            if (ContainsAny(text, "hardwareidentity", "hwid", "smbios", "disk serial", "mac", "spoof"))
            {
                return "hardware_identity";
            }

            if (ContainsAny(text, "localhost", "127.0.0.1", "::1", "websocket", "localcontroller"))
            {
                return "local_controller";
            }

            if (ContainsAny(text, "cleanup", "deleted", "auditlogcleared", "wevtutil", "prefetch", "amcache", "shimcache"))
            {
                return "cleanup";
            }

            return "other";
        }

        private static bool IsProcessCreationSignal(NativeSignal signal)
        {
            return (signal.Category.Equals("Process", StringComparison.OrdinalIgnoreCase) && signal.Action.Equals("Executed", StringComparison.OrdinalIgnoreCase)) ||
                   (signal.Action.Equals("ProcessCreated", StringComparison.OrdinalIgnoreCase));
        }

        private bool HasRecentTerm(string term)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            return _recentSignals.Any(s => s.TimestampUtc >= cutoff && s.Text.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private string SummarizeRecentSignals(int processId)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            return string.Join(" || ", _recentSignals
                .Where(s => s.TimestampUtc >= cutoff && (processId <= 0 || s.ProcessId == processId || !s.SignalType.Equals("other", StringComparison.OrdinalIgnoreCase)))
                .Select(s => s.Summary)
                .Take(18)
                .ToArray());
        }

        private void AddNativeSignal(string signalType, DetectionEvent detectionEvent, int processId, string processName, string path)
        {
            _recentSignals.Enqueue(new NativeSignal
            {
                TimestampUtc = detectionEvent.TimestampUtc.UtcDateTime,
                Category = detectionEvent.Category,
                Action = detectionEvent.Action,
                Severity = detectionEvent.Severity,
                ProcessId = processId,
                ProcessName = processName,
                ImagePath = path,
                FileName = NormalizeProcessName(processName),
                SignalType = signalType,
                Summary = detectionEvent.Category + "/" + detectionEvent.Action + " " + detectionEvent.Description,
                Text = detectionEvent.Category + " " + detectionEvent.Action + " " + detectionEvent.Description + " " + path
            });
        }

        private void CleanupRecentSignals()
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            while (_recentSignals.TryPeek(out NativeSignal signal) && signal.TimestampUtc < cutoff)
            {
                NativeSignal ignored;
                _recentSignals.TryDequeue(out ignored);
            }
        }

        private string GetOrCreateCase(string key, string reason)
        {
            NativeCase existing;
            if (_cases.TryGetValue(key, out existing) && DateTime.UtcNow.Subtract(existing.LastUpdatedUtc) <= CorrelationWindow)
            {
                existing.LastUpdatedUtc = DateTime.UtcNow;
                return existing.CaseId;
            }

            string caseId = "NATIVE-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            NativeCase created = new NativeCase
            {
                CaseId = caseId,
                CreatedUtc = DateTime.UtcNow,
                LastUpdatedUtc = DateTime.UtcNow,
                Reason = reason
            };
            Directory.CreateDirectory(GetCaseFolder(caseId));
            _cases[key] = created;
            return caseId;
        }

        private string GetCaseFolder(string caseId)
        {
            return Path.Combine(_caseRoot, caseId);
        }

        private void AppendCaseEvent(string caseId, DetectionEvent detectionEvent)
        {
            try
            {
                string folder = GetCaseFolder(caseId);
                Directory.CreateDirectory(folder);
                string path = Path.Combine(folder, "native-abuse-case.jsonl");
                lock (_writeLock)
                {
                    File.AppendAllText(path, CaseEventToJson(detectionEvent) + Environment.NewLine, Encoding.UTF8);
                    CaseIntegrityManifestWriter.WriteManifest(folder);
                }
            }
            catch
            {
            }
        }

        private static string CaseEventToJson(DetectionEvent detectionEvent)
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

        private Dictionary<string, string> BuildBaseDetails(NativeSignal signal, string caseId)
        {
            return new Dictionary<string, string>
            {
                { "case_id", caseId },
                { "evidence_folder_path", GetCaseFolder(caseId) },
                { "source_event_category", signal.Category ?? string.Empty },
                { "source_event_action", signal.Action ?? string.Empty },
                { "source_process_id", signal.ProcessId.ToString(CultureInfo.InvariantCulture) },
                { "source_process_name", signal.ProcessName ?? string.Empty },
                { "source_path", signal.ImagePath ?? string.Empty },
                { "parent_process_id", signal.ParentProcessId.ToString(CultureInfo.InvariantCulture) },
                { "parent_process_name", signal.ParentProcessName ?? string.Empty },
                { "command_line", signal.CommandLine ?? string.Empty },
                { "event_path", signal.Path ?? string.Empty },
                { "event_text", Truncate(signal.Text, 2000) },
                { "visibility", "Event/log/process telemetry correlation only; no native tool was blocked or modified." }
            };
        }

        private static string BuildCaseKey(NativeSignal signal, string toolName)
        {
            string identity = FirstNonEmpty(signal.ImagePath, signal.ProcessName, toolName);
            return toolName + "|" + signal.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + ReputationStore.HashText(identity + "|" + signal.CommandLine).Substring(0, 16);
        }

        private static string BuildLolbinSummary(string toolName, ICollection<string> indicators, NativeSignal signal)
        {
            return toolName + " executed with " + string.Join(", ", indicators.Take(5).ToArray()) +
                   (string.IsNullOrWhiteSpace(signal.CommandLine) ? "." : ": " + Truncate(signal.CommandLine, 240));
        }

        private static string BuildNativeChainSummary(string processName, ISet<string> types)
        {
            List<string> parts = new List<string>();
            parts.Add(string.IsNullOrWhiteSpace(processName) ? "Native Windows tooling appeared" : processName + " appeared");
            if (types.Contains("driver")) parts.Add("driver or mapper evidence appeared nearby");
            if (types.Contains("hardware_identity")) parts.Add("hardware identity drift was observed");
            if (types.Contains("kernel_comm")) parts.Add("device or shared-memory communication was observed");
            if (types.Contains("target")) parts.Add("protected target interaction occurred");
            if (types.Contains("local_controller")) parts.Add("localhost/controller-style communication appeared");
            if (types.Contains("cleanup")) parts.Add("cleanup or trace-removal behavior followed");
            return string.Join(", then ", parts.ToArray()) + ".";
        }

        private bool RememberReportedKey(string key)
        {
            lock (_reportedKeys)
            {
                return _reportedKeys.Add(key);
            }
        }

        private static bool IsSuspiciousProcessName(string processName, string path)
        {
            string text = (processName + " " + path).ToLowerInvariant();
            return ContainsAny(text, "loader", "mapper", "inject", "spoofer", "hwid", "kdmapper", "iqvw", "gdrv", "capcom", "dbutil", "rtcore", "winio", "mhyprot") ||
                   ContainsAny(path, "\\temp\\", "\\appdata\\", "\\downloads\\", "\\desktop\\");
        }

        private static string NormalizeProcessName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return string.Empty;
            }

            string name = value;
            try
            {
                if (value.IndexOf(@"\", StringComparison.OrdinalIgnoreCase) >= 0 || value.IndexOf("/", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    name = Path.GetFileName(value);
                }
            }
            catch
            {
            }

            if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                name += ".exe";
            }

            return name.ToLowerInvariant();
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

        private static bool ContainsAny(string text, params string[] terms)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            foreach (string term in terms)
            {
                if (text.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string Truncate(string value, int max)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length <= max)
            {
                return value ?? string.Empty;
            }

            return value.Substring(0, max) + "...";
        }

        public void Dispose()
        {
            _disposed = true;
            _logger.EventLogged -= OnEventLogged;
        }

        private sealed class NativeCase
        {
            public string CaseId;
            public DateTime CreatedUtc;
            public DateTime LastUpdatedUtc;
            public string Reason;
        }

        private sealed class NativeSignal
        {
            public DateTime TimestampUtc;
            public string Category;
            public string Action;
            public EventSeverity Severity;
            public int ProcessId;
            public string ProcessName;
            public string FileName;
            public string ImagePath;
            public string CommandLine;
            public int ParentProcessId;
            public string ParentProcessName;
            public string Path;
            public string SignalType;
            public string Summary;
            public string Text;
            public Dictionary<string, string> Details;

            public string Detail(string key)
            {
                if (Details == null || string.IsNullOrWhiteSpace(key))
                {
                    return string.Empty;
                }

                string value;
                return Details.TryGetValue(key, out value) ? value : string.Empty;
            }

            public static NativeSignal FromEvent(DetectionEvent detectionEvent)
            {
                Dictionary<string, string> details = detectionEvent.Details == null
                    ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, string>(detectionEvent.Details, StringComparer.OrdinalIgnoreCase);

                string imagePath = FirstNonEmpty(
                    Value(details, "executable_path"),
                    Value(details, "Image"),
                    Value(details, "NewProcessName"),
                    Value(details, "SourceImage"),
                    Value(details, "source_path"),
                    detectionEvent.Path);
                string processName = FirstNonEmpty(
                    Value(details, "process_name"),
                    Value(details, "Name"),
                    System.IO.Path.GetFileName(imagePath),
                    detectionEvent.ProcessName);
                string commandLine = FirstNonEmpty(
                    Value(details, "command_line"),
                    Value(details, "CommandLine"),
                    Value(details, "ProcessCommandLine"),
                    Value(details, "SourceCommandLine"),
                    Value(details, "script_preview"));

                NativeSignal signal = new NativeSignal
                {
                    TimestampUtc = detectionEvent.TimestampUtc.UtcDateTime,
                    Category = detectionEvent.Category ?? string.Empty,
                    Action = detectionEvent.Action ?? string.Empty,
                    Severity = detectionEvent.Severity,
                    ProcessId = FirstInt(Value(details, "process_id"), Value(details, "ProcessId"), Value(details, "SourceProcessId"), detectionEvent.ProcessId.HasValue ? detectionEvent.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : null),
                    ProcessName = processName,
                    FileName = System.IO.Path.GetFileName(imagePath),
                    ImagePath = imagePath,
                    CommandLine = commandLine,
                    ParentProcessId = FirstInt(Value(details, "parent_process_id"), Value(details, "ParentProcessId")),
                    ParentProcessName = FirstNonEmpty(Value(details, "parent_process_name"), Value(details, "ParentImage")),
                    Path = detectionEvent.Path,
                    Summary = detectionEvent.Category + "/" + detectionEvent.Action + " " + detectionEvent.Description,
                    Details = details
                };

                signal.Text = string.Join(" ", new[]
                {
                    signal.Category,
                    signal.Action,
                    detectionEvent.Description ?? string.Empty,
                    signal.ProcessName ?? string.Empty,
                    signal.ImagePath ?? string.Empty,
                    signal.CommandLine ?? string.Empty,
                    detectionEvent.Path ?? string.Empty,
                    string.Join(" ", details.Select(p => p.Key + "=" + p.Value).ToArray())
                });
                signal.SignalType = "other";
                return signal;
            }

            private static string Value(IDictionary<string, string> details, string key)
            {
                string value;
                return details != null && details.TryGetValue(key, out value) ? value : string.Empty;
            }

            private static int FirstInt(params string[] values)
            {
                foreach (string value in values)
                {
                    int parsed;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed))
                    {
                        return parsed;
                    }
                }

                return 0;
            }
        }
    }
}
