using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal sealed class TrustedProcessAbuseMonitor : IDetectionMonitor
    {
        private static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(10);

        private static readonly HashSet<string> TrustedProcessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "discord.exe",
            "discordcanary.exe",
            "discordptb.exe",
            "steam.exe",
            "steamwebhelper.exe",
            "gameoverlayui.exe",
            "nvcontainer.exe",
            "nvidia share.exe",
            "nvidia overlay.exe",
            "obs64.exe",
            "obs32.exe",
            "chrome.exe",
            "msedge.exe",
            "firefox.exe",
            "brave.exe",
            "opera.exe",
            "browser.exe"
        };

        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly ManualResetEventSlim _stopSignal = new ManualResetEventSlim(false);
        private readonly ConcurrentQueue<TrustedSignal> _recentSignals = new ConcurrentQueue<TrustedSignal>();
        private readonly ConcurrentDictionary<string, SignatureVerificationResult> _signatureCache = new ConcurrentDictionary<string, SignatureVerificationResult>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, TrustedCase> _cases = new ConcurrentDictionary<string, TrustedCase>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _reportedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly object _writeLock = new object();
        private readonly DevicePathResolver _pathResolver = new DevicePathResolver();
        private readonly string _caseRoot;
        private Thread _thread;
        private bool _disposed;

        public TrustedProcessAbuseMonitor(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _caseRoot = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Trusted Process Abuse Cases");
        }

        public string Name
        {
            get { return "Trusted Process Abuse"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_caseRoot);
            _logger.EventLogged += OnEventLogged;

            _thread = new Thread(ThreadMain)
            {
                IsBackground = true,
                Name = "Aegis Trusted Process Abuse Monitor"
            };
            _thread.Start();

            _logger.Log(DetectionEvent.Create(
                "TrustedProcessAbuse",
                "Started",
                EventSeverity.Low,
                "Trusted process abuse monitor started in evidence-only mode.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "trusted_processes", string.Join(";", TrustedProcessNames.OrderBy(n => n).ToArray()) },
                    { "scan_interval_seconds", TrustedScanInterval().TotalSeconds.ToString("0", CultureInfo.InvariantCulture) },
                    { "case_root", _caseRoot },
                    { "safety_rule", "Evidence-only monitoring; no injection, blocking, patching, or process interference." }
                }));
        }

        private void ThreadMain()
        {
            while (!_stopSignal.Wait(TrustedScanInterval()))
            {
                try
                {
                    ScanTrustedProcesses();
                }
                catch (Exception ex)
                {
                    _logger.LogException("TrustedProcessAbuse", "ScanFailed", ex, null);
                }

                CleanupRecentSignals();
            }
        }

        private TimeSpan TrustedScanInterval()
        {
            TimeSpan interval = _options.TargetInteractionScanInterval;
            if (interval < TimeSpan.FromSeconds(5))
            {
                interval = TimeSpan.FromSeconds(5);
            }

            return interval;
        }

        private void ScanTrustedProcesses()
        {
            foreach (Process process in Process.GetProcesses())
            {
                ProcessIdentity identity = null;
                try
                {
                    identity = BuildProcessIdentity(process);
                    if (identity == null || !IsTrustedApplication(identity.ProcessName, identity.Path, identity.CommandLine))
                    {
                        continue;
                    }

                    ScanTrustedProcessMemory(identity);
                }
                catch
                {
                }
                finally
                {
                    process.Dispose();
                }
            }
        }

        private ProcessIdentity BuildProcessIdentity(Process process)
        {
            int processId = process.Id;
            string processName = SafeProcessName(process);
            ProcessIdentity identity = QueryProcessIdentity(processId);
            if (string.IsNullOrWhiteSpace(identity.ProcessName))
            {
                identity.ProcessName = processName;
            }

            if (string.IsNullOrWhiteSpace(identity.Path))
            {
                identity.Path = SafeMainModulePath(process);
            }

            return identity;
        }

        private void ScanTrustedProcessMemory(ProcessIdentity identity)
        {
            IntPtr processHandle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION | NativeMethods.PROCESS_VM_READ,
                false,
                identity.ProcessId);

            if (processHandle == IntPtr.Zero)
            {
                return;
            }

            try
            {
                List<MemoryRegion> mappedRegions = new List<MemoryRegion>();
                HashSet<string> modulePaths = GetProcessModulePaths(identity.ProcessId);
                ulong address = 0;
                int mbiSize = Marshal.SizeOf(typeof(NativeMethods.MEMORY_BASIC_INFORMATION));

                while (true)
                {
                    NativeMethods.MEMORY_BASIC_INFORMATION info;
                    UIntPtr result = NativeMethods.VirtualQueryEx(
                        processHandle,
                        new IntPtr(unchecked((long)address)),
                        out info,
                        new UIntPtr((uint)mbiSize));

                    if (result == UIntPtr.Zero)
                    {
                        break;
                    }

                    ulong baseAddress = unchecked((ulong)info.BaseAddress.ToInt64());
                    ulong regionSize = info.RegionSize.ToUInt64();
                    ulong nextAddress = baseAddress + regionSize;
                    if (regionSize == 0 || nextAddress <= address)
                    {
                        break;
                    }

                    if (info.State == NativeMethods.MEM_COMMIT)
                    {
                        bool executable = IsExecutableProtection(info.Protect);
                        bool rwx = IsRwxProtection(info.Protect);

                        if (info.Type == NativeMethods.MEM_PRIVATE && executable)
                        {
                            bool hasPeHeader = LooksLikePeHeader(processHandle, info.BaseAddress);
                            double entropy = CalculateEntropy(processHandle, info.BaseAddress, regionSize);
                            EmitTrustedMemoryAnomaly(identity, info, hasPeHeader, rwx, entropy);
                        }
                        else if (info.Type == NativeMethods.MEM_IMAGE || info.Type == NativeMethods.MEM_MAPPED)
                        {
                            string mappedPath = TryGetMappedPath(processHandle, info.BaseAddress);
                            if (!string.IsNullOrWhiteSpace(mappedPath))
                            {
                                MemoryRegion mapped = new MemoryRegion
                                {
                                    BaseAddress = baseAddress,
                                    Size = regionSize,
                                    Protection = info.Protect,
                                    Type = info.Type,
                                    Path = mappedPath
                                };
                                mappedRegions.Add(mapped);

                                EvaluateTrustedMappedImage(identity, mapped, modulePaths);
                            }
                        }
                    }

                    address = nextAddress;
                }

                ScanTrustedThreadStarts(identity, mappedRegions);
            }
            finally
            {
                NativeMethods.CloseHandle(processHandle);
            }
        }

        private void EmitTrustedMemoryAnomaly(ProcessIdentity identity, NativeMethods.MEMORY_BASIC_INFORMATION info, bool hasPeHeader, bool rwx, double entropy)
        {
            string action = hasPeHeader ? "TrustedProcessPrivatePeHeader" :
                rwx ? "TrustedProcessRwxMemory" : "TrustedProcessPrivateExecutableMemory";
            string key = action + "|" + identity.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" +
                         info.BaseAddress.ToInt64().ToString("X", CultureInfo.InvariantCulture);

            if (!RememberReportedKey(key))
            {
                return;
            }

            string caseId = GetOrCreateCase(identity.ProcessId, "memory");
            double confidence = 0.70;
            if (hasPeHeader) confidence += 0.12;
            if (rwx) confidence += 0.12;
            if (HasRecentSignal(identity.ProcessId, "kernel_comm") || HasRecentSignal(identity.ProcessId, "target_interaction")) confidence += 0.10;
            confidence = Math.Min(0.99, confidence);

            Dictionary<string, string> details = BuildTrustedBaseDetails(identity, caseId);
            details["base_address"] = "0x" + info.BaseAddress.ToInt64().ToString("X", CultureInfo.InvariantCulture);
            details["region_size"] = info.RegionSize.ToUInt64().ToString(CultureInfo.InvariantCulture);
            details["protection"] = "0x" + info.Protect.ToString("X", CultureInfo.InvariantCulture);
            details["memory_type"] = "MEM_PRIVATE";
            details["has_private_pe_header"] = hasPeHeader.ToString();
            details["is_rwx"] = rwx.ToString();
            details["entropy_sample"] = entropy.ToString("0.00", CultureInfo.InvariantCulture);
            details["confidence_score"] = confidence.ToString("0.00", CultureInfo.InvariantCulture);
            details["related_recent_evidence"] = SummarizeRecentSignals(identity.ProcessId);

            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                "TrustedProcessAbuse",
                action,
                confidence >= 0.90 ? EventSeverity.Critical : EventSeverity.High,
                "Trusted application has suspicious private executable memory: " + identity.ProcessName,
                identity.Path,
                identity.ProcessId,
                identity.ProcessName,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
            AddTrustedSignal(identity.ProcessId, identity.ProcessName, identity.Path, "memory", detectionEvent);
            TryEmitCorrelatedAbuse(identity.ProcessId, identity.ProcessName, identity.Path, caseId);
        }

        private void EvaluateTrustedMappedImage(ProcessIdentity identity, MemoryRegion mapped, ICollection<string> modulePaths)
        {
            string extension = Path.GetExtension(mapped.Path);
            if (!extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) &&
                !extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                !extension.Equals(".sys", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            SignatureVerificationResult signature = GetSignature(mapped.Path);
            bool suspiciousLocation = FileClassifier.IsLikelyDownloadLocation(mapped.Path) ||
                                      FileClassifier.IsUnder(mapped.Path, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)) ||
                                      FileClassifier.IsUnder(mapped.Path, Path.GetTempPath());
            bool untrusted = signature == null || !signature.IsTrusted;
            bool moduleListMismatch = mapped.Type == NativeMethods.MEM_IMAGE &&
                                      !modulePaths.Contains(NormalizePath(mapped.Path), StringComparer.OrdinalIgnoreCase);

            if (!untrusted && !suspiciousLocation && !moduleListMismatch)
            {
                return;
            }

            string action = moduleListMismatch ? "TrustedProcessMappedImageNotInModuleList" :
                untrusted ? "TrustedProcessUnsignedMappedImage" : "TrustedProcessSuspiciousMappedImageLocation";
            string key = action + "|" + identity.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + NormalizePath(mapped.Path);
            if (!RememberReportedKey(key))
            {
                return;
            }

            string caseId = GetOrCreateCase(identity.ProcessId, "mapped_image");
            double confidence = 0.55;
            if (untrusted) confidence += 0.18;
            if (suspiciousLocation) confidence += 0.14;
            if (moduleListMismatch) confidence += 0.18;
            if (HasRecentSignal(identity.ProcessId, "kernel_comm") || HasRecentSignal(identity.ProcessId, "target_interaction")) confidence += 0.10;
            confidence = Math.Min(0.99, confidence);

            Dictionary<string, string> details = BuildTrustedBaseDetails(identity, caseId);
            details["mapped_path"] = mapped.Path;
            details["mapped_base"] = "0x" + mapped.BaseAddress.ToString("X", CultureInfo.InvariantCulture);
            details["mapped_size"] = mapped.Size.ToString(CultureInfo.InvariantCulture);
            details["protection"] = "0x" + mapped.Protection.ToString("X", CultureInfo.InvariantCulture);
            details["mapping_type"] = mapped.Type == NativeMethods.MEM_IMAGE ? "MEM_IMAGE" : "MEM_MAPPED";
            details["signature_status"] = signature == null ? string.Empty : signature.Status ?? string.Empty;
            details["signature_subject"] = signature == null ? string.Empty : signature.Subject ?? string.Empty;
            details["suspicious_location"] = suspiciousLocation.ToString();
            details["module_list_mismatch"] = moduleListMismatch.ToString();
            details["sha256"] = TryHashFile(mapped.Path) ?? string.Empty;
            details["confidence_score"] = confidence.ToString("0.00", CultureInfo.InvariantCulture);
            details["related_recent_evidence"] = SummarizeRecentSignals(identity.ProcessId);

            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                "TrustedProcessAbuse",
                action,
                confidence >= 0.85 ? EventSeverity.Critical : EventSeverity.High,
                "Trusted application loaded suspicious mapped image: " + mapped.Path,
                mapped.Path,
                identity.ProcessId,
                identity.ProcessName,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
            AddTrustedSignal(identity.ProcessId, identity.ProcessName, identity.Path, untrusted ? "unsigned_module" : "mapped_image", detectionEvent);
            TryEmitCorrelatedAbuse(identity.ProcessId, identity.ProcessName, identity.Path, caseId);
        }

        private void ScanTrustedThreadStarts(ProcessIdentity identity, ICollection<MemoryRegion> mappedRegions)
        {
            if (!HasRecentSignal(identity.ProcessId, "memory"))
            {
                return;
            }

            Process process;
            try
            {
                process = Process.GetProcessById(identity.ProcessId);
            }
            catch
            {
                return;
            }

            using (process)
            {
                foreach (ProcessThread thread in process.Threads)
                {
                    try
                    {
                        IntPtr startAddress;
                        if (!TryQueryThreadStartAddress(thread.Id, out startAddress) || startAddress == IntPtr.Zero)
                        {
                            continue;
                        }

                        ulong start = unchecked((ulong)startAddress.ToInt64());
                        bool insideKnownRegion = mappedRegions.Any(r => start >= r.BaseAddress && start < r.BaseAddress + r.Size);
                        if (insideKnownRegion)
                        {
                            continue;
                        }

                        string key = "TrustedThreadStartOutsideModule|" + identity.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" +
                                     thread.Id.ToString(CultureInfo.InvariantCulture) + "|" + start.ToString("X", CultureInfo.InvariantCulture);
                        if (!RememberReportedKey(key))
                        {
                            continue;
                        }

                        string caseId = GetOrCreateCase(identity.ProcessId, "thread_start");
                        Dictionary<string, string> details = BuildTrustedBaseDetails(identity, caseId);
                        details["thread_id"] = thread.Id.ToString(CultureInfo.InvariantCulture);
                        details["thread_start_address"] = "0x" + start.ToString("X", CultureInfo.InvariantCulture);
                        details["confidence_score"] = "0.72";
                        details["related_recent_evidence"] = SummarizeRecentSignals(identity.ProcessId);

                        DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                            "TrustedProcessAbuse",
                            "TrustedProcessThreadStartOutsideModule",
                            EventSeverity.High,
                            "Trusted application thread starts outside known mapped module ranges.",
                            identity.Path,
                            identity.ProcessId,
                            identity.ProcessName,
                            details);

                        _logger.Log(detectionEvent);
                        AppendCaseEvent(caseId, detectionEvent);
                        AddTrustedSignal(identity.ProcessId, identity.ProcessName, identity.Path, "memory", detectionEvent);
                        TryEmitCorrelatedAbuse(identity.ProcessId, identity.ProcessName, identity.Path, caseId);
                    }
                    catch
                    {
                    }
                }
            }
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed ||
                detectionEvent == null ||
                detectionEvent.Category.StartsWith("TrustedProcessAbuse", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            TrustedEventContext context = TryBuildTrustedContext(detectionEvent);
            if (context != null)
            {
                EvaluateExternalTrustedSignal(detectionEvent, context);
            }

            if (IsRelatedSignal(detectionEvent))
            {
                TrustedSignal signal = new TrustedSignal
                {
                    TimestampUtc = detectionEvent.TimestampUtc.UtcDateTime,
                    ProcessId = context == null ? detectionEvent.ProcessId.GetValueOrDefault(0) : context.ProcessId,
                    ProcessName = context == null ? detectionEvent.ProcessName : context.ProcessName,
                    Path = context == null ? detectionEvent.Path : context.Path,
                    SignalType = ClassifySignalType(detectionEvent),
                    Category = detectionEvent.Category,
                    Action = detectionEvent.Action,
                    Summary = detectionEvent.Category + "/" + detectionEvent.Action + " " + detectionEvent.Description
                };
                _recentSignals.Enqueue(signal);
            }

            CleanupRecentSignals();
        }

        private void EvaluateExternalTrustedSignal(DetectionEvent detectionEvent, TrustedEventContext context)
        {
            string signalType = ClassifySignalType(detectionEvent);
            if (signalType.Equals("other", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            bool shouldEmit =
                signalType.Equals("kernel_comm", StringComparison.OrdinalIgnoreCase) ||
                signalType.Equals("target_interaction", StringComparison.OrdinalIgnoreCase) ||
                signalType.Equals("unsigned_module", StringComparison.OrdinalIgnoreCase) ||
                signalType.Equals("memory", StringComparison.OrdinalIgnoreCase);

            if (!shouldEmit)
            {
                return;
            }

            string key = "external|" + signalType + "|" + context.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" +
                         detectionEvent.Category + "|" + detectionEvent.Action + "|" + (detectionEvent.Path ?? string.Empty);
            if (!RememberReportedKey(key))
            {
                return;
            }

            string caseId = GetOrCreateCase(context.ProcessId, signalType);
            double confidence = ScoreExternalSignal(detectionEvent, signalType);
            Dictionary<string, string> details = BuildExternalDetails(context, caseId, detectionEvent, confidence);
            string action = signalType.Equals("kernel_comm", StringComparison.OrdinalIgnoreCase) ? "TrustedProcessKernelChannel" :
                signalType.Equals("target_interaction", StringComparison.OrdinalIgnoreCase) ? "TrustedProcessTargetInteraction" :
                signalType.Equals("unsigned_module", StringComparison.OrdinalIgnoreCase) ? "TrustedProcessUnsignedModuleSignal" :
                "TrustedProcessMemorySignal";

            DetectionEvent correlated = DetectionEvent.CreateForProcess(
                "TrustedProcessAbuse",
                action,
                confidence >= 0.85 ? EventSeverity.Critical : EventSeverity.High,
                "Trusted application participated in suspicious activity: " + context.ProcessName,
                context.Path,
                context.ProcessId,
                context.ProcessName,
                details);

            _logger.Log(correlated);
            AppendCaseEvent(caseId, correlated);
            AddTrustedSignal(context.ProcessId, context.ProcessName, context.Path, signalType, correlated);
            TryEmitCorrelatedAbuse(context.ProcessId, context.ProcessName, context.Path, caseId);
        }

        private TrustedEventContext TryBuildTrustedContext(DetectionEvent detectionEvent)
        {
            string sourceName = FirstNonEmpty(
                Detail(detectionEvent, "source_process_name"),
                Detail(detectionEvent, "SourceImage"),
                Detail(detectionEvent, "Image"),
                Detail(detectionEvent, "process_name"),
                detectionEvent.ProcessName);
            string sourcePath = FirstNonEmpty(
                Detail(detectionEvent, "source_path"),
                Detail(detectionEvent, "SourceImage"),
                Detail(detectionEvent, "Image"),
                Detail(detectionEvent, "executable_path"),
                detectionEvent.Path);
            string commandLine = FirstNonEmpty(
                Detail(detectionEvent, "command_line"),
                Detail(detectionEvent, "CommandLine"),
                Detail(detectionEvent, "SourceCommandLine"));
            int sourcePid = FirstInt(
                Detail(detectionEvent, "source_process_id"),
                Detail(detectionEvent, "SourceProcessId"),
                Detail(detectionEvent, "ProcessId"),
                detectionEvent.ProcessId.HasValue ? detectionEvent.ProcessId.Value.ToString(CultureInfo.InvariantCulture) : null);

            if (IsTrustedApplication(sourceName, sourcePath, commandLine))
            {
                return new TrustedEventContext
                {
                    ProcessId = sourcePid,
                    ProcessName = NormalizeProcessName(sourceName),
                    Path = sourcePath,
                    CommandLine = commandLine,
                    Role = TrustedRole(sourceName, sourcePath, commandLine)
                };
            }

            if (detectionEvent.Category.Equals("Memory", StringComparison.OrdinalIgnoreCase) ||
                detectionEvent.Category.StartsWith("TargetInteraction", StringComparison.OrdinalIgnoreCase))
            {
                string eventName = FirstNonEmpty(detectionEvent.ProcessName, Detail(detectionEvent, "target_process_name"));
                string eventPath = FirstNonEmpty(detectionEvent.Path, Detail(detectionEvent, "target_path"));
                if (IsTrustedApplication(eventName, eventPath, commandLine))
                {
                    return new TrustedEventContext
                    {
                        ProcessId = detectionEvent.ProcessId.GetValueOrDefault(0),
                        ProcessName = NormalizeProcessName(eventName),
                        Path = eventPath,
                        CommandLine = commandLine,
                        Role = TrustedRole(eventName, eventPath, commandLine)
                    };
                }
            }

            return null;
        }

        private Dictionary<string, string> BuildTrustedBaseDetails(ProcessIdentity identity, string caseId)
        {
            SignatureVerificationResult signature = GetSignature(identity.Path);
            return new Dictionary<string, string>
            {
                { "case_id", caseId },
                { "evidence_folder_path", GetCaseFolder(caseId) },
                { "source_process_id", identity.ProcessId.ToString(CultureInfo.InvariantCulture) },
                { "source_process_name", identity.ProcessName ?? string.Empty },
                { "source_path", identity.Path ?? string.Empty },
                { "source_command_line", identity.CommandLine ?? string.Empty },
                { "source_sha256", TryHashFile(identity.Path) ?? string.Empty },
                { "source_signature_status", signature == null ? string.Empty : signature.Status ?? string.Empty },
                { "source_signature_subject", signature == null ? string.Empty : signature.Subject ?? string.Empty },
                { "trusted_application_role", TrustedRole(identity.ProcessName, identity.Path, identity.CommandLine) },
                { "visibility", "User-mode memory/module/thread inspection of trusted applications; evidence only." }
            };
        }

        private Dictionary<string, string> BuildExternalDetails(TrustedEventContext context, string caseId, DetectionEvent sourceEvent, double confidence)
        {
            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "case_id", caseId },
                { "evidence_folder_path", GetCaseFolder(caseId) },
                { "source_process_id", context.ProcessId.ToString(CultureInfo.InvariantCulture) },
                { "source_process_name", context.ProcessName ?? string.Empty },
                { "source_path", context.Path ?? string.Empty },
                { "source_command_line", context.CommandLine ?? string.Empty },
                { "trusted_application_role", context.Role ?? string.Empty },
                { "source_event_category", sourceEvent.Category ?? string.Empty },
                { "source_event_action", sourceEvent.Action ?? string.Empty },
                { "source_event_description", sourceEvent.Description ?? string.Empty },
                { "source_event_path", sourceEvent.Path ?? string.Empty },
                { "confidence_score", confidence.ToString("0.00", CultureInfo.InvariantCulture) },
                { "related_recent_evidence", SummarizeRecentSignals(context.ProcessId) },
                { "visibility", "Correlation event only; no process modification or handle action was performed." }
            };

            foreach (KeyValuePair<string, string> pair in sourceEvent.Details)
            {
                if (!details.ContainsKey(pair.Key))
                {
                    details["linked_" + pair.Key] = pair.Value;
                }
            }

            return details;
        }

        private void TryEmitCorrelatedAbuse(int processId, string processName, string path, string caseId)
        {
            if (processId <= 0)
            {
                return;
            }

            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            List<TrustedSignal> signals = _recentSignals
                .Where(s => s.TimestampUtc >= cutoff && s.ProcessId == processId)
                .OrderBy(s => s.TimestampUtc)
                .ToList();

            HashSet<string> types = new HashSet<string>(signals.Select(s => s.SignalType), StringComparer.OrdinalIgnoreCase);
            bool strong =
                (types.Contains("memory") && (types.Contains("kernel_comm") || types.Contains("target_interaction"))) ||
                (types.Contains("unsigned_module") && (types.Contains("target_interaction") || types.Contains("kernel_comm"))) ||
                (types.Contains("kernel_comm") && types.Contains("target_interaction"));

            if (!strong)
            {
                return;
            }

            string typeKey = string.Join(",", types.OrderBy(t => t).ToArray());
            string key = "correlated|" + processId.ToString(CultureInfo.InvariantCulture) + "|" + typeKey;
            if (!RememberReportedKey(key))
            {
                return;
            }

            double confidence = 0.72 + Math.Min(0.20, types.Count * 0.05);
            if (types.Contains("memory")) confidence += 0.05;
            if (types.Contains("target_interaction")) confidence += 0.05;
            confidence = Math.Min(0.99, confidence);

            Dictionary<string, string> details = new Dictionary<string, string>
            {
                { "case_id", caseId },
                { "evidence_folder_path", GetCaseFolder(caseId) },
                { "source_process_id", processId.ToString(CultureInfo.InvariantCulture) },
                { "source_process_name", processName ?? string.Empty },
                { "source_path", path ?? string.Empty },
                { "trusted_application_role", TrustedRole(processName, path, null) },
                { "signal_types", typeKey },
                { "timeline_summary", string.Join(" || ", signals.Select(s => s.Summary).Take(18).ToArray()) },
                { "confidence_score", confidence.ToString("0.00", CultureInfo.InvariantCulture) },
                { "case_summary", BuildNarrative(processName, types) },
                { "safety_rule", "Trusted-process abuse correlation is evidence-only." }
            };

            DetectionEvent detectionEvent = DetectionEvent.CreateForProcess(
                "TrustedProcessAbuse",
                "TrustedProcessAbuseCorrelated",
                confidence >= 0.90 ? EventSeverity.Critical : EventSeverity.High,
                "Trusted-process abuse chain correlated for " + processName + ".",
                path,
                processId,
                processName,
                details);

            _logger.Log(detectionEvent);
            AppendCaseEvent(caseId, detectionEvent);
        }

        private static string BuildNarrative(string processName, ISet<string> types)
        {
            List<string> parts = new List<string>();
            parts.Add((string.IsNullOrWhiteSpace(processName) ? "A trusted application" : processName) + " showed trusted-process abuse indicators");
            if (types.Contains("unsigned_module")) parts.Add("loaded an unsigned or suspicious module");
            if (types.Contains("memory")) parts.Add("developed suspicious executable memory");
            if (types.Contains("kernel_comm")) parts.Add("used a device/shared-memory/named-pipe communication surface");
            if (types.Contains("target_interaction")) parts.Add("interacted with a protected game process");
            return string.Join(", then ", parts.ToArray()) + ".";
        }

        private void AddTrustedSignal(int processId, string processName, string path, string signalType, DetectionEvent detectionEvent)
        {
            _recentSignals.Enqueue(new TrustedSignal
            {
                TimestampUtc = detectionEvent.TimestampUtc.UtcDateTime,
                ProcessId = processId,
                ProcessName = processName,
                Path = path,
                SignalType = signalType,
                Category = detectionEvent.Category,
                Action = detectionEvent.Action,
                Summary = detectionEvent.Category + "/" + detectionEvent.Action + " " + detectionEvent.Description
            });
        }

        private static string ClassifySignalType(DetectionEvent detectionEvent)
        {
            string text = (detectionEvent.Category + " " + detectionEvent.Action + " " + detectionEvent.Description + " " +
                           detectionEvent.Path + " " + Detail(detectionEvent, "decoded_access") + " " +
                           Detail(detectionEvent, "object_type") + " " + Detail(detectionEvent, "object_name")).ToLowerInvariant();

            if (ContainsAny(text, "kernelcomm", "\\device\\", "section", "namedpipe", "alpc", "communicationchain"))
            {
                return "kernel_comm";
            }

            if (ContainsAny(text, "targetinteraction", "protected target", "process_vm_write", "process_vm_operation", "process_create_thread", "processopenedprotectedtarget", "suspicioustargethandle"))
            {
                return "target_interaction";
            }

            if (ContainsAny(text, "privateexecutable", "rwx", "privatepeheader", "threadstartoutside", "mappedimagenotinmodulelist"))
            {
                return "memory";
            }

            if (ContainsAny(text, "unsignedmappeddll", "unsignedmapped", "untrustedorinvalid", "unsignedorcatalogonlyuntrusted"))
            {
                return "unsigned_module";
            }

            return "other";
        }

        private static bool IsRelatedSignal(DetectionEvent detectionEvent)
        {
            if (detectionEvent.Severity >= EventSeverity.High)
            {
                return true;
            }

            string text = (detectionEvent.Category + " " + detectionEvent.Action + " " + detectionEvent.Description + " " + detectionEvent.Path).ToLowerInvariant();
            return ContainsAny(text, "kernelcomm", "targetinteraction", "privateexecutable", "rwx", "unsigned", "device", "section", "driver", ".sys", "hwid", "spoof");
        }

        private bool HasRecentSignal(int processId, string signalType)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            return _recentSignals.Any(s => s.TimestampUtc >= cutoff &&
                                           s.ProcessId == processId &&
                                           s.SignalType.Equals(signalType, StringComparison.OrdinalIgnoreCase));
        }

        private string SummarizeRecentSignals(int processId)
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            return string.Join(" || ", _recentSignals
                .Where(s => s.TimestampUtc >= cutoff && (processId <= 0 || s.ProcessId == processId || s.ProcessId == 0))
                .Select(s => s.Summary)
                .Take(16)
                .ToArray());
        }

        private void CleanupRecentSignals()
        {
            DateTime cutoff = DateTime.UtcNow.Subtract(CorrelationWindow);
            while (_recentSignals.TryPeek(out TrustedSignal signal) && signal.TimestampUtc < cutoff)
            {
                TrustedSignal ignored;
                _recentSignals.TryDequeue(out ignored);
            }
        }

        private bool RememberReportedKey(string key)
        {
            lock (_reportedKeys)
            {
                return _reportedKeys.Add(key);
            }
        }

        private string GetOrCreateCase(int processId, string reason)
        {
            string key = processId.ToString(CultureInfo.InvariantCulture);
            TrustedCase existing;
            if (_cases.TryGetValue(key, out existing) && DateTime.UtcNow.Subtract(existing.LastUpdatedUtc) <= CorrelationWindow)
            {
                existing.LastUpdatedUtc = DateTime.UtcNow;
                return existing.CaseId;
            }

            string caseId = "TPA-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            TrustedCase created = new TrustedCase
            {
                CaseId = caseId,
                ProcessId = processId,
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
                string path = Path.Combine(folder, "trusted-process-abuse.jsonl");
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

        private static bool IsTrustedApplication(string processNameOrPath, string path, string commandLine)
        {
            string normalizedName = NormalizeProcessName(processNameOrPath);
            if (TrustedProcessNames.Contains(normalizedName))
            {
                return true;
            }

            string fileName = NormalizeProcessName(path);
            if (TrustedProcessNames.Contains(fileName))
            {
                return true;
            }

            string text = (processNameOrPath + " " + path + " " + commandLine).ToLowerInvariant();
            return ContainsAny(text, "discord", "steamwebhelper", "gameoverlayui", "nvcontainer", "nvidia share", "obs64", "obs32") ||
                   (ContainsAny(text, "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe") && ContainsAny(text, "--type=gpu-process", "--type=renderer", "gpu-process"));
        }

        private static string TrustedRole(string processName, string path, string commandLine)
        {
            string text = (processName + " " + path + " " + commandLine).ToLowerInvariant();
            if (text.IndexOf("discord", StringComparison.OrdinalIgnoreCase) >= 0) return "chat_overlay";
            if (text.IndexOf("steam", StringComparison.OrdinalIgnoreCase) >= 0 || text.IndexOf("gameoverlayui", StringComparison.OrdinalIgnoreCase) >= 0) return "game_platform_overlay";
            if (text.IndexOf("nvidia", StringComparison.OrdinalIgnoreCase) >= 0 || text.IndexOf("nvcontainer", StringComparison.OrdinalIgnoreCase) >= 0) return "gpu_overlay";
            if (text.IndexOf("obs", StringComparison.OrdinalIgnoreCase) >= 0) return "capture_overlay";
            if (ContainsAny(text, "chrome", "edge", "msedge", "firefox", "brave", "gpu-process")) return "browser_or_gpu_process";
            return "trusted_application";
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

        private static ProcessIdentity QueryProcessIdentity(int processId)
        {
            ProcessIdentity identity = new ProcessIdentity { ProcessId = processId };
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
                            identity.ProcessName = Convert.ToString(process["Name"], CultureInfo.InvariantCulture);
                            identity.Path = Convert.ToString(process["ExecutablePath"], CultureInfo.InvariantCulture);
                            identity.CommandLine = Convert.ToString(process["CommandLine"], CultureInfo.InvariantCulture);
                            object parent = process["ParentProcessId"];
                            if (parent != null)
                            {
                                int parentId;
                                if (int.TryParse(Convert.ToString(parent, CultureInfo.InvariantCulture), NumberStyles.Integer, CultureInfo.InvariantCulture, out parentId))
                                {
                                    identity.ParentProcessId = parentId;
                                }
                            }
                            break;
                        }
                    }
                }
            }
            catch
            {
            }

            return identity;
        }

        private HashSet<string> GetProcessModulePaths(int processId)
        {
            HashSet<string> modules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (Process process = Process.GetProcessById(processId))
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        try
                        {
                            if (!string.IsNullOrWhiteSpace(module.FileName))
                            {
                                modules.Add(NormalizePath(module.FileName));
                            }
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch
            {
            }

            return modules;
        }

        private string TryGetMappedPath(IntPtr processHandle, IntPtr baseAddress)
        {
            try
            {
                StringBuilder builder = new StringBuilder(4096);
                int length = NativeMethods.GetMappedFileName(processHandle, baseAddress, builder, builder.Capacity);
                if (length <= 0)
                {
                    return null;
                }

                return _pathResolver.ToDosPath(builder.ToString());
            }
            catch
            {
                return null;
            }
        }

        private static bool IsExecutableProtection(uint protection)
        {
            uint normalized = protection & ~NativeMethods.PAGE_GUARD;
            return normalized == NativeMethods.PAGE_EXECUTE ||
                   normalized == NativeMethods.PAGE_EXECUTE_READ ||
                   normalized == NativeMethods.PAGE_EXECUTE_READWRITE ||
                   normalized == NativeMethods.PAGE_EXECUTE_WRITECOPY;
        }

        private static bool IsRwxProtection(uint protection)
        {
            uint normalized = protection & ~NativeMethods.PAGE_GUARD;
            return normalized == NativeMethods.PAGE_EXECUTE_READWRITE;
        }

        private static bool LooksLikePeHeader(IntPtr processHandle, IntPtr baseAddress)
        {
            byte[] buffer = new byte[2];
            IntPtr bytesRead;
            if (!NativeMethods.ReadProcessMemory(processHandle, baseAddress, buffer, buffer.Length, out bytesRead))
            {
                return false;
            }

            return bytesRead.ToInt64() == buffer.Length && buffer[0] == 0x4D && buffer[1] == 0x5A;
        }

        private static double CalculateEntropy(IntPtr processHandle, IntPtr baseAddress, ulong regionSize)
        {
            int sampleSize = (int)Math.Min(4096UL, regionSize);
            if (sampleSize <= 0)
            {
                return 0;
            }

            byte[] buffer = new byte[sampleSize];
            IntPtr bytesRead;
            if (!NativeMethods.ReadProcessMemory(processHandle, baseAddress, buffer, buffer.Length, out bytesRead))
            {
                return 0;
            }

            int count = (int)Math.Min(buffer.Length, bytesRead.ToInt64());
            if (count <= 0)
            {
                return 0;
            }

            int[] buckets = new int[256];
            for (int i = 0; i < count; i++)
            {
                buckets[buffer[i]]++;
            }

            double entropy = 0;
            for (int i = 0; i < buckets.Length; i++)
            {
                if (buckets[i] == 0)
                {
                    continue;
                }

                double p = buckets[i] / (double)count;
                entropy -= p * (Math.Log(p) / Math.Log(2));
            }

            return entropy;
        }

        private static bool TryQueryThreadStartAddress(int threadId, out IntPtr startAddress)
        {
            startAddress = IntPtr.Zero;
            IntPtr threadHandle = NativeMethods.OpenThread(
                NativeMethods.THREAD_QUERY_INFORMATION | NativeMethods.THREAD_QUERY_LIMITED_INFORMATION,
                false,
                threadId);

            if (threadHandle == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                int status = NativeMethods.NtQueryInformationThread(threadHandle, 9, out startAddress, IntPtr.Size, IntPtr.Zero);
                return status == 0;
            }
            finally
            {
                NativeMethods.CloseHandle(threadHandle);
            }
        }

        private SignatureVerificationResult GetSignature(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return new SignatureVerificationResult { Status = "Missing", WinVerifyTrustStatus = -1 };
            }

            return _signatureCache.GetOrAdd(path, AuthenticodeVerifier.VerifyFile);
        }

        private static string TryHashFile(string path)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    return null;
                }

                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(stream);
                    StringBuilder builder = new StringBuilder(hash.Length * 2);
                    foreach (byte b in hash)
                    {
                        builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                    }

                    return builder.ToString();
                }
            }
            catch
            {
                return null;
            }
        }

        private static string SafeProcessName(Process process)
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

        private static string SafeMainModulePath(Process process)
        {
            try
            {
                return process.MainModule == null ? null : process.MainModule.FileName;
            }
            catch
            {
                return null;
            }
        }

        private static string NormalizePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return string.Empty;
            }

            try
            {
                return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            }
            catch
            {
                return path.Trim();
            }
        }

        private static double ScoreExternalSignal(DetectionEvent detectionEvent, string signalType)
        {
            double score = 0.58;
            if (signalType.Equals("target_interaction", StringComparison.OrdinalIgnoreCase)) score += 0.15;
            if (signalType.Equals("kernel_comm", StringComparison.OrdinalIgnoreCase)) score += 0.12;
            if (signalType.Equals("memory", StringComparison.OrdinalIgnoreCase)) score += 0.14;
            if (signalType.Equals("unsigned_module", StringComparison.OrdinalIgnoreCase)) score += 0.12;
            if (detectionEvent.Severity >= EventSeverity.High) score += 0.08;
            if (detectionEvent.Severity >= EventSeverity.Critical) score += 0.08;
            return Math.Min(0.99, score);
        }

        private static string Detail(DetectionEvent detectionEvent, string key)
        {
            if (detectionEvent == null || detectionEvent.Details == null || string.IsNullOrWhiteSpace(key))
            {
                return string.Empty;
            }

            string value;
            return detectionEvent.Details.TryGetValue(key, out value) ? value : string.Empty;
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

        public void Dispose()
        {
            _disposed = true;
            _logger.EventLogged -= OnEventLogged;
            _stopSignal.Set();
            if (_thread != null && _thread.IsAlive)
            {
                _thread.Join(TimeSpan.FromSeconds(2));
            }

            _stopSignal.Dispose();
        }

        private sealed class ProcessIdentity
        {
            public int ProcessId;
            public string ProcessName;
            public string Path;
            public string CommandLine;
            public int ParentProcessId;
        }

        private sealed class MemoryRegion
        {
            public ulong BaseAddress;
            public ulong Size;
            public uint Protection;
            public uint Type;
            public string Path;
        }

        private sealed class TrustedSignal
        {
            public DateTime TimestampUtc;
            public int ProcessId;
            public string ProcessName;
            public string Path;
            public string SignalType;
            public string Category;
            public string Action;
            public string Summary;
        }

        private sealed class TrustedEventContext
        {
            public int ProcessId;
            public string ProcessName;
            public string Path;
            public string CommandLine;
            public string Role;
        }

        private sealed class TrustedCase
        {
            public string CaseId;
            public int ProcessId;
            public DateTime CreatedUtc;
            public DateTime LastUpdatedUtc;
            public string Reason;
        }
    }
}
