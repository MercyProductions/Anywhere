using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal sealed class HardwareIdentityCrossValidator : IDetectionMonitor
    {
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly HardwareIdentityCollector _collector;
        private readonly HardwareIdentityBaselineStore _baselineStore;
        private readonly string _evidenceRoot;
        private readonly ManualResetEventSlim _stopSignal = new ManualResetEventSlim(false);
        private readonly ConcurrentQueue<string> _recentActivity = new ConcurrentQueue<string>();
        private readonly HashSet<int> _activeProtectedProcesses = new HashSet<int>();
        private readonly object _captureLock = new object();
        private Thread _thread;
        private bool _disposed;

        public HardwareIdentityCrossValidator(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _collector = new HardwareIdentityCollector(logger);
            _evidenceRoot = Path.Combine(Path.GetDirectoryName(logger.JsonLogPath), "Hardware Identity");
            _baselineStore = new HardwareIdentityBaselineStore(Path.Combine(_evidenceRoot, "hardware-identity-baseline.tsv"));
        }

        public string Name
        {
            get { return "Hardware Identity Cross-Validation"; }
        }

        public void Start()
        {
            Directory.CreateDirectory(_evidenceRoot);
            _logger.EventLogged += OnEventLogged;

            CaptureEvaluateAndReport("BootOrMonitorStart");

            _thread = new Thread(ThreadMain)
            {
                IsBackground = true,
                Name = "Aegis Hardware Identity Cross-Validator"
            };
            _thread.Start();

            _logger.Log(DetectionEvent.Create(
                "HardwareIdentity",
                "Started",
                EventSeverity.Low,
                "Hardware identity cross-validation started.",
                null,
                null,
                new Dictionary<string, string>
                {
                    { "identity_scan_interval_seconds", _options.IdentityScanInterval.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) },
                    { "baseline_path", Path.Combine(_evidenceRoot, "hardware-identity-baseline.tsv") },
                    { "protected_processes", string.Join(";", _options.ProtectedProcessNames.ToArray()) }
                }));
        }

        private void ThreadMain()
        {
            while (!_stopSignal.Wait(_options.IdentityScanInterval))
            {
                string stage = HasActiveProtectedProcess() ? "DuringProtectedGameRuntime" : "Periodic";
                CaptureEvaluateAndReport(stage);
            }
        }

        private void OnEventLogged(DetectionEvent detectionEvent)
        {
            if (_disposed || detectionEvent == null)
            {
                return;
            }

            if (!detectionEvent.Category.StartsWith("HardwareIdentity", StringComparison.OrdinalIgnoreCase))
            {
                RememberActivity(detectionEvent);
            }

            if (IsProtectedProcessEvent(detectionEvent))
            {
                if (IsProcessStartEvent(detectionEvent) && detectionEvent.ProcessId.HasValue)
                {
                    lock (_activeProtectedProcesses)
                    {
                        _activeProtectedProcesses.Add(detectionEvent.ProcessId.Value);
                    }

                    QueueCapture("ProtectedGameLaunchBoundary");
                }
                else if (IsProcessExitEvent(detectionEvent) && detectionEvent.ProcessId.HasValue)
                {
                    lock (_activeProtectedProcesses)
                    {
                        _activeProtectedProcesses.Remove(detectionEvent.ProcessId.Value);
                    }

                    QueueCapture("AfterProtectedGameExit");
                }
            }
        }

        private void QueueCapture(string stage)
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                Thread.Sleep(500);
                CaptureEvaluateAndReport(stage);
            });
        }

        private void CaptureEvaluateAndReport(string stage)
        {
            if (_disposed)
            {
                return;
            }

            lock (_captureLock)
            {
                HardwareIdentitySnapshot snapshot = _collector.Capture(stage);
                Dictionary<string, string> currentBaselineValues = FlattenSnapshot(snapshot);
                bool hadBaseline = _baselineStore.Exists;
                Dictionary<string, string> baseline = _baselineStore.Load();

                if (!hadBaseline)
                {
                    _baselineStore.Save(currentBaselineValues);
                    baseline = new Dictionary<string, string>(currentBaselineValues, StringComparer.OrdinalIgnoreCase);
                }

                List<HardwareIdentityFinding> findings = EvaluateSnapshot(snapshot, baseline, hadBaseline);
                string reportPath = WriteReport(snapshot, findings, hadBaseline);

                foreach (HardwareIdentityFinding finding in findings)
                {
                    Dictionary<string, string> details = new Dictionary<string, string>(finding.Details, StringComparer.OrdinalIgnoreCase)
                    {
                        { "identifier_type", finding.IdentifierType ?? string.Empty },
                        { "source_a", finding.SourceA ?? string.Empty },
                        { "source_a_value", finding.SourceAValue ?? string.Empty },
                        { "source_b", finding.SourceB ?? string.Empty },
                        { "source_b_value", finding.SourceBValue ?? string.Empty },
                        { "baseline_value", finding.BaselineValue ?? string.Empty },
                        { "current_value", finding.CurrentValue ?? string.Empty },
                        { "timestamp_utc", snapshot.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) },
                        { "stage", stage },
                        { "confidence_score", finding.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture) },
                        { "related_activity", SummarizeRecentActivity() },
                        { "evidence_report", reportPath }
                    };

                    _logger.Log(DetectionEvent.Create(
                        "HardwareIdentity",
                        finding.Action,
                        finding.Severity,
                        finding.Description,
                        null,
                        null,
                        details));
                }

                _logger.Log(DetectionEvent.Create(
                    "HardwareIdentity",
                    "SnapshotComplete",
                    findings.Count > 0 ? EventSeverity.Medium : EventSeverity.Low,
                    "Hardware identity snapshot complete for stage " + stage + ".",
                    reportPath,
                    null,
                    new Dictionary<string, string>
                    {
                        { "finding_count", findings.Count.ToString(CultureInfo.InvariantCulture) },
                        { "baseline_existed", hadBaseline.ToString() },
                        { "report_path", reportPath }
                    }));
            }
        }

        private List<HardwareIdentityFinding> EvaluateSnapshot(HardwareIdentitySnapshot snapshot, Dictionary<string, string> baseline, bool hadBaseline)
        {
            List<HardwareIdentityFinding> findings = new List<HardwareIdentityFinding>();
            EvaluateDisks(snapshot, baseline, hadBaseline, findings);
            EvaluateNetwork(snapshot, baseline, hadBaseline, findings);
            EvaluateSystemIdentity(snapshot, baseline, hadBaseline, findings);
            EvaluateGpus(snapshot, baseline, hadBaseline, findings);
            EvaluateDeviceStackIdentity(snapshot, baseline, hadBaseline, findings);
            EvaluateBaselineDrift(snapshot, baseline, hadBaseline, findings);
            return findings;
        }

        private void EvaluateDisks(HardwareIdentitySnapshot snapshot, Dictionary<string, string> baseline, bool hadBaseline, ICollection<HardwareIdentityFinding> findings)
        {
            foreach (DiskIdentityRecord disk in snapshot.Disks)
            {
                if (HardwareIdentityUtilities.IsBlankOrZero(disk.Serial))
                {
                    findings.Add(Finding(
                        "DiskBlankOrZeroSerial",
                        EventSeverity.High,
                        "Disk identity source reported a blank/generic/zero serial.",
                        "disk.serial",
                        disk.Source,
                        disk.Serial,
                        null,
                        null,
                        null,
                        disk.Serial,
                        0.85,
                        DiskDetails(disk)));
                }
            }

            Dictionary<string, DiskIdentityRecord> wmiByIndex = snapshot.Disks
                .Where(d => d.Source == "WMI.Win32_DiskDrive" && !string.IsNullOrWhiteSpace(d.Index))
                .GroupBy(d => d.Index)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

            foreach (DiskIdentityRecord ioctl in snapshot.Disks.Where(d => d.Source == "IOCTL_STORAGE_QUERY_PROPERTY" && !string.IsNullOrWhiteSpace(d.Index)))
            {
                DiskIdentityRecord wmi;
                if (!wmiByIndex.TryGetValue(ioctl.Index, out wmi))
                {
                    continue;
                }

                CompareValues(findings, "DiskSerialMismatch", "disk.serial", wmi.Source, wmi.Serial, ioctl.Source, ioctl.Serial, 0.9, DiskDetails(wmi, ioctl));
                CompareValues(findings, "DiskModelMismatch", "disk.model", wmi.Source, wmi.Model, ioctl.Source, ioctl.Model, 0.65, DiskDetails(wmi, ioctl));
            }

            foreach (DiskIdentityRecord wmi in snapshot.Disks.Where(d => d.Source == "WMI.Win32_DiskDrive" && !string.IsNullOrWhiteSpace(d.Serial)))
            {
                foreach (DiskIdentityRecord registry in snapshot.Disks.Where(d => d.Source == "Registry.StorageEnum" && !string.IsNullOrWhiteSpace(d.Serial)))
                {
                    if (!LooksLikeSameDisk(wmi, registry))
                    {
                        continue;
                    }

                    CompareValues(findings, "DiskRegistrySerialMismatch", "disk.serial", wmi.Source, wmi.Serial, registry.Source, registry.Serial, 0.78, DiskDetails(wmi, registry));
                    CompareValues(findings, "DiskRegistryModelMismatch", "disk.model", wmi.Source, wmi.Model, registry.Source, registry.Model, 0.60, DiskDetails(wmi, registry));
                }
            }
        }

        private void EvaluateNetwork(HardwareIdentitySnapshot snapshot, Dictionary<string, string> baseline, bool hadBaseline, ICollection<HardwareIdentityFinding> findings)
        {
            foreach (NetworkIdentityRecord adapter in snapshot.NetworkAdapters)
            {
                if (adapter.IsLocallyAdministered && !adapter.IsVirtual)
                {
                    findings.Add(Finding(
                        "LocallyAdministeredMac",
                        EventSeverity.High,
                        "Physical network adapter is using a locally administered MAC address.",
                        "network.mac",
                        adapter.Source,
                        adapter.MacAddress,
                        null,
                        null,
                        null,
                        adapter.MacAddress,
                        0.8,
                        NetworkDetails(adapter)));
                }

                if (adapter.IsVirtual && HasActiveProtectedProcess() && IsNewAdapterComparedToBaseline(adapter, baseline))
                {
                    findings.Add(Finding(
                        "VirtualAdapterAppearedDuringProtectedSession",
                        EventSeverity.High,
                        "Virtual network adapter is present during protected runtime and was not in the baseline.",
                        "network.adapter",
                        adapter.Source,
                        adapter.Name,
                        "baseline",
                        "missing",
                        "missing",
                        adapter.Name,
                        0.75,
                        NetworkDetails(adapter)));
                }

                if (HasActiveProtectedProcess() && HasRecentActivity("adapter", "reset"))
                {
                    findings.Add(Finding(
                        "AdapterResetNearProtectedLaunch",
                        EventSeverity.Medium,
                        "Network adapter reset/change activity appeared near protected runtime.",
                        "network.adapter_reset",
                        adapter.Source,
                        adapter.Name,
                        "event-log",
                        SummarizeRecentActivity(),
                        null,
                        adapter.Name,
                        0.68,
                        NetworkDetails(adapter)));
                }
            }

            foreach (NetworkIdentityRecord wmi in snapshot.NetworkAdapters.Where(a => a.Source == "WMI.Win32_NetworkAdapter" && !string.IsNullOrWhiteSpace(a.MacAddress)))
            {
                foreach (NetworkIdentityRecord other in snapshot.NetworkAdapters.Where(a => a.Source != wmi.Source && !string.IsNullOrWhiteSpace(a.MacAddress)))
                {
                    if (!LooksLikeSameAdapter(wmi, other))
                    {
                        continue;
                    }

                    CompareValues(findings, "RuntimeMacMismatch", "network.mac", wmi.Source, wmi.MacAddress, other.Source, other.MacAddress, 0.9, NetworkDetails(wmi, other));
                }
            }

            foreach (NetworkIdentityRecord registry in snapshot.NetworkAdapters.Where(a => a.Source == "Registry.NetworkClass" && !string.IsNullOrWhiteSpace(a.MacAddress)))
            {
                findings.Add(Finding(
                    "AdapterAdvancedMacOverridePresent",
                    EventSeverity.Medium,
                    "Network adapter registry advanced properties contain a NetworkAddress override.",
                    "network.registry_override_mac",
                    registry.Source,
                    registry.MacAddress,
                    null,
                    null,
                    null,
                    registry.MacAddress,
                    0.7,
                    NetworkDetails(registry)));
            }
        }

        private void EvaluateSystemIdentity(HardwareIdentitySnapshot snapshot, Dictionary<string, string> baseline, bool hadBaseline, ICollection<HardwareIdentityFinding> findings)
        {
            foreach (SystemIdentityRecord record in snapshot.SystemIdentities)
            {
                FlagGenericSystemValue(findings, record, "smbios.bios_serial", record.BiosSerial);
                FlagGenericSystemValue(findings, record, "smbios.baseboard_serial", record.BaseboardSerial);
                FlagGenericSystemValue(findings, record, "smbios.uuid", record.SystemUuid);
                FlagRandomizedSystemValue(findings, record, "smbios.bios_serial", record.BiosSerial);
                FlagRandomizedSystemValue(findings, record, "smbios.baseboard_serial", record.BaseboardSerial);
            }

            SystemIdentityRecord wmi = snapshot.SystemIdentities.FirstOrDefault(s => s.Source == "WMI");
            SystemIdentityRecord registry = snapshot.SystemIdentities.FirstOrDefault(s => s.Source == "Registry.HardwareDescription");
            SystemIdentityRecord firmware = snapshot.SystemIdentities.FirstOrDefault(s => s.Source == "FirmwareTable.RSMB");

            if (wmi != null && registry != null)
            {
                CompareValues(findings, "SmbiosRegistryMismatch", "smbios.bios_serial", wmi.Source, wmi.BiosSerial, registry.Source, registry.BiosSerial, 0.75, SystemDetails(wmi, registry));
                CompareValues(findings, "SmbiosRegistryMismatch", "smbios.baseboard_serial", wmi.Source, wmi.BaseboardSerial, registry.Source, registry.BaseboardSerial, 0.75, SystemDetails(wmi, registry));
                CompareValues(findings, "SmbiosRegistryMismatch", "smbios.system_vendor", wmi.Source, wmi.SystemVendor, registry.Source, registry.SystemVendor, 0.55, SystemDetails(wmi, registry));
            }

            if (wmi != null && firmware != null && !string.IsNullOrWhiteSpace(firmware.FirmwareStringSummary))
            {
                CheckFirmwareContains(findings, wmi.BiosSerial, "smbios.bios_serial", firmware, 0.6);
                CheckFirmwareContains(findings, wmi.BaseboardSerial, "smbios.baseboard_serial", firmware, 0.6);
                CheckFirmwareContains(findings, wmi.SystemUuid, "smbios.uuid", firmware, 0.55);
            }

            if (wmi != null && HasImpossibleVendorMix(wmi))
            {
                findings.Add(Finding(
                    "ImpossibleVendorCombination",
                    EventSeverity.High,
                    "System identity contains a suspicious real/virtual vendor combination.",
                    "smbios.vendor_combination",
                    wmi.Source,
                    HardwareIdentityUtilities.JoinNonEmpty(new[] { wmi.BiosVendor, wmi.BaseboardVendor, wmi.SystemVendor }, "|"),
                    null,
                    null,
                    null,
                    null,
                    0.7,
                    SystemDetails(wmi)));
            }
        }

        private void EvaluateGpus(HardwareIdentitySnapshot snapshot, Dictionary<string, string> baseline, bool hadBaseline, ICollection<HardwareIdentityFinding> findings)
        {
            foreach (GpuIdentityRecord gpu in snapshot.Gpus)
            {
                if (gpu.IsVirtual)
                {
                    findings.Add(Finding(
                        "SuspiciousVirtualGpuLayer",
                        EventSeverity.Medium,
                        "GPU/display identity indicates a virtual display or GPU layer.",
                        "gpu.virtual_layer",
                        gpu.Source,
                        gpu.Name,
                        null,
                        null,
                        null,
                        gpu.Name,
                        0.65,
                        GpuDetails(gpu)));
                }

                if (!string.IsNullOrWhiteSpace(gpu.DriverPath) &&
                    !string.Equals(gpu.SignatureStatus, "Trusted", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(Finding(
                        "UnsignedDisplayRelatedDriver",
                        EventSeverity.High,
                        "Display-related driver is not trusted.",
                        "gpu.driver_signature",
                        gpu.Source,
                        gpu.DriverPath,
                        "WinVerifyTrust",
                        gpu.SignatureStatus,
                        null,
                        gpu.SignatureStatus,
                        0.85,
                        GpuDetails(gpu)));
                }
            }

            foreach (GpuIdentityRecord wmi in snapshot.Gpus.Where(g => g.Source == "WMI.Win32_VideoController"))
            {
                bool matchedDeviceStack = false;
                foreach (GpuIdentityRecord dxgi in snapshot.Gpus.Where(g => g.Source == "DXGI"))
                {
                    if (!GpuNamesLikelyMatch(wmi.Name, dxgi.Name))
                    {
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(wmi.DeviceId) && !string.IsNullOrWhiteSpace(dxgi.DeviceId))
                    {
                        CompareValues(findings, "GpuDeviceIdMismatch", "gpu.device_id", wmi.Source, wmi.DeviceId, dxgi.Source, dxgi.DeviceId, 0.75, GpuDetails(wmi, dxgi));
                    }
                }

                foreach (DeviceStackRecord display in snapshot.Devices.Where(d => IsDisplayDevice(d)))
                {
                    if (!LooksLikeSameGpuDevice(wmi, display))
                    {
                        continue;
                    }

                    matchedDeviceStack = true;
                    CompareValues(findings, "GpuPnpDeviceStackMismatch", "gpu.pnp_device_id", wmi.Source, wmi.PnpDeviceId, display.Source, display.DeviceId, 0.72, MergeDetails(GpuDetails(wmi), DeviceDetails(display)));
                    if (!string.IsNullOrWhiteSpace(display.Service) && LooksSuspiciousDeviceService(display.Service))
                    {
                        findings.Add(Finding(
                            "SuspiciousDisplayDeviceService",
                            EventSeverity.High,
                            "Display device stack references a suspicious service or filter.",
                            "gpu.device_service",
                            display.Source,
                            display.Service,
                            "device_stack",
                            display.DeviceId,
                            null,
                            display.Service,
                            0.78,
                            DeviceDetails(display)));
                    }
                }

                if (!string.IsNullOrWhiteSpace(wmi.PnpDeviceId) && !matchedDeviceStack && snapshot.Devices.Any(IsDisplayDevice))
                {
                    findings.Add(Finding(
                        "GpuPnpMissingFromDeviceStack",
                        EventSeverity.Medium,
                        "GPU PnP identifier was not found in the current display device stack inventory.",
                        "gpu.pnp_device_id",
                        wmi.Source,
                        wmi.PnpDeviceId,
                        "WMI.Win32_PnPEntity",
                        "missing",
                        null,
                        wmi.PnpDeviceId,
                        0.62,
                        GpuDetails(wmi)));
                }
            }
        }

        private static void EvaluateDeviceStackIdentity(HardwareIdentitySnapshot snapshot, Dictionary<string, string> baseline, bool hadBaseline, ICollection<HardwareIdentityFinding> findings)
        {
            foreach (DeviceStackRecord device in snapshot.Devices)
            {
                if (device.IsVirtual && IsIdentityRelevantDevice(device) && hadBaseline && IsNewDeviceComparedToBaseline(device, baseline))
                {
                    findings.Add(Finding(
                        "VirtualHardwareDeviceAppeared",
                        EventSeverity.Medium,
                        "Virtual hardware-related device is present and was not in the baseline.",
                        "device.virtual_hardware",
                        device.Source,
                        device.Name,
                        "baseline",
                        "missing",
                        "missing",
                        device.Name,
                        0.66,
                        DeviceDetails(device)));
                }

                string filters = HardwareIdentityUtilities.JoinNonEmpty(new[] { device.UpperFilters, device.LowerFilters }, ";");
                if (!string.IsNullOrWhiteSpace(filters) && LooksSuspiciousDeviceService(filters))
                {
                    findings.Add(Finding(
                        "SuspiciousDeviceFilter",
                        EventSeverity.High,
                        "Hardware device class has a suspicious filter driver value.",
                        "device.filter",
                        device.Source,
                        filters,
                        "device",
                        device.Name,
                        null,
                        filters,
                        0.80,
                        DeviceDetails(device)));
                }
            }
        }

        private void EvaluateBaselineDrift(HardwareIdentitySnapshot snapshot, Dictionary<string, string> baseline, bool hadBaseline, ICollection<HardwareIdentityFinding> findings)
        {
            if (!hadBaseline)
            {
                return;
            }

            Dictionary<string, string> current = FlattenSnapshot(snapshot);
            foreach (KeyValuePair<string, string> pair in current)
            {
                string baselineValue;
                if (!baseline.TryGetValue(pair.Key, out baselineValue))
                {
                    if (IsSessionSensitiveKey(pair.Key))
                    {
                        findings.Add(Finding(
                            "HardwareIdentifierAppeared",
                            EventSeverity.Medium,
                            "Hardware identifier appeared compared to baseline.",
                            pair.Key,
                            "baseline",
                            "missing",
                            "current",
                            pair.Value,
                            "missing",
                            pair.Value,
                            0.65,
                            new Dictionary<string, string> { { "baseline_key", pair.Key } }));
                    }

                    continue;
                }

                if (!string.Equals(baselineValue, pair.Value, StringComparison.OrdinalIgnoreCase) && IsSessionSensitiveKey(pair.Key))
                {
                    if (IsDiskSerialKey(pair.Key) && DiskIdentitySiblingsStable(pair.Key, current, baseline))
                    {
                        findings.Add(Finding(
                            "DiskSerialChangedWithoutDeviceChange",
                            EventSeverity.High,
                            "Disk serial changed while sibling disk model/vendor/PnP identity stayed stable.",
                            pair.Key,
                            "baseline",
                            baselineValue,
                            "current",
                            pair.Value,
                            baselineValue,
                            pair.Value,
                            0.88,
                            new Dictionary<string, string>
                            {
                                { "baseline_key", pair.Key },
                                { "real_device_change_indicator", "model_vendor_or_pnp_unchanged" }
                            }));
                    }

                    findings.Add(Finding(
                        "HardwareIdentifierChanged",
                        SeverityForBaselineKey(pair.Key),
                        "Hardware identifier changed compared to baseline.",
                        pair.Key,
                        "baseline",
                        baselineValue,
                        "current",
                        pair.Value,
                        baselineValue,
                        pair.Value,
                        0.8,
                        new Dictionary<string, string> { { "baseline_key", pair.Key } }));
                }
            }
        }

        private void CompareValues(ICollection<HardwareIdentityFinding> findings, string action, string identifierType, string sourceA, string valueA, string sourceB, string valueB, double confidence, Dictionary<string, string> details)
        {
            string normalizedA = HardwareIdentityUtilities.NormalizeIdentifier(valueA);
            string normalizedB = HardwareIdentityUtilities.NormalizeIdentifier(valueB);
            if (string.IsNullOrWhiteSpace(normalizedA) || string.IsNullOrWhiteSpace(normalizedB))
            {
                return;
            }

            if (string.Equals(normalizedA, normalizedB, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            findings.Add(Finding(
                action,
                confidence >= 0.85 ? EventSeverity.High : EventSeverity.Medium,
                identifierType + " differs between " + sourceA + " and " + sourceB + ".",
                identifierType,
                sourceA,
                valueA,
                sourceB,
                valueB,
                null,
                valueB,
                confidence,
                details));
        }

        private void FlagGenericSystemValue(ICollection<HardwareIdentityFinding> findings, SystemIdentityRecord record, string identifierType, string value)
        {
            if (!HardwareIdentityUtilities.IsBlankOrZero(value))
            {
                return;
            }

            findings.Add(Finding(
                "GenericSystemIdentifier",
                EventSeverity.High,
                "System firmware identity value is blank, generic, or zeroed.",
                identifierType,
                record.Source,
                value,
                null,
                null,
                null,
                value,
                0.8,
                SystemDetails(record)));
        }

        private void FlagRandomizedSystemValue(ICollection<HardwareIdentityFinding> findings, SystemIdentityRecord record, string identifierType, string value)
        {
            if (!LooksRandomizedIdentifier(value))
            {
                return;
            }

            findings.Add(Finding(
                "RandomizedLookingSystemIdentifier",
                EventSeverity.Medium,
                "System firmware identity value has a randomized-looking serial format.",
                identifierType,
                record.Source,
                value,
                null,
                null,
                null,
                value,
                0.62,
                SystemDetails(record)));
        }

        private void CheckFirmwareContains(ICollection<HardwareIdentityFinding> findings, string value, string identifierType, SystemIdentityRecord firmware, double confidence)
        {
            if (HardwareIdentityUtilities.IsBlankOrZero(value))
            {
                return;
            }

            if (firmware.FirmwareStringSummary.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return;
            }

            findings.Add(Finding(
                "WmiFirmwareTableMismatch",
                EventSeverity.Medium,
                "WMI system identity value was not found in raw SMBIOS firmware strings.",
                identifierType,
                "WMI",
                value,
                firmware.Source,
                firmware.FirmwareHash,
                null,
                value,
                confidence,
                SystemDetails(firmware)));
        }

        private static bool LooksRandomizedIdentifier(string value)
        {
            string normalized = HardwareIdentityUtilities.NormalizeIdentifier(value);
            if (string.IsNullOrWhiteSpace(normalized) || normalized.Length < 10 || normalized.Length > 48)
            {
                return false;
            }

            string compact = new string(normalized.Where(char.IsLetterOrDigit).ToArray());
            if (compact.Length < 10)
            {
                return false;
            }

            int letters = compact.Count(char.IsLetter);
            int digits = compact.Count(char.IsDigit);
            int vowels = compact.Count(c => "AEIOU".IndexOf(char.ToUpperInvariant(c)) >= 0);
            int distinct = compact.Distinct().Count();
            return letters >= 5 && digits >= 3 && distinct >= 8 && vowels <= Math.Max(1, letters / 5);
        }

        private static HardwareIdentityFinding Finding(string action, EventSeverity severity, string description, string identifierType, string sourceA, string sourceAValue, string sourceB, string sourceBValue, string baselineValue, string currentValue, double confidence, Dictionary<string, string> details)
        {
            HardwareIdentityFinding finding = new HardwareIdentityFinding
            {
                Action = action,
                Severity = severity,
                Description = description,
                IdentifierType = identifierType,
                SourceA = sourceA,
                SourceAValue = sourceAValue,
                SourceB = sourceB,
                SourceBValue = sourceBValue,
                BaselineValue = baselineValue,
                CurrentValue = currentValue,
                ConfidenceScore = confidence
            };

            if (details != null)
            {
                foreach (KeyValuePair<string, string> pair in details)
                {
                    finding.Details[pair.Key] = pair.Value;
                }
            }

            return finding;
        }

        private Dictionary<string, string> FlattenSnapshot(HardwareIdentitySnapshot snapshot)
        {
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (DiskIdentityRecord disk in snapshot.Disks)
            {
                string key = "disk|" + disk.Source + "|" + (disk.Index ?? disk.DeviceId ?? disk.RegistryPath ?? disk.PnpDeviceId);
                AddFlattened(values, key + "|serial", disk.Serial);
                AddFlattened(values, key + "|model", disk.Model);
                AddFlattened(values, key + "|vendor", disk.Vendor);
                AddFlattened(values, key + "|pnp", disk.PnpDeviceId);
            }

            foreach (VolumeIdentityRecord volume in snapshot.Volumes)
            {
                string key = "volume|" + volume.DriveName;
                AddFlattened(values, key + "|serial", volume.VolumeSerial);
            }

            foreach (MountedDeviceRecord mounted in snapshot.MountedDevices)
            {
                AddFlattened(values, "mounteddevice|" + mounted.RegistryValueName, mounted.ValueHash);
            }

            foreach (NetworkIdentityRecord adapter in snapshot.NetworkAdapters)
            {
                string key = "network|" + adapter.Source + "|" + (adapter.AdapterId ?? adapter.Name ?? adapter.Description);
                AddFlattened(values, key + "|mac", adapter.MacAddress);
                AddFlattened(values, key + "|pnp", adapter.PnpDeviceId);
            }

            foreach (SystemIdentityRecord system in snapshot.SystemIdentities)
            {
                string key = "system|" + system.Source;
                AddFlattened(values, key + "|bios_serial", system.BiosSerial);
                AddFlattened(values, key + "|baseboard_serial", system.BaseboardSerial);
                AddFlattened(values, key + "|uuid", system.SystemUuid);
                AddFlattened(values, key + "|firmware_hash", system.FirmwareHash);
                AddFlattened(values, key + "|hypervisor_present", system.HypervisorPresent);
            }

            foreach (GpuIdentityRecord gpu in snapshot.Gpus)
            {
                string key = "gpu|" + gpu.Source + "|" + (gpu.PnpDeviceId ?? gpu.DeviceId ?? gpu.Name);
                AddFlattened(values, key + "|pnp", gpu.PnpDeviceId);
                AddFlattened(values, key + "|device_id", gpu.DeviceId);
                AddFlattened(values, key + "|driver_version", gpu.DriverVersion);
            }

            foreach (TpmIdentityRecord tpm in snapshot.Tpms)
            {
                string key = "tpm|" + tpm.Source;
                AddFlattened(values, key + "|present", tpm.Present.ToString());
                AddFlattened(values, key + "|enabled", tpm.Enabled.ToString());
                AddFlattened(values, key + "|activated", tpm.Activated.ToString());
                AddFlattened(values, key + "|owned", tpm.Owned.ToString());
                AddFlattened(values, key + "|manufacturer", tpm.ManufacturerId);
                AddFlattened(values, key + "|version", tpm.ManufacturerVersion);
            }

            foreach (MonitorIdentityRecord monitor in snapshot.Monitors)
            {
                string key = "monitor|" + monitor.Source + "|" + (monitor.DeviceId ?? monitor.InstanceId ?? monitor.EdidHash);
                AddFlattened(values, key + "|serial", monitor.Serial);
                AddFlattened(values, key + "|product", monitor.ProductCode);
                AddFlattened(values, key + "|manufacturer", monitor.Manufacturer);
                AddFlattened(values, key + "|edid_hash", monitor.EdidHash);
            }

            foreach (DeviceStackRecord device in snapshot.Devices)
            {
                string key = "device|" + device.Source + "|" + (device.DeviceId ?? device.ClassGuid ?? device.Name);
                AddFlattened(values, key + "|present", "present");
                AddFlattened(values, key + "|service", device.Service);
                AddFlattened(values, key + "|status", device.Status);
                AddFlattened(values, key + "|upper_filters", device.UpperFilters);
                AddFlattened(values, key + "|lower_filters", device.LowerFilters);
            }

            return values;
        }

        private static void AddFlattened(IDictionary<string, string> values, string key, string value)
        {
            string normalized = HardwareIdentityUtilities.NormalizeIdentifier(value);
            if (!string.IsNullOrWhiteSpace(key) && !string.IsNullOrWhiteSpace(normalized))
            {
                values[key] = normalized;
            }
        }

        private string WriteReport(HardwareIdentitySnapshot snapshot, ICollection<HardwareIdentityFinding> findings, bool hadBaseline)
        {
            string stamp = snapshot.TimestampUtc.ToString("yyyyMMdd-HHmmssfff", CultureInfo.InvariantCulture);
            string safeStage = SanitizeFileName(snapshot.Stage ?? "snapshot");
            string path = Path.Combine(_evidenceRoot, "hardware-identity-" + stamp + "-" + safeStage + ".json");

            File.WriteAllText(path, BuildReportJson(snapshot, findings, hadBaseline), Encoding.UTF8);
            return path;
        }

        private string BuildReportJson(HardwareIdentitySnapshot snapshot, ICollection<HardwareIdentityFinding> findings, bool hadBaseline)
        {
            StringBuilder builder = new StringBuilder();
            bool first = true;
            builder.Append("{");
            JsonUtilities.AppendStringProperty(builder, "timestamp_utc", snapshot.TimestampUtc.ToString("o", CultureInfo.InvariantCulture), ref first);
            JsonUtilities.AppendStringProperty(builder, "stage", snapshot.Stage, ref first);
            JsonUtilities.AppendStringProperty(builder, "baseline_existed", hadBaseline.ToString(), ref first);
            JsonUtilities.AppendNumberProperty(builder, "finding_count", findings.Count.ToString(CultureInfo.InvariantCulture), ref first);
            AppendFindings(builder, findings, ref first);
            AppendSnapshotSummary(builder, snapshot, ref first);
            builder.Append("}");
            return builder.ToString();
        }

        private static void AppendFindings(StringBuilder builder, ICollection<HardwareIdentityFinding> findings, ref bool first)
        {
            if (!first)
            {
                builder.Append(",");
            }

            builder.Append("\"findings\":[");
            bool firstFinding = true;
            foreach (HardwareIdentityFinding finding in findings)
            {
                if (!firstFinding)
                {
                    builder.Append(",");
                }

                bool firstProperty = true;
                builder.Append("{");
                JsonUtilities.AppendStringProperty(builder, "action", finding.Action, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "severity", finding.Severity.ToString(), ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "description", finding.Description, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "identifier_type", finding.IdentifierType, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "source_a", finding.SourceA, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "source_a_value", finding.SourceAValue, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "source_b", finding.SourceB, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "source_b_value", finding.SourceBValue, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "baseline_value", finding.BaselineValue, ref firstProperty);
                JsonUtilities.AppendStringProperty(builder, "current_value", finding.CurrentValue, ref firstProperty);
                JsonUtilities.AppendNumberProperty(builder, "confidence_score", finding.ConfidenceScore.ToString("0.00", CultureInfo.InvariantCulture), ref firstProperty);
                builder.Append("}");
                firstFinding = false;
            }

            builder.Append("]");
            first = false;
        }

        private static void AppendSnapshotSummary(StringBuilder builder, HardwareIdentitySnapshot snapshot, ref bool first)
        {
            if (!first)
            {
                builder.Append(",");
            }

            builder.Append("\"snapshot_summary\":{");
            bool firstSummary = true;
            JsonUtilities.AppendNumberProperty(builder, "disk_records", snapshot.Disks.Count.ToString(CultureInfo.InvariantCulture), ref firstSummary);
            JsonUtilities.AppendNumberProperty(builder, "volume_records", snapshot.Volumes.Count.ToString(CultureInfo.InvariantCulture), ref firstSummary);
            JsonUtilities.AppendNumberProperty(builder, "mounted_device_records", snapshot.MountedDevices.Count.ToString(CultureInfo.InvariantCulture), ref firstSummary);
            JsonUtilities.AppendNumberProperty(builder, "network_records", snapshot.NetworkAdapters.Count.ToString(CultureInfo.InvariantCulture), ref firstSummary);
            JsonUtilities.AppendNumberProperty(builder, "system_records", snapshot.SystemIdentities.Count.ToString(CultureInfo.InvariantCulture), ref firstSummary);
            JsonUtilities.AppendNumberProperty(builder, "gpu_records", snapshot.Gpus.Count.ToString(CultureInfo.InvariantCulture), ref firstSummary);
            JsonUtilities.AppendNumberProperty(builder, "tpm_records", snapshot.Tpms.Count.ToString(CultureInfo.InvariantCulture), ref firstSummary);
            JsonUtilities.AppendNumberProperty(builder, "monitor_records", snapshot.Monitors.Count.ToString(CultureInfo.InvariantCulture), ref firstSummary);
            JsonUtilities.AppendNumberProperty(builder, "device_stack_records", snapshot.Devices.Count.ToString(CultureInfo.InvariantCulture), ref firstSummary);
            builder.Append("}");
            first = false;
        }

        private void RememberActivity(DetectionEvent detectionEvent)
        {
            if (detectionEvent.Severity < EventSeverity.Medium)
            {
                return;
            }

            string summary = detectionEvent.TimestampUtc.ToString("o", CultureInfo.InvariantCulture) +
                             " " + detectionEvent.Category + "/" + detectionEvent.Action +
                             " " + detectionEvent.Description;
            _recentActivity.Enqueue(summary);

            while (_recentActivity.Count > 25)
            {
                string ignored;
                _recentActivity.TryDequeue(out ignored);
            }
        }

        private string SummarizeRecentActivity()
        {
            return string.Join(" || ", _recentActivity.ToArray().Reverse().Take(8).Reverse().ToArray());
        }

        private bool HasRecentActivity(params string[] terms)
        {
            string recent = SummarizeRecentActivity();
            if (string.IsNullOrWhiteSpace(recent) || terms == null)
            {
                return false;
            }

            foreach (string term in terms)
            {
                if (string.IsNullOrWhiteSpace(term) || recent.IndexOf(term, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    return false;
                }
            }

            return true;
        }

        private bool IsProtectedProcessEvent(DetectionEvent detectionEvent)
        {
            string name = detectionEvent.ProcessName;
            if (string.IsNullOrWhiteSpace(name))
            {
                string processName;
                detectionEvent.Details.TryGetValue("process_name", out processName);
                name = processName;
            }

            if (string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(detectionEvent.Path))
            {
                name = Path.GetFileName(detectionEvent.Path);
            }

            if (string.IsNullOrWhiteSpace(name))
            {
                return false;
            }

            return TargetProcessMatcher.IsProtectedProcessName(name, _options.ProtectedProcessNames);
        }

        private static bool IsProcessStartEvent(DetectionEvent detectionEvent)
        {
            return detectionEvent.Action.IndexOf("Executed", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   detectionEvent.Action.IndexOf("Created", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsProcessExitEvent(DetectionEvent detectionEvent)
        {
            return detectionEvent.Action.IndexOf("Exited", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private bool HasActiveProtectedProcess()
        {
            lock (_activeProtectedProcesses)
            {
                return _activeProtectedProcesses.Count > 0;
            }
        }

        private static bool IsNewAdapterComparedToBaseline(NetworkIdentityRecord adapter, IDictionary<string, string> baseline)
        {
            string token = HardwareIdentityUtilities.NormalizeIdentifier(adapter.AdapterId ?? adapter.Name ?? adapter.Description);
            if (string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            foreach (string key in baseline.Keys)
            {
                if (key.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return false;
                }
            }

            return true;
        }

        private static bool LooksLikeSameAdapter(NetworkIdentityRecord a, NetworkIdentityRecord b)
        {
            string aId = NormalizeAdapterId(a.AdapterId);
            string bId = NormalizeAdapterId(b.AdapterId);
            if (!string.IsNullOrWhiteSpace(aId) && !string.IsNullOrWhiteSpace(bId) && aId.Equals(bId, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return !string.IsNullOrWhiteSpace(a.Description) &&
                   !string.IsNullOrWhiteSpace(b.Description) &&
                   (a.Description.IndexOf(b.Description, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    b.Description.IndexOf(a.Description, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static bool LooksLikeSameDisk(DiskIdentityRecord a, DiskIdentityRecord b)
        {
            if (a == null || b == null)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(a.PnpDeviceId) && !string.IsNullOrWhiteSpace(b.DeviceId) &&
                (a.PnpDeviceId.IndexOf(b.DeviceId, StringComparison.OrdinalIgnoreCase) >= 0 ||
                 b.DeviceId.IndexOf(a.PnpDeviceId, StringComparison.OrdinalIgnoreCase) >= 0))
            {
                return true;
            }

            if (!string.IsNullOrWhiteSpace(a.Model) && !string.IsNullOrWhiteSpace(b.Model) && TokenOverlap(a.Model, b.Model) >= 2)
            {
                return true;
            }

            return !string.IsNullOrWhiteSpace(a.Index) && string.Equals(a.Index, b.Index, StringComparison.OrdinalIgnoreCase);
        }

        private static bool LooksLikeSameGpuDevice(GpuIdentityRecord gpu, DeviceStackRecord device)
        {
            if (gpu == null || device == null)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(gpu.PnpDeviceId) && !string.IsNullOrWhiteSpace(device.DeviceId))
            {
                return string.Equals(gpu.PnpDeviceId, device.DeviceId, StringComparison.OrdinalIgnoreCase) ||
                       gpu.PnpDeviceId.IndexOf(device.DeviceId, StringComparison.OrdinalIgnoreCase) >= 0 ||
                       device.DeviceId.IndexOf(gpu.PnpDeviceId, StringComparison.OrdinalIgnoreCase) >= 0;
            }

            return GpuNamesLikelyMatch(gpu.Name, device.Name);
        }

        private static bool IsDisplayDevice(DeviceStackRecord device)
        {
            return device != null &&
                   (ContainsAny(device.PnpClass, "display") ||
                    ContainsAny(device.ClassGuid, "{4d36e968-e325-11ce-bfc1-08002be10318}") ||
                    ContainsAny(device.Name, "display", "gpu", "nvidia", "radeon", "intel"));
        }

        private static bool IsIdentityRelevantDevice(DeviceStackRecord device)
        {
            return device != null &&
                   (ContainsAny(device.PnpClass, "net", "display", "diskdrive", "storage", "scsiadapter", "volume", "monitor", "system", "securitydevices") ||
                    ContainsAny(device.ClassGuid, "{4d36e972", "{4d36e968", "{4d36e967", "{4d36e97b}"));
        }

        private static bool IsNewDeviceComparedToBaseline(DeviceStackRecord device, IDictionary<string, string> baseline)
        {
            string token = HardwareIdentityUtilities.NormalizeIdentifier(device.DeviceId ?? device.Name ?? device.ClassGuid);
            if (string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            foreach (string key in baseline.Keys)
            {
                if (key.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return false;
                }
            }

            return true;
        }

        private static bool LooksSuspiciousDeviceService(string value)
        {
            return ContainsAny(value, "spoof", "hwid", "mapper", "kdmapper", "iqvw", "gdrv", "capcom", "dbutil", "rtcore", "winio", "mhyprot", "kdu") ||
                   LooksRandomizedIdentifier(value);
        }

        private static string NormalizeAdapterId(string id)
        {
            if (string.IsNullOrWhiteSpace(id))
            {
                return null;
            }

            return id.Trim('{', '}').ToUpperInvariant();
        }

        private static bool HasImpossibleVendorMix(SystemIdentityRecord record)
        {
            string combined = HardwareIdentityUtilities.JoinNonEmpty(new[] { record.BiosVendor, record.BaseboardVendor, record.SystemVendor }, " ");
            if (string.IsNullOrWhiteSpace(combined))
            {
                return false;
            }

            bool virtualVendor = HardwareIdentityUtilities.LooksVirtual(combined);
            bool realVendor = combined.IndexOf("ASUS", StringComparison.OrdinalIgnoreCase) >= 0 ||
                              combined.IndexOf("MSI", StringComparison.OrdinalIgnoreCase) >= 0 ||
                              combined.IndexOf("GIGABYTE", StringComparison.OrdinalIgnoreCase) >= 0 ||
                              combined.IndexOf("DELL", StringComparison.OrdinalIgnoreCase) >= 0 ||
                              combined.IndexOf("HP", StringComparison.OrdinalIgnoreCase) >= 0 ||
                              combined.IndexOf("LENOVO", StringComparison.OrdinalIgnoreCase) >= 0 ||
                              combined.IndexOf("ACER", StringComparison.OrdinalIgnoreCase) >= 0;

            return virtualVendor && realVendor;
        }

        private static bool GpuNamesLikelyMatch(string a, string b)
        {
            if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b))
            {
                return false;
            }

            return a.IndexOf(b, StringComparison.OrdinalIgnoreCase) >= 0 ||
                   b.IndexOf(a, StringComparison.OrdinalIgnoreCase) >= 0 ||
                   TokenOverlap(a, b) >= 2;
        }

        private static int TokenOverlap(string a, string b)
        {
            HashSet<string> aTokens = new HashSet<string>(a.Split(new[] { ' ', '\t', '-', '_' }, StringSplitOptions.RemoveEmptyEntries), StringComparer.OrdinalIgnoreCase);
            int count = 0;
            foreach (string token in b.Split(new[] { ' ', '\t', '-', '_' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (token.Length > 2 && aTokens.Contains(token))
                {
                    count++;
                }
            }

            return count;
        }

        private static bool IsSessionSensitiveKey(string key)
        {
            return key.IndexOf("|serial", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   key.IndexOf("|mac", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   key.IndexOf("|uuid", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   key.IndexOf("|pnp", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   key.IndexOf("|device_id", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   key.IndexOf("mounteddevice", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   key.IndexOf("|firmware_hash", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   key.IndexOf("|hypervisor_present", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   key.IndexOf("tpm|", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   key.IndexOf("monitor|", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   key.IndexOf("device|", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool IsDiskSerialKey(string key)
        {
            return key != null &&
                   key.StartsWith("disk|", StringComparison.OrdinalIgnoreCase) &&
                   key.EndsWith("|serial", StringComparison.OrdinalIgnoreCase);
        }

        private static bool DiskIdentitySiblingsStable(string serialKey, IDictionary<string, string> current, IDictionary<string, string> baseline)
        {
            if (string.IsNullOrWhiteSpace(serialKey) || current == null || baseline == null)
            {
                return false;
            }

            string prefix = serialKey.Substring(0, serialKey.Length - "|serial".Length);
            string[] siblingSuffixes = { "|model", "|vendor", "|pnp" };
            bool sawStableSibling = false;
            foreach (string suffix in siblingSuffixes)
            {
                string sibling = prefix + suffix;
                string currentValue;
                string baselineValue;
                if (!current.TryGetValue(sibling, out currentValue) || !baseline.TryGetValue(sibling, out baselineValue))
                {
                    continue;
                }

                if (!string.Equals(currentValue, baselineValue, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                sawStableSibling = true;
            }

            return sawStableSibling;
        }

        private static EventSeverity SeverityForBaselineKey(string key)
        {
            if (key.IndexOf("|serial", StringComparison.OrdinalIgnoreCase) >= 0 ||
                key.IndexOf("|mac", StringComparison.OrdinalIgnoreCase) >= 0 ||
                key.IndexOf("|uuid", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return EventSeverity.High;
            }

            return EventSeverity.Medium;
        }

        private static Dictionary<string, string> DiskDetails(params DiskIdentityRecord[] disks)
        {
            Dictionary<string, string> details = new Dictionary<string, string>();
            for (int i = 0; i < disks.Length; i++)
            {
                DiskIdentityRecord disk = disks[i];
                string prefix = "disk_" + i.ToString(CultureInfo.InvariantCulture) + "_";
                details[prefix + "source"] = disk.Source ?? string.Empty;
                details[prefix + "device_id"] = disk.DeviceId ?? string.Empty;
                details[prefix + "index"] = disk.Index ?? string.Empty;
                details[prefix + "model"] = disk.Model ?? string.Empty;
                details[prefix + "vendor"] = disk.Vendor ?? string.Empty;
                details[prefix + "serial"] = disk.Serial ?? string.Empty;
                details[prefix + "pnp_device_id"] = disk.PnpDeviceId ?? string.Empty;
                details[prefix + "registry_path"] = disk.RegistryPath ?? string.Empty;
            }

            return details;
        }

        private static Dictionary<string, string> NetworkDetails(params NetworkIdentityRecord[] adapters)
        {
            Dictionary<string, string> details = new Dictionary<string, string>();
            for (int i = 0; i < adapters.Length; i++)
            {
                NetworkIdentityRecord adapter = adapters[i];
                string prefix = "adapter_" + i.ToString(CultureInfo.InvariantCulture) + "_";
                details[prefix + "source"] = adapter.Source ?? string.Empty;
                details[prefix + "name"] = adapter.Name ?? string.Empty;
                details[prefix + "description"] = adapter.Description ?? string.Empty;
                details[prefix + "adapter_id"] = adapter.AdapterId ?? string.Empty;
                details[prefix + "pnp_device_id"] = adapter.PnpDeviceId ?? string.Empty;
                details[prefix + "mac"] = adapter.MacAddress ?? string.Empty;
                details[prefix + "registry_path"] = adapter.RegistryPath ?? string.Empty;
                details[prefix + "is_virtual"] = adapter.IsVirtual.ToString();
                details[prefix + "is_locally_administered"] = adapter.IsLocallyAdministered.ToString();
            }

            return details;
        }

        private static Dictionary<string, string> SystemDetails(params SystemIdentityRecord[] systems)
        {
            Dictionary<string, string> details = new Dictionary<string, string>();
            for (int i = 0; i < systems.Length; i++)
            {
                SystemIdentityRecord system = systems[i];
                string prefix = "system_" + i.ToString(CultureInfo.InvariantCulture) + "_";
                details[prefix + "source"] = system.Source ?? string.Empty;
                details[prefix + "bios_vendor"] = system.BiosVendor ?? string.Empty;
                details[prefix + "bios_version"] = system.BiosVersion ?? string.Empty;
                details[prefix + "bios_serial"] = system.BiosSerial ?? string.Empty;
                details[prefix + "baseboard_vendor"] = system.BaseboardVendor ?? string.Empty;
                details[prefix + "baseboard_product"] = system.BaseboardProduct ?? string.Empty;
                details[prefix + "baseboard_serial"] = system.BaseboardSerial ?? string.Empty;
                details[prefix + "system_vendor"] = system.SystemVendor ?? string.Empty;
                details[prefix + "system_product"] = system.SystemProduct ?? string.Empty;
                details[prefix + "system_uuid"] = system.SystemUuid ?? string.Empty;
                details[prefix + "firmware_hash"] = system.FirmwareHash ?? string.Empty;
                details[prefix + "hypervisor_present"] = system.HypervisorPresent ?? string.Empty;
            }

            return details;
        }

        private static Dictionary<string, string> GpuDetails(params GpuIdentityRecord[] gpus)
        {
            Dictionary<string, string> details = new Dictionary<string, string>();
            for (int i = 0; i < gpus.Length; i++)
            {
                GpuIdentityRecord gpu = gpus[i];
                string prefix = "gpu_" + i.ToString(CultureInfo.InvariantCulture) + "_";
                details[prefix + "source"] = gpu.Source ?? string.Empty;
                details[prefix + "name"] = gpu.Name ?? string.Empty;
                details[prefix + "vendor"] = gpu.Vendor ?? string.Empty;
                details[prefix + "pnp_device_id"] = gpu.PnpDeviceId ?? string.Empty;
                details[prefix + "device_id"] = gpu.DeviceId ?? string.Empty;
                details[prefix + "driver_version"] = gpu.DriverVersion ?? string.Empty;
                details[prefix + "driver_path"] = gpu.DriverPath ?? string.Empty;
                details[prefix + "signature_status"] = gpu.SignatureStatus ?? string.Empty;
                details[prefix + "signature_subject"] = gpu.SignatureSubject ?? string.Empty;
                details[prefix + "is_virtual"] = gpu.IsVirtual.ToString();
            }

            return details;
        }

        private static Dictionary<string, string> DeviceDetails(params DeviceStackRecord[] devices)
        {
            Dictionary<string, string> details = new Dictionary<string, string>();
            for (int i = 0; i < devices.Length; i++)
            {
                DeviceStackRecord device = devices[i];
                string prefix = "device_" + i.ToString(CultureInfo.InvariantCulture) + "_";
                details[prefix + "source"] = device.Source ?? string.Empty;
                details[prefix + "device_id"] = device.DeviceId ?? string.Empty;
                details[prefix + "name"] = device.Name ?? string.Empty;
                details[prefix + "pnp_class"] = device.PnpClass ?? string.Empty;
                details[prefix + "class_guid"] = device.ClassGuid ?? string.Empty;
                details[prefix + "manufacturer"] = device.Manufacturer ?? string.Empty;
                details[prefix + "service"] = device.Service ?? string.Empty;
                details[prefix + "driver"] = device.Driver ?? string.Empty;
                details[prefix + "status"] = device.Status ?? string.Empty;
                details[prefix + "registry_path"] = device.RegistryPath ?? string.Empty;
                details[prefix + "upper_filters"] = device.UpperFilters ?? string.Empty;
                details[prefix + "lower_filters"] = device.LowerFilters ?? string.Empty;
                details[prefix + "is_virtual"] = device.IsVirtual.ToString();
            }

            return details;
        }

        private static Dictionary<string, string> MergeDetails(params Dictionary<string, string>[] maps)
        {
            Dictionary<string, string> merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (maps == null)
            {
                return merged;
            }

            foreach (Dictionary<string, string> map in maps)
            {
                if (map == null)
                {
                    continue;
                }

                foreach (KeyValuePair<string, string> pair in map)
                {
                    string key = pair.Key;
                    int suffix = 1;
                    while (merged.ContainsKey(key))
                    {
                        suffix++;
                        key = pair.Key + "_" + suffix.ToString(CultureInfo.InvariantCulture);
                    }

                    merged[key] = pair.Value;
                }
            }

            return merged;
        }

        private static bool ContainsAny(string value, params string[] terms)
        {
            if (string.IsNullOrWhiteSpace(value) || terms == null)
            {
                return false;
            }

            foreach (string term in terms)
            {
                if (!string.IsNullOrWhiteSpace(term) && value.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        private static string SanitizeFileName(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return "snapshot";
            }

            char[] invalid = Path.GetInvalidFileNameChars();
            StringBuilder builder = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                builder.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
            }

            return builder.ToString();
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
    }
}
