using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace AnyWhere.Telemetry
{
    internal sealed class MonitorOptions
    {
        public TimeSpan MapScanInterval { get; private set; }

        public TimeSpan KernelArtifactScanInterval { get; private set; }

        public TimeSpan IdentityScanInterval { get; private set; }

        public TimeSpan HardwareIdentityIntegrityScanInterval { get; private set; }

        public TimeSpan TargetInteractionScanInterval { get; private set; }

        public TimeSpan KernelCommunicationScanInterval { get; private set; }

        public TimeSpan ActiveCaptureCooldown { get; private set; }

        public TimeSpan DefensiveIntegrityScanInterval { get; private set; }

        public TimeSpan BehavioralProfileWindow { get; private set; }

        public bool ReputationEnabled { get; private set; }

        public bool HardwareIdentityIntegrityEnabled { get; private set; }

        public bool WatchAllFixedDrives { get; private set; }

        public bool EmitInitialMappedFiles { get; private set; }

        public bool ActiveCaptureEnabled { get; private set; }

        public bool DefensiveIntegrityEnabled { get; private set; }

        public bool BehavioralProfilingEnabled { get; private set; }

        public bool EvidenceArchiveEnabled { get; private set; }

        public bool EvidenceDatabaseEnabled { get; private set; }

        public bool InvestigationUiEnabled { get; private set; }

        public bool KernelSensorAutoLoadEnabled { get; private set; }

        public bool VerboseConsole { get; private set; }

        public bool ReplayIncludeDerivedEvents { get; private set; }

        public bool ReplayRebaseTimestamps { get; private set; }

        public long MaxHashBytes { get; private set; }

        public int MaxRegistryDiffEventsPerBurst { get; private set; }

        public int MaxDeviceHandlesToInspect { get; private set; }

        public int MaxProcessHandlesToInspect { get; private set; }

        public int MaxKernelCommunicationHandlesToInspect { get; private set; }

        public int ActiveCaptureMaxHandlesToInspect { get; private set; }

        public int ActiveCaptureMaxMemoryRegionsPerProcess { get; private set; }

        public int ActiveCaptureEventLogMinutes { get; private set; }

        public int MaxSelfHandleScan { get; private set; }

        public double BehavioralSimilarityThreshold { get; private set; }

        public string EvidenceMirrorPath { get; private set; }

        public string ReputationExportPath { get; private set; }

        public string EvidenceDatabasePath { get; private set; }

        public string DetectionProfileName { get; private set; }

        public string ReplayOutputPath { get; private set; }

        public string ReplayExpectationPath { get; private set; }

        public string ExportCaseId { get; private set; }

        public string ExportOutputPath { get; private set; }

        public string KernelSensorDriverPath { get; private set; }

        public string KernelSensorServiceName { get; private set; }

        public List<string> ProtectedProcessNames { get; private set; }

        public List<string> ReputationImportPaths { get; private set; }

        public List<string> ReplayInputPaths { get; private set; }

        public List<string> ReputationMarks { get; private set; }

        public List<string> CaseStatusUpdates { get; private set; }

        public List<string> CaseNotes { get; private set; }

        public List<string> CaseTags { get; private set; }

        private MonitorOptions()
        {
            MapScanInterval = TimeSpan.FromSeconds(15);
            KernelArtifactScanInterval = TimeSpan.FromSeconds(30);
            IdentityScanInterval = TimeSpan.FromSeconds(60);
            HardwareIdentityIntegrityScanInterval = TimeSpan.FromSeconds(60);
            TargetInteractionScanInterval = TimeSpan.FromSeconds(5);
            KernelCommunicationScanInterval = TimeSpan.FromSeconds(5);
            ActiveCaptureCooldown = TimeSpan.FromMinutes(3);
            DefensiveIntegrityScanInterval = TimeSpan.FromSeconds(15);
            BehavioralProfileWindow = TimeSpan.FromMinutes(10);
            WatchAllFixedDrives = false;
            EmitInitialMappedFiles = false;
            ActiveCaptureEnabled = true;
            DefensiveIntegrityEnabled = true;
            BehavioralProfilingEnabled = true;
            ReputationEnabled = true;
            HardwareIdentityIntegrityEnabled = true;
            EvidenceArchiveEnabled = false;
            EvidenceDatabaseEnabled = true;
            InvestigationUiEnabled = false;
            KernelSensorAutoLoadEnabled = false;
            VerboseConsole = true;
            ReplayIncludeDerivedEvents = false;
            ReplayRebaseTimestamps = false;
            MaxHashBytes = 100L * 1024L * 1024L;
            MaxRegistryDiffEventsPerBurst = 100;
            MaxDeviceHandlesToInspect = 2000;
            MaxProcessHandlesToInspect = 50000;
            MaxKernelCommunicationHandlesToInspect = 50000;
            ActiveCaptureMaxHandlesToInspect = 50000;
            ActiveCaptureMaxMemoryRegionsPerProcess = 256;
            ActiveCaptureEventLogMinutes = 15;
            MaxSelfHandleScan = 50000;
            BehavioralSimilarityThreshold = 0.58;
            EvidenceMirrorPath = null;
            ReputationExportPath = null;
            EvidenceDatabasePath = null;
            DetectionProfileName = "balanced";
            ReplayOutputPath = null;
            ReplayExpectationPath = null;
            ExportCaseId = null;
            ExportOutputPath = null;
            KernelSensorDriverPath = null;
            KernelSensorServiceName = null;
            ReputationImportPaths = new List<string>();
            ReplayInputPaths = new List<string>();
            ReputationMarks = new List<string>();
            CaseStatusUpdates = new List<string>();
            CaseNotes = new List<string>();
            CaseTags = new List<string>();
            ProtectedProcessNames = new List<string>
            {
                "Game.exe",
                "UnityPlayer.exe",
                "UnrealEditor.exe",
                "*-Win64-Shipping.exe",
                "*Shipping.exe",
                "cod.exe",
                "FortniteClient-Win64-Shipping.exe",
                "r5apex.exe",
                "VALORANT-Win64-Shipping.exe",
                "cs2.exe"
            };
        }

        public static MonitorOptions FromArgs(string[] args)
        {
            MonitorOptions options = new MonitorOptions();

            if (args == null)
            {
                return options;
            }

            foreach (string rawArg in args)
            {
                string arg = rawArg ?? string.Empty;
                if (arg.Equals("--watch-all-fixed-drives", StringComparison.OrdinalIgnoreCase))
                {
                    options.WatchAllFixedDrives = true;
                }
                else if (arg.Equals("--emit-initial-mapped-files", StringComparison.OrdinalIgnoreCase))
                {
                    options.EmitInitialMappedFiles = true;
                }
                else if (arg.Equals("--quiet", StringComparison.OrdinalIgnoreCase))
                {
                    options.VerboseConsole = false;
                }
                else if (arg.Equals("--disable-active-capture", StringComparison.OrdinalIgnoreCase))
                {
                    options.ActiveCaptureEnabled = false;
                }
                else if (arg.Equals("--disable-defensive-integrity", StringComparison.OrdinalIgnoreCase))
                {
                    options.DefensiveIntegrityEnabled = false;
                }
                else if (arg.Equals("--disable-behavioral-profiling", StringComparison.OrdinalIgnoreCase))
                {
                    options.BehavioralProfilingEnabled = false;
                }
                else if (arg.Equals("--disable-reputation", StringComparison.OrdinalIgnoreCase))
                {
                    options.ReputationEnabled = false;
                }
                else if (arg.Equals("--disable-hwid-integrity", StringComparison.OrdinalIgnoreCase))
                {
                    options.HardwareIdentityIntegrityEnabled = false;
                }
                else if (arg.Equals("--archive-cases", StringComparison.OrdinalIgnoreCase))
                {
                    options.EvidenceArchiveEnabled = true;
                }
                else if (arg.Equals("--disable-evidence-db", StringComparison.OrdinalIgnoreCase))
                {
                    options.EvidenceDatabaseEnabled = false;
                }
                else if (arg.Equals("--ui", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("--gui", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("--investigation-ui", StringComparison.OrdinalIgnoreCase))
                {
                    options.InvestigationUiEnabled = true;
                }
                else if (arg.Equals("--console", StringComparison.OrdinalIgnoreCase))
                {
                    options.InvestigationUiEnabled = false;
                }
                else if (arg.Equals("--auto-load-kernel-sensor", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("--autoload-kernel-sensor", StringComparison.OrdinalIgnoreCase))
                {
                    options.KernelSensorAutoLoadEnabled = true;
                }
                else if (arg.Equals("--replay-include-derived", StringComparison.OrdinalIgnoreCase))
                {
                    options.ReplayIncludeDerivedEvents = true;
                }
                else if (arg.Equals("--replay-rebase-timestamps", StringComparison.OrdinalIgnoreCase))
                {
                    options.ReplayRebaseTimestamps = true;
                }
                else if (arg.StartsWith("--map-scan-seconds=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--map-scan-seconds=".Length);
                    int seconds;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds) && seconds >= 3)
                    {
                        options.MapScanInterval = TimeSpan.FromSeconds(seconds);
                    }
                }
                else if (arg.StartsWith("--kernel-scan-seconds=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--kernel-scan-seconds=".Length);
                    int seconds;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds) && seconds >= 10)
                    {
                        options.KernelArtifactScanInterval = TimeSpan.FromSeconds(seconds);
                    }
                }
                else if (arg.StartsWith("--identity-scan-seconds=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--identity-scan-seconds=".Length);
                    int seconds;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds) && seconds >= 15)
                    {
                        options.IdentityScanInterval = TimeSpan.FromSeconds(seconds);
                    }
                }
                else if (arg.StartsWith("--hwid-integrity-scan-seconds=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--hwid-integrity-scan-seconds=".Length);
                    int seconds;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds) && seconds >= 15)
                    {
                        options.HardwareIdentityIntegrityScanInterval = TimeSpan.FromSeconds(seconds);
                    }
                }
                else if (arg.StartsWith("--target-scan-seconds=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--target-scan-seconds=".Length);
                    int seconds;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds) && seconds >= 2)
                    {
                        options.TargetInteractionScanInterval = TimeSpan.FromSeconds(seconds);
                    }
                }
                else if (arg.StartsWith("--kernel-comm-scan-seconds=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--kernel-comm-scan-seconds=".Length);
                    int seconds;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds) && seconds >= 2)
                    {
                        options.KernelCommunicationScanInterval = TimeSpan.FromSeconds(seconds);
                    }
                }
                else if (arg.StartsWith("--defensive-integrity-scan-seconds=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--defensive-integrity-scan-seconds=".Length);
                    int seconds;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds) && seconds >= 5)
                    {
                        options.DefensiveIntegrityScanInterval = TimeSpan.FromSeconds(seconds);
                    }
                }
                else if (arg.StartsWith("--behavior-window-minutes=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--behavior-window-minutes=".Length);
                    int minutes;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out minutes) && minutes >= 1)
                    {
                        options.BehavioralProfileWindow = TimeSpan.FromMinutes(minutes);
                    }
                }
                else if (arg.StartsWith("--behavior-similarity-threshold=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--behavior-similarity-threshold=".Length);
                    double threshold;
                    if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out threshold) && threshold >= 0 && threshold <= 1)
                    {
                        options.BehavioralSimilarityThreshold = threshold;
                    }
                }
                else if (arg.StartsWith("--max-device-handles=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--max-device-handles=".Length);
                    int handles;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out handles) && handles >= 0)
                    {
                        options.MaxDeviceHandlesToInspect = handles;
                    }
                }
                else if (arg.StartsWith("--max-process-handles=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--max-process-handles=".Length);
                    int handles;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out handles) && handles >= 0)
                    {
                        options.MaxProcessHandlesToInspect = handles;
                    }
                }
                else if (arg.StartsWith("--max-kernel-comm-handles=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--max-kernel-comm-handles=".Length);
                    int handles;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out handles) && handles >= 0)
                    {
                        options.MaxKernelCommunicationHandlesToInspect = handles;
                    }
                }
                else if (arg.StartsWith("--max-active-capture-handles=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--max-active-capture-handles=".Length);
                    int handles;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out handles) && handles >= 0)
                    {
                        options.ActiveCaptureMaxHandlesToInspect = handles;
                    }
                }
                else if (arg.StartsWith("--max-self-handle-scan=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--max-self-handle-scan=".Length);
                    int handles;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out handles) && handles >= 0)
                    {
                        options.MaxSelfHandleScan = handles;
                    }
                }
                else if (arg.StartsWith("--active-capture-cooldown-seconds=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--active-capture-cooldown-seconds=".Length);
                    int seconds;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out seconds) && seconds >= 30)
                    {
                        options.ActiveCaptureCooldown = TimeSpan.FromSeconds(seconds);
                    }
                }
                else if (arg.StartsWith("--active-capture-event-log-minutes=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--active-capture-event-log-minutes=".Length);
                    int minutes;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out minutes) && minutes >= 1)
                    {
                        options.ActiveCaptureEventLogMinutes = minutes;
                    }
                }
                else if (arg.StartsWith("--active-capture-max-memory-regions=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--active-capture-max-memory-regions=".Length);
                    int regions;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out regions) && regions >= 0)
                    {
                        options.ActiveCaptureMaxMemoryRegionsPerProcess = regions;
                    }
                }
                else if (arg.StartsWith("--protected-process=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--protected-process=".Length);
                    foreach (string part in value.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                    {
                        string processName = part.Trim();
                        if (!string.IsNullOrWhiteSpace(processName) && !options.ProtectedProcessNames.Contains(processName, StringComparer.OrdinalIgnoreCase))
                        {
                            options.ProtectedProcessNames.Add(processName);
                        }
                    }
                }
                else if (arg.StartsWith("--evidence-mirror=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--evidence-mirror=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.EvidenceMirrorPath = value;
                    }
                }
                else if (arg.StartsWith("--reputation-import=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--reputation-import=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.ReputationImportPaths.Add(value);
                    }
                }
                else if (arg.StartsWith("--reputation-export=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--reputation-export=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.ReputationExportPath = value;
                    }
                }
                else if (arg.StartsWith("--reputation-mark=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--reputation-mark=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.ReputationMarks.Add(value);
                    }
                }
                else if (arg.StartsWith("--database=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--database=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.EvidenceDatabasePath = value;
                    }
                }
                else if (arg.StartsWith("--kernel-sensor-driver=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--kernel-sensor-driver=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.KernelSensorDriverPath = value;
                        options.KernelSensorAutoLoadEnabled = true;
                    }
                }
                else if (arg.StartsWith("--kernel-sensor-service=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--kernel-sensor-service=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.KernelSensorServiceName = value;
                    }
                }
                else if (arg.StartsWith("--replay=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--replay=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.ReplayInputPaths.Add(value);
                    }
                }
                else if (arg.StartsWith("--replay-input=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--replay-input=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.ReplayInputPaths.Add(value);
                    }
                }
                else if (arg.StartsWith("--replay-output=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--replay-output=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.ReplayOutputPath = value;
                    }
                }
                else if (arg.StartsWith("--replay-expect=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--replay-expect=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.ReplayExpectationPath = value;
                    }
                }
                else if (arg.StartsWith("--replay-expectations=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--replay-expectations=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.ReplayExpectationPath = value;
                    }
                }
                else if (arg.StartsWith("--export-case=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--export-case=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.ExportCaseId = value;
                    }
                }
                else if (arg.StartsWith("--export-output=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--export-output=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.ExportOutputPath = value;
                    }
                }
                else if (arg.StartsWith("--detection-profile=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--detection-profile=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.DetectionProfileName = value;
                    }
                }
                else if (arg.StartsWith("--case-status=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--case-status=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.CaseStatusUpdates.Add(value);
                    }
                }
                else if (arg.StartsWith("--case-note=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--case-note=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.CaseNotes.Add(value);
                    }
                }
                else if (arg.StartsWith("--case-tag=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--case-tag=".Length).Trim().Trim('"');
                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        options.CaseTags.Add(value);
                    }
                }
                else if (arg.StartsWith("--max-hash-mb=", StringComparison.OrdinalIgnoreCase))
                {
                    string value = arg.Substring("--max-hash-mb=".Length);
                    int megabytes;
                    if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out megabytes) && megabytes > 0)
                    {
                        options.MaxHashBytes = (long)megabytes * 1024L * 1024L;
                    }
                }
            }

            return options;
        }
    }
}
