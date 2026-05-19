using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Windows.Forms;
using AnyWhere.Telemetry;

namespace AnyWhere
{
    internal static class Program
    {
        private static readonly ManualResetEventSlim Shutdown = new ManualResetEventSlim(false);

        [STAThread]
        private static void Main(string[] args)
        {
            if (args != null && args.Any(a => string.Equals(a, "--platform-self-test", StringComparison.OrdinalIgnoreCase)))
            {
                RunPlatformSelfTest(args);
                return;
            }

            MonitorOptions options = MonitorOptions.FromArgs(args);
            string logRoot = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Aegis Logs");
            Directory.CreateDirectory(logRoot);

            using (EventLogger logger = new EventLogger(logRoot, options.VerboseConsole))
            {
                Console.Title = "Aegis Anywhere Detection Monitor";
                PrintBanner(logger);

                SecurityUtilities.TryEnableDebugPrivilege(logger);

                EvidenceDatabaseMonitor evidenceDatabaseMonitor = new EvidenceDatabaseMonitor(logger, options);
                List<IDetectionMonitor> monitors = new List<IDetectionMonitor>
                {
                    evidenceDatabaseMonitor,
                    new RealTimeDetectionEngine(logger, options),
                    new BaselineLearningMonitor(logger, options),
                    new ProcessActivityMonitor(logger, options),
                    new EventLogActivityMonitor(logger, options),
                    new FileActivityMonitor(logger, options),
                    new RegistryActivityMonitor(logger, options),
                    new HiddenKernelArtifactDetector(logger, options),
                    new TransientDriverMappingDetector(logger, options),
                    new HardwareIdentityCrossValidator(logger, options),
                    new HardwareIdentityIntegrityMonitor(logger, options),
                    new TargetProcessInteractionMonitor(logger, options),
                    new KernelCommunicationSurfaceDetector(logger, options),
                    new TrustedProcessAbuseMonitor(logger, options),
                    new NativeAbuseMonitor(logger, options),
                    new DefensiveIntegrityMonitor(logger, options),
                    new BehavioralProfileMonitor(logger, options),
                    new ReputationMonitor(logger, options),
                    new SessionEngine(logger, options),
                    new ActiveCaptureMonitor(logger, options),
                    new MappedMemoryScanner(logger, options)
                };

                Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs eventArgs)
                {
                    eventArgs.Cancel = true;
                    Shutdown.Set();
                };

                try
                {
                    foreach (IDetectionMonitor monitor in monitors)
                    {
                        monitor.Start();
                    }

                    logger.Log(DetectionEvent.Create(
                        "Monitor",
                        "Started",
                        EventSeverity.Low,
                        "Aegis Anywhere detection monitor is running.",
                        null,
                        null,
                        new Dictionary<string, string>
                        {
                            { "log_directory", logRoot },
                            { "map_scan_interval_seconds", options.MapScanInterval.TotalSeconds.ToString("0") },
                            { "kernel_artifact_scan_interval_seconds", options.KernelArtifactScanInterval.TotalSeconds.ToString("0") },
                            { "identity_scan_interval_seconds", options.IdentityScanInterval.TotalSeconds.ToString("0") },
                            { "hwid_integrity_enabled", options.HardwareIdentityIntegrityEnabled.ToString() },
                            { "hwid_integrity_scan_interval_seconds", options.HardwareIdentityIntegrityScanInterval.TotalSeconds.ToString("0") },
                            { "target_interaction_scan_interval_seconds", options.TargetInteractionScanInterval.TotalSeconds.ToString("0") },
                            { "kernel_communication_scan_interval_seconds", options.KernelCommunicationScanInterval.TotalSeconds.ToString("0") },
                            { "defensive_integrity_enabled", options.DefensiveIntegrityEnabled.ToString() },
                            { "defensive_integrity_scan_interval_seconds", options.DefensiveIntegrityScanInterval.TotalSeconds.ToString("0") },
                            { "behavioral_profiling_enabled", options.BehavioralProfilingEnabled.ToString() },
                            { "behavioral_profile_window_minutes", options.BehavioralProfileWindow.TotalMinutes.ToString("0") },
                            { "reputation_enabled", options.ReputationEnabled.ToString() },
                            { "evidence_database_enabled", options.EvidenceDatabaseEnabled.ToString() },
                            { "investigation_ui_enabled", options.InvestigationUiEnabled.ToString() },
                            { "detection_profile", options.DetectionProfileName },
                            { "active_capture_enabled", options.ActiveCaptureEnabled.ToString() },
                            { "active_capture_cooldown_seconds", options.ActiveCaptureCooldown.TotalSeconds.ToString("0") },
                            { "watch_all_fixed_drives", options.WatchAllFixedDrives.ToString() },
                            { "emit_initial_mapped_files", options.EmitInitialMappedFiles.ToString() }
                        }));

                    if (options.InvestigationUiEnabled && options.EvidenceDatabaseEnabled)
                    {
                        Application.EnableVisualStyles();
                        Application.SetCompatibleTextRenderingDefault(false);
                        Application.Run(new InvestigationForm(evidenceDatabaseMonitor.Database));
                        Shutdown.Set();
                    }
                    else
                    {
                        WaitForExit();
                    }
                }
                finally
                {
                    logger.Log(DetectionEvent.Create(
                        "Monitor",
                        "Stopping",
                        EventSeverity.Low,
                        "Stopping detection monitors.",
                        null,
                        null,
                        null));

                    for (int i = monitors.Count - 1; i >= 0; i--)
                    {
                        try
                        {
                            monitors[i].Dispose();
                        }
                        catch (Exception ex)
                        {
                            logger.LogException("Monitor", "DisposeFailed", ex, monitors[i].Name);
                        }
                    }
                }
            }
        }

        private static void WaitForExit()
        {
            while (!Shutdown.Wait(500))
            {
                try
                {
                    if (Console.KeyAvailable)
                    {
                        ConsoleKeyInfo key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.Q || key.Key == ConsoleKey.Escape)
                        {
                            Shutdown.Set();
                        }
                    }
                }
                catch (InvalidOperationException)
                {
                    Thread.Sleep(500);
                }
            }
        }

        private static void PrintBanner(EventLogger logger)
        {
            Console.WriteLine("Aegis Anywhere Detection Monitor");
            Console.WriteLine("Press Q, Esc, or Ctrl+C to stop.");
            Console.WriteLine();

            logger.Log(DetectionEvent.Create(
                "Monitor",
                "Initialized",
                EventSeverity.Low,
                "Logger initialized.",
                null,
                null,
                null));
        }

        private static void RunPlatformSelfTest(string[] args)
        {
            MonitorOptions options = MonitorOptions.FromArgs(args);
            string logRoot = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Aegis Logs");
            Directory.CreateDirectory(logRoot);

            using (EventLogger logger = new EventLogger(logRoot, false))
            {
                string databasePath = string.IsNullOrWhiteSpace(options.EvidenceDatabasePath)
                    ? Path.Combine(logRoot, "AegisEvidence.selftest.db")
                    : options.EvidenceDatabasePath;
                EvidenceDatabase database = new EvidenceDatabase(databasePath);
                database.Initialize();

                DetectionEvent detectionEvent = DetectionEvent.Create(
                    "SelfTest",
                    "PlatformSelfTest",
                    EventSeverity.Medium,
                    "SQLite evidence database and detection-platform dependencies initialized.",
                    databasePath,
                    null,
                    new Dictionary<string, string>
                    {
                        { "case_id", "SELFTEST-" + DateTime.UtcNow.ToString("yyyyMMddHHmmss") },
                        { "confidence_score", "0.50" },
                        { "case_summary", "Platform self-test event." }
                    });

                long eventId = database.InsertEvent(detectionEvent);
                logger.Log(detectionEvent);
                Console.WriteLine("Platform self-test succeeded.");
                Console.WriteLine("Database: " + database.DatabasePath);
                Console.WriteLine("Inserted event id: " + eventId.ToString());
            }
        }
    }
}
