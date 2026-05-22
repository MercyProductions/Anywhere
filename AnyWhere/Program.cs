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
        private static bool gui;

        internal static bool Gui
        {
            get { return gui; }
        }

        [STAThread]
        private static void Main(string[] args)
        {
            if (args != null && args.Any(a => string.Equals(a, "--platform-self-test", StringComparison.OrdinalIgnoreCase)))
            {
                RunPlatformSelfTest(args);
                return;
            }

            MonitorOptions options = MonitorOptions.FromArgs(args);
            if (!string.IsNullOrWhiteSpace(options.ExportCaseId))
            {
                RunCaseExport(options);
                return;
            }

            if (options.ReplayInputPaths.Count > 0)
            {
                RunReplay(options);
                return;
            }

            gui = options.InvestigationUiEnabled;
            if (gui)
            {
                RunGuiApplication(options);
            }
            else
            {
                RunConsoleApplication(options);
            }
        }

        private static void RunGuiApplication(MonitorOptions options)
        {
            RunLiveApplication(options, true);
        }

        private static void RunConsoleApplication(MonitorOptions options)
        {
            RunLiveApplication(options, false);
        }

        private static void RunLiveApplication(MonitorOptions options, bool runGui)
        {
            string logRoot = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Aegis Logs");
            Directory.CreateDirectory(logRoot);

            using (EventLogger logger = new EventLogger(logRoot, options.VerboseConsole))
            {
                Console.Title = "Aegis Anywhere Detection Monitor";
                PrintBanner(logger);

                SecurityUtilities.TryEnableDebugPrivilege(logger);
                LogKernelSensorAutoLoad(logger, KernelSensorServiceManager.EnsureStarted(options));

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
                            { "gui_enabled", gui.ToString() },
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

                    if (runGui && options.EvidenceDatabaseEnabled)
                    {
                        RunInvestigationGui(evidenceDatabaseMonitor.Database);
                    }
                    else if (runGui)
                    {
                        logger.Log(DetectionEvent.Create(
                            "Monitor",
                            "GuiUnavailable",
                            EventSeverity.Medium,
                            "GUI mode was requested, but the evidence database is disabled. Continuing in console mode.",
                            null,
                            null,
                            null));
                        WaitForExit();
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

        private static void RunInvestigationGui(EvidenceDatabase database)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new InvestigationForm(database));
            Shutdown.Set();
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

        private static void LogKernelSensorAutoLoad(EventLogger logger, KernelSensorLoadResult result)
        {
            if (logger == null || result == null || !result.Requested)
            {
                return;
            }

            string action = result.Success ? "AutoLoadSucceeded" : "AutoLoadUnavailable";
            EventSeverity severity = result.Success ? EventSeverity.Low : EventSeverity.Medium;
            logger.Log(DetectionEvent.Create(
                "KernelSensor",
                action,
                severity,
                result.Message,
                result.DriverPath,
                null,
                new Dictionary<string, string>
                {
                    { "status", result.Status ?? string.Empty },
                    { "service_name", result.ServiceName ?? string.Empty },
                    { "driver_path", result.DriverPath ?? string.Empty },
                    { "error_code", result.ErrorCode.ToString() },
                    { "last_service_state", result.LastServiceState.ToString() },
                    { "win32_exit_code", result.Win32ExitCode.ToString() },
                    { "service_specific_exit_code", result.ServiceSpecificExitCode.ToString() },
                    { "service_created", result.ServiceCreated.ToString() },
                    { "existing_service", result.ExistingService.ToString() },
                    { "configuration_updated", result.ConfigurationUpdated.ToString() },
                    { "start_requested", result.StartRequested.ToString() },
                    { "already_running", result.AlreadyRunning.ToString() },
                    { "fallback_behavior", result.Success ? "kernel_sensor_available" : "continuing_user_mode_monitoring" },
                    { "safety_rule", "SCM service loading only. No mapper, vulnerable-driver, unsigned-driver, or signature-bypass fallback is used." }
                }));
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

        private static void RunCaseExport(MonitorOptions options)
        {
            string databasePath = ResolveEvidenceDatabasePath(options);
            Console.Title = "Aegis Anywhere Case Export";
            Console.WriteLine("Aegis Anywhere Case Export");
            Console.WriteLine("Case: " + options.ExportCaseId);
            Console.WriteLine("Database: " + databasePath);
            Console.WriteLine();

            if (!File.Exists(databasePath))
            {
                Console.Error.WriteLine("Evidence database was not found: " + databasePath);
                Environment.ExitCode = 2;
                return;
            }

            try
            {
                EvidenceDatabase database = new EvidenceDatabase(databasePath);
                database.Initialize();
                CaseExportResult result = CaseExportBundleWriter.Export(database, options.ExportCaseId, options.ExportOutputPath);

                Console.WriteLine("Case export complete.");
                Console.WriteLine("Folder: " + result.FolderPath);
                Console.WriteLine("Archive: " + (string.IsNullOrWhiteSpace(result.ArchivePath) ? "(not created)" : result.ArchivePath));
                Console.WriteLine("Manifest: " + result.ManifestPath);
                Console.WriteLine("Events: " + result.EventCount.ToString());
                Console.WriteLine("Artifacts: " + result.ArtifactCount.ToString());
                Console.WriteLine("Notes: " + result.NoteCount.ToString());
                Console.WriteLine("Tags: " + result.TagCount.ToString());
                if (!string.IsNullOrWhiteSpace(result.MirroredEvidenceFolder))
                {
                    Console.WriteLine("Mirrored evidence: " + result.MirroredEvidenceFolder);
                }
            }
            catch (InvalidOperationException ex)
            {
                Console.Error.WriteLine(ex.Message);
                Environment.ExitCode = 2;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Case export failed: " + ex.Message);
                Environment.ExitCode = 1;
            }
        }

        private static void RunReplay(MonitorOptions options)
        {
            string outputRoot = ResolveReplayOutputRoot(options);
            Directory.CreateDirectory(outputRoot);

            using (EventLogger logger = new EventLogger(outputRoot, options.VerboseConsole))
            {
                Console.Title = "Aegis Anywhere Detection Replay";
                Console.WriteLine("Aegis Anywhere Detection Replay");
                Console.WriteLine("Output: " + outputRoot);
                Console.WriteLine();

                List<IDetectionMonitor> monitors = new List<IDetectionMonitor>
                {
                    new EvidenceDatabaseMonitor(logger, options),
                    new RealTimeDetectionEngine(logger, options),
                    new BaselineLearningMonitor(logger, options),
                    new BehavioralProfileMonitor(logger, options),
                    new ReputationMonitor(logger, options),
                    new SessionEngine(logger, options)
                };

                try
                {
                    foreach (IDetectionMonitor monitor in monitors)
                    {
                        monitor.Start();
                    }

                    DetectionReplayResult result = DetectionReplayRunner.Replay(options, logger);
                    Console.WriteLine();
                    Console.WriteLine("Replay complete.");
                    Console.WriteLine("Files read: " + result.FilesRead.ToString());
                    Console.WriteLine("Events replayed: " + result.ReplayedEvents.ToString());
                    if (result.ExpectationsEvaluated)
                    {
                        Console.WriteLine("Expectations: " + (result.ExpectationsPassed ? "PASS" : "FAIL"));
                        Console.WriteLine("Expectation report: " + result.ExpectationReportPath);
                        if (!result.ExpectationsPassed)
                        {
                            Environment.ExitCode = 2;
                        }
                    }

                    Console.WriteLine("Summary: " + result.SummaryPath);
                }
                finally
                {
                    for (int i = monitors.Count - 1; i >= 0; i--)
                    {
                        try
                        {
                            monitors[i].Dispose();
                        }
                        catch (Exception ex)
                        {
                            logger.LogException("Replay", "DisposeFailed", ex, monitors[i].Name);
                        }
                    }
                }
            }
        }

        private static string ResolveReplayOutputRoot(MonitorOptions options)
        {
            if (!string.IsNullOrWhiteSpace(options.ReplayOutputPath))
            {
                return Path.GetFullPath(options.ReplayOutputPath);
            }

            string stamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Aegis Logs", "Replay", stamp);
        }

        private static string ResolveEvidenceDatabasePath(MonitorOptions options)
        {
            if (options == null || string.IsNullOrWhiteSpace(options.EvidenceDatabasePath))
            {
                return Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Aegis Logs", "AegisEvidence.db"));
            }

            string path = options.EvidenceDatabasePath.Trim().Trim('"');
            if (string.IsNullOrWhiteSpace(Path.GetDirectoryName(path)))
            {
                path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, path);
            }

            return Path.GetFullPath(path);
        }
    }
}
