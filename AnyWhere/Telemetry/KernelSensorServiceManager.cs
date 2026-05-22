using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal static class KernelSensorServiceManager
    {
        private const uint ScManagerConnect = 0x0001;
        private const uint ScManagerCreateService = 0x0002;
        private const uint ServiceQueryStatus = 0x0004;
        private const uint ServiceChangeConfig = 0x0002;
        private const uint ServiceStart = 0x0010;
        private const uint ServiceKernelDriver = 0x00000001;
        private const uint ServiceDemandStart = 0x00000003;
        private const uint ServiceErrorNormal = 0x00000001;
        private const int ScStatusProcessInfo = 0;
        private const int ServiceStopped = 0x00000001;
        private const int ServiceRunning = 0x00000004;
        private const int ErrorServiceExists = 1073;
        private const int ErrorServiceAlreadyRunning = 1056;

        public static KernelSensorLoadResult EnsureStarted(MonitorOptions options)
        {
            KernelSensorLoadResult result = new KernelSensorLoadResult
            {
                Requested = options != null && options.KernelSensorAutoLoadEnabled,
                Success = false,
                Status = "skipped",
                Message = "Kernel sensor auto-load is disabled."
            };

            if (options == null || !options.KernelSensorAutoLoadEnabled)
            {
                return result;
            }

            string driverPath = ResolveDriverPath(options.KernelSensorDriverPath);
            result.DriverPath = driverPath;
            if (string.IsNullOrWhiteSpace(driverPath) || !File.Exists(driverPath))
            {
                result.Status = "driver_not_found";
                result.Message = "No kernel sensor driver was found in the configured or known development paths.";
                return result;
            }

            string serviceName = string.IsNullOrWhiteSpace(options.KernelSensorServiceName)
                ? Path.GetFileNameWithoutExtension(driverPath)
                : options.KernelSensorServiceName.Trim();
            result.ServiceName = serviceName;

            IntPtr scm = IntPtr.Zero;
            IntPtr service = IntPtr.Zero;
            try
            {
                scm = OpenSCManager(null, null, ScManagerConnect | ScManagerCreateService);
                if (scm == IntPtr.Zero)
                {
                    return FailWithLastError(result, "open_scm_failed", "OpenSCManagerW failed.");
                }

                service = CreateService(
                    scm,
                    serviceName,
                    serviceName,
                    ServiceStart | ServiceQueryStatus | ServiceChangeConfig,
                    ServiceKernelDriver,
                    ServiceDemandStart,
                    ServiceErrorNormal,
                    driverPath,
                    null,
                    IntPtr.Zero,
                    null,
                    null,
                    null);

                if (service == IntPtr.Zero)
                {
                    int createError = Marshal.GetLastWin32Error();
                    if (createError != ErrorServiceExists)
                    {
                        return Fail(result, "create_service_failed", createError, "CreateServiceW failed.");
                    }

                    service = OpenService(scm, serviceName, ServiceStart | ServiceQueryStatus | ServiceChangeConfig);
                    if (service == IntPtr.Zero)
                    {
                        return FailWithLastError(result, "open_service_failed", "OpenServiceW failed for an existing service.");
                    }

                    result.ExistingService = true;
                    if (!ChangeServiceConfig(
                        service,
                        ServiceKernelDriver,
                        ServiceDemandStart,
                        ServiceErrorNormal,
                        driverPath,
                        null,
                        IntPtr.Zero,
                        null,
                        null,
                        null,
                        null))
                    {
                        return FailWithLastError(result, "change_config_failed", "ChangeServiceConfigW failed for an existing service.");
                    }

                    result.ConfigurationUpdated = true;
                }
                else
                {
                    result.ServiceCreated = true;
                }

                if (!StartService(service, 0, IntPtr.Zero))
                {
                    int startError = Marshal.GetLastWin32Error();
                    if (startError != ErrorServiceAlreadyRunning)
                    {
                        return Fail(result, "start_service_failed", startError, "StartServiceW failed.");
                    }

                    result.AlreadyRunning = true;
                }
                else
                {
                    result.StartRequested = true;
                }

                if (!WaitForRunning(service, TimeSpan.FromSeconds(10), result))
                {
                    return result;
                }

                result.Success = true;
                result.Status = result.AlreadyRunning ? "already_running" : "running";
                result.Message = result.AlreadyRunning
                    ? "Kernel sensor service was already running."
                    : "Kernel sensor service started successfully.";
                return result;
            }
            finally
            {
                if (service != IntPtr.Zero)
                {
                    CloseServiceHandle(service);
                }

                if (scm != IntPtr.Zero)
                {
                    CloseServiceHandle(scm);
                }
            }
        }

        private static bool WaitForRunning(IntPtr service, TimeSpan timeout, KernelSensorLoadResult result)
        {
            DateTime deadline = DateTime.UtcNow.Add(timeout);
            SERVICE_STATUS_PROCESS status = new SERVICE_STATUS_PROCESS();
            int bytesNeeded;
            do
            {
                if (!QueryServiceStatusEx(
                    service,
                    ScStatusProcessInfo,
                    ref status,
                    Marshal.SizeOf(typeof(SERVICE_STATUS_PROCESS)),
                    out bytesNeeded))
                {
                    FailWithLastError(result, "query_status_failed", "QueryServiceStatusEx failed.");
                    return false;
                }

                result.LastServiceState = status.dwCurrentState;
                result.Win32ExitCode = status.dwWin32ExitCode;
                result.ServiceSpecificExitCode = status.dwServiceSpecificExitCode;

                if (status.dwCurrentState == ServiceRunning)
                {
                    return true;
                }

                if (status.dwCurrentState == ServiceStopped)
                {
                    result.Success = false;
                    result.Status = "service_stopped";
                    result.Message = "Kernel sensor service stopped during startup.";
                    return false;
                }

                Thread.Sleep(100);
            } while (DateTime.UtcNow < deadline);

            result.Success = false;
            result.Status = "start_timeout";
            result.Message = "Timed out waiting for the kernel sensor service to report SERVICE_RUNNING.";
            return false;
        }

        private static string ResolveDriverPath(string configuredPath)
        {
            if (!string.IsNullOrWhiteSpace(configuredPath))
            {
                string candidate = ExpandPath(configuredPath.Trim().Trim('"'));
                if (string.IsNullOrWhiteSpace(Path.GetDirectoryName(candidate)))
                {
                    candidate = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, candidate);
                }

                return Path.GetFullPath(candidate);
            }

            foreach (string candidate in CandidateDriverPaths())
            {
                if (!string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate))
                {
                    return Path.GetFullPath(candidate);
                }
            }

            return string.Empty;
        }

        private static IEnumerable<string> CandidateDriverPaths()
        {
            string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
            string currentDirectory = Environment.CurrentDirectory;
            string[] driverNames =
            {
                "AegisKernelSensor.sys",
                "AegisDriver2.sys"
            };

            foreach (string driverName in driverNames)
            {
                yield return Path.Combine(baseDirectory, driverName);
                yield return Path.Combine(currentDirectory, driverName);
                yield return Path.Combine(baseDirectory, "Drivers", driverName);
                yield return Path.Combine(currentDirectory, "Drivers", driverName);
            }

            yield return Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "..", "..", "DLL Injector", "AegisDriver2", "x64", "Release", "AegisDriver2.sys"));
            yield return Path.GetFullPath(Path.Combine(currentDirectory, "..", "DLL Injector", "AegisDriver2", "x64", "Release", "AegisDriver2.sys"));
        }

        private static KernelSensorLoadResult FailWithLastError(KernelSensorLoadResult result, string status, string message)
        {
            return Fail(result, status, Marshal.GetLastWin32Error(), message);
        }

        private static KernelSensorLoadResult Fail(KernelSensorLoadResult result, string status, int errorCode, string message)
        {
            result.Success = false;
            result.Status = status;
            result.ErrorCode = errorCode;
            result.Message = message + " " + DescribeWin32Error(errorCode);
            return result;
        }

        private static string DescribeWin32Error(int errorCode)
        {
            if (errorCode == 0)
            {
                return string.Empty;
            }

            string hint = string.Empty;
            if (errorCode == 5)
            {
                hint = " Run elevated.";
            }
            else if (errorCode == 577)
            {
                hint = " Windows rejected the driver signature.";
            }
            else if (errorCode == 1275)
            {
                hint = " Windows blocked the driver, commonly due to policy or vulnerable-driver blocklist enforcement.";
            }

            return "GetLastError=" + errorCode.ToString(CultureInfo.InvariantCulture) + " (" + new Win32Exception(errorCode).Message + ")." + hint;
        }

        private static string ExpandPath(string path)
        {
            return Environment.ExpandEnvironmentVariables(path ?? string.Empty);
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateService(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            uint dwDesiredAccess,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ChangeServiceConfig(
            IntPtr hService,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword,
            string lpDisplayName);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartService(IntPtr hService, int dwNumServiceArgs, IntPtr lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatusEx(
            IntPtr hService,
            int infoLevel,
            ref SERVICE_STATUS_PROCESS lpBuffer,
            int cbBufSize,
            out int pcbBytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS_PROCESS
        {
            public int dwServiceType;
            public int dwCurrentState;
            public int dwControlsAccepted;
            public int dwWin32ExitCode;
            public int dwServiceSpecificExitCode;
            public int dwCheckPoint;
            public int dwWaitHint;
            public int dwProcessId;
            public int dwServiceFlags;
        }
    }

    internal sealed class KernelSensorLoadResult
    {
        public bool Requested { get; set; }

        public bool Success { get; set; }

        public string Status { get; set; }

        public string Message { get; set; }

        public string ServiceName { get; set; }

        public string DriverPath { get; set; }

        public int ErrorCode { get; set; }

        public int LastServiceState { get; set; }

        public int Win32ExitCode { get; set; }

        public int ServiceSpecificExitCode { get; set; }

        public bool ServiceCreated { get; set; }

        public bool ExistingService { get; set; }

        public bool ConfigurationUpdated { get; set; }

        public bool StartRequested { get; set; }

        public bool AlreadyRunning { get; set; }
    }
}
