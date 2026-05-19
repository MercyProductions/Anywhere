using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace AnyWhere.Telemetry
{
    internal sealed class MappedMemoryScanner : IDetectionMonitor
    {
        private readonly EventLogger _logger;
        private readonly MonitorOptions _options;
        private readonly DevicePathResolver _pathResolver;
        private readonly HashSet<string> _observedMappings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly ManualResetEventSlim _stopSignal = new ManualResetEventSlim(false);
        private readonly object _syncRoot = new object();
        private Thread _thread;
        private bool _initialScan = true;

        public MappedMemoryScanner(EventLogger logger, MonitorOptions options)
        {
            _logger = logger;
            _options = options;
            _pathResolver = new DevicePathResolver();
        }

        public string Name
        {
            get { return "Mapped Memory"; }
        }

        public void Start()
        {
            _thread = new Thread(ThreadMain)
            {
                IsBackground = true,
                Name = "Aegis Mapped Memory Scanner"
            };
            _thread.Start();
        }

        private void ThreadMain()
        {
            while (!_stopSignal.IsSet)
            {
                try
                {
                    ScanAllProcesses();
                }
                catch (Exception ex)
                {
                    _logger.LogException("Memory", "ScanFailed", ex, null);
                }

                _stopSignal.Wait(_options.MapScanInterval);
            }
        }

        private void ScanAllProcesses()
        {
            int processCount = 0;
            int mappingCount = 0;
            int newMappingCount = 0;
            Process[] processes = Process.GetProcesses();
            HashSet<int> liveProcessIds = new HashSet<int>();

            foreach (Process process in processes)
            {
                int processId;
                string processName;
                try
                {
                    processId = process.Id;
                    processName = process.ProcessName;
                }
                catch
                {
                    process.Dispose();
                    continue;
                }

                try
                {
                    processCount++;
                    liveProcessIds.Add(processId);
                    foreach (MemoryMapRecord record in EnumerateMappedFiles(processId, processName))
                    {
                        mappingCount++;
                        if (RememberMapping(record))
                        {
                            newMappingCount++;
                            if (!_initialScan || _options.EmitInitialMappedFiles)
                            {
                                EmitMapping(record);
                            }
                        }
                    }
                }
                finally
                {
                    process.Dispose();
                }
            }

            CleanupDeadProcessMappings(liveProcessIds);

            if (_initialScan)
            {
                _logger.Log(DetectionEvent.Create(
                    "Memory",
                    "Baseline",
                    EventSeverity.Low,
                    "Mapped-memory baseline complete.",
                    null,
                    null,
                    new Dictionary<string, string>
                    {
                        { "process_count", processCount.ToString(CultureInfo.InvariantCulture) },
                        { "mapped_file_count", mappingCount.ToString(CultureInfo.InvariantCulture) },
                        { "emitted_initial_mappings", _options.EmitInitialMappedFiles.ToString() }
                    }));
                _initialScan = false;
            }
            else if (newMappingCount > 0)
            {
                _logger.Log(DetectionEvent.Create(
                    "Memory",
                    "ScanComplete",
                    EventSeverity.Low,
                    "Mapped-memory scan found " + newMappingCount.ToString(CultureInfo.InvariantCulture) + " new mappings.",
                    null,
                    null,
                    new Dictionary<string, string>
                    {
                        { "process_count", processCount.ToString(CultureInfo.InvariantCulture) },
                        { "mapped_file_count", mappingCount.ToString(CultureInfo.InvariantCulture) },
                        { "new_mapping_count", newMappingCount.ToString(CultureInfo.InvariantCulture) }
                    }));
            }
        }

        private IEnumerable<MemoryMapRecord> EnumerateMappedFiles(int processId, string processName)
        {
            IntPtr handle = NativeMethods.OpenProcess(
                NativeMethods.PROCESS_QUERY_INFORMATION | NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION | NativeMethods.PROCESS_VM_READ,
                false,
                processId);

            if (handle == IntPtr.Zero)
            {
                yield break;
            }

            try
            {
                ulong address = 0;
                int mbiSize = Marshal.SizeOf(typeof(NativeMethods.MEMORY_BASIC_INFORMATION));
                HashSet<string> seenInProcess = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                while (true)
                {
                    NativeMethods.MEMORY_BASIC_INFORMATION info;
                    UIntPtr result = NativeMethods.VirtualQueryEx(
                        handle,
                        new IntPtr(unchecked((long)address)),
                        out info,
                        new UIntPtr((uint)mbiSize));

                    if (result == UIntPtr.Zero)
                    {
                        break;
                    }

                    ulong baseAddress = ToUInt64(info.BaseAddress);
                    ulong regionSize = info.RegionSize.ToUInt64();
                    ulong nextAddress = baseAddress + regionSize;
                    if (regionSize == 0 || nextAddress <= address)
                    {
                        break;
                    }

                    if (info.State == NativeMethods.MEM_COMMIT &&
                        (info.Type == NativeMethods.MEM_IMAGE || info.Type == NativeMethods.MEM_MAPPED))
                    {
                        string mappedPath = TryGetMappedPath(handle, info.BaseAddress);
                        if (!string.IsNullOrWhiteSpace(mappedPath))
                        {
                            string mappingType = info.Type == NativeMethods.MEM_IMAGE ? "Image" : "MappedFile";
                            string localKey = mappingType + "|" + mappedPath;
                            if (seenInProcess.Add(localKey))
                            {
                                yield return new MemoryMapRecord
                                {
                                    ProcessId = processId,
                                    ProcessName = processName,
                                    Path = mappedPath,
                                    MappingType = mappingType,
                                    BaseAddress = baseAddress,
                                    RegionSize = regionSize,
                                    Protection = info.Protect
                                };
                            }
                        }
                    }

                    address = nextAddress;
                }
            }
            finally
            {
                NativeMethods.CloseHandle(handle);
            }
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

                string nativePath = builder.ToString();
                return _pathResolver.ToDosPath(nativePath);
            }
            catch
            {
                return null;
            }
        }

        private bool RememberMapping(MemoryMapRecord record)
        {
            string key = record.ProcessId.ToString(CultureInfo.InvariantCulture) + "|" + record.MappingType + "|" + record.Path;
            lock (_syncRoot)
            {
                return _observedMappings.Add(key);
            }
        }

        private void CleanupDeadProcessMappings(HashSet<int> liveProcessIds)
        {
            lock (_syncRoot)
            {
                _observedMappings.RemoveWhere(delegate(string key)
                {
                    int separator = key.IndexOf('|');
                    if (separator <= 0)
                    {
                        return true;
                    }

                    int processId;
                    if (!int.TryParse(key.Substring(0, separator), NumberStyles.Integer, CultureInfo.InvariantCulture, out processId))
                    {
                        return true;
                    }

                    return !liveProcessIds.Contains(processId);
                });
            }
        }

        private void EmitMapping(MemoryMapRecord record)
        {
            Dictionary<string, string> details = FileClassifier.BuildFileDetails(record.Path, _options, false);
            details["mapping_type"] = record.MappingType;
            details["base_address"] = "0x" + record.BaseAddress.ToString("X", CultureInfo.InvariantCulture);
            details["region_size"] = record.RegionSize.ToString(CultureInfo.InvariantCulture);
            details["protection"] = "0x" + record.Protection.ToString("X", CultureInfo.InvariantCulture);

            EventSeverity severity = EventSeverity.Low;
            if (record.MappingType.Equals("MappedFile", StringComparison.OrdinalIgnoreCase) &&
                (FileClassifier.IsLikelyDownloadLocation(record.Path) || FileClassifier.HasMarkOfTheWeb(record.Path)))
            {
                severity = EventSeverity.High;
            }
            else if (record.MappingType.Equals("MappedFile", StringComparison.OrdinalIgnoreCase))
            {
                severity = EventSeverity.Medium;
            }

            _logger.Log(DetectionEvent.CreateForProcess(
                "Memory",
                "FileMapped",
                severity,
                "File mapped into process memory: " + record.Path,
                record.Path,
                record.ProcessId,
                record.ProcessName,
                details));
        }

        private static ulong ToUInt64(IntPtr value)
        {
            return unchecked((ulong)value.ToInt64());
        }

        public void Dispose()
        {
            _stopSignal.Set();
            if (_thread != null && _thread.IsAlive)
            {
                _thread.Join(TimeSpan.FromSeconds(2));
            }

            _stopSignal.Dispose();
        }
    }
}
