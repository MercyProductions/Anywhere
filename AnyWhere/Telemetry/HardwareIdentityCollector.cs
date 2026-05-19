using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

namespace AnyWhere.Telemetry
{
    internal sealed class HardwareIdentityCollector
    {
        private readonly EventLogger _logger;

        public HardwareIdentityCollector(EventLogger logger)
        {
            _logger = logger;
        }

        public HardwareIdentitySnapshot Capture(string stage)
        {
            HardwareIdentitySnapshot snapshot = new HardwareIdentitySnapshot
            {
                Stage = stage
            };

            snapshot.Disks.AddRange(CaptureWmiDisks());
            snapshot.Disks.AddRange(CapturePhysicalDriveIoctlDisks());
            snapshot.Disks.AddRange(CaptureRegistryStorageDisks());
            snapshot.Volumes.AddRange(CaptureVolumes());
            snapshot.MountedDevices.AddRange(CaptureMountedDevices());
            snapshot.NetworkAdapters.AddRange(CaptureWmiNetworkAdapters());
            snapshot.NetworkAdapters.AddRange(CaptureNetworkInterfaceAdapters());
            snapshot.NetworkAdapters.AddRange(CaptureGetAdaptersAddresses());
            snapshot.NetworkAdapters.AddRange(CaptureRegistryNetworkAdapters());
            snapshot.SystemIdentities.AddRange(CaptureWmiSystemIdentity());
            snapshot.SystemIdentities.AddRange(CaptureRegistrySystemIdentity());
            snapshot.SystemIdentities.Add(CaptureFirmwareTableIdentity());
            snapshot.Gpus.AddRange(CaptureWmiGpus());
            snapshot.Gpus.AddRange(DxgiAdapterInventory.Capture(_logger));
            snapshot.Tpms.AddRange(CaptureTpmIdentity());
            snapshot.Monitors.AddRange(CaptureWmiMonitorIdentity());
            snapshot.Monitors.AddRange(CaptureRegistryMonitorIdentity());
            snapshot.Devices.AddRange(CaptureWmiDeviceStack());
            snapshot.Devices.AddRange(CaptureRegistryDeviceClassFilters());

            return snapshot;
        }

        private IEnumerable<DiskIdentityRecord> CaptureWmiDisks()
        {
            List<DiskIdentityRecord> records = new List<DiskIdentityRecord>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT Index, DeviceID, Model, Manufacturer, SerialNumber, PNPDeviceID, InterfaceType FROM Win32_DiskDrive"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject disk in results)
                    {
                        using (disk)
                        {
                            records.Add(new DiskIdentityRecord
                            {
                                Source = "WMI.Win32_DiskDrive",
                                Index = Convert.ToString(disk["Index"], CultureInfo.InvariantCulture),
                                DeviceId = Convert.ToString(disk["DeviceID"], CultureInfo.InvariantCulture),
                                Model = Convert.ToString(disk["Model"], CultureInfo.InvariantCulture),
                                Vendor = Convert.ToString(disk["Manufacturer"], CultureInfo.InvariantCulture),
                                Serial = Convert.ToString(disk["SerialNumber"], CultureInfo.InvariantCulture),
                                PnpDeviceId = Convert.ToString(disk["PNPDeviceID"], CultureInfo.InvariantCulture),
                                InterfaceType = Convert.ToString(disk["InterfaceType"], CultureInfo.InvariantCulture)
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException("HardwareIdentity", "WmiDiskCaptureFailed", ex, null);
            }

            return records;
        }

        private IEnumerable<DiskIdentityRecord> CapturePhysicalDriveIoctlDisks()
        {
            List<DiskIdentityRecord> records = new List<DiskIdentityRecord>();
            for (int i = 0; i < 32; i++)
            {
                string devicePath = @"\\.\PhysicalDrive" + i.ToString(CultureInfo.InvariantCulture);
                IntPtr handle = NativeMethods.CreateFile(
                    devicePath,
                    NativeMethods.GENERIC_READ,
                    NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    NativeMethods.OPEN_EXISTING,
                    0,
                    IntPtr.Zero);

                if (handle == IntPtr.Zero || handle.ToInt64() == -1)
                {
                    continue;
                }

                IntPtr outBuffer = IntPtr.Zero;
                try
                {
                    int bufferSize = 4096;
                    outBuffer = Marshal.AllocHGlobal(bufferSize);
                    NativeMethods.STORAGE_PROPERTY_QUERY query = new NativeMethods.STORAGE_PROPERTY_QUERY
                    {
                        PropertyId = 0,
                        QueryType = 0,
                        AdditionalParameters = 0
                    };

                    int bytesReturned;
                    bool ok = NativeMethods.DeviceIoControl(
                        handle,
                        NativeMethods.IOCTL_STORAGE_QUERY_PROPERTY,
                        ref query,
                        Marshal.SizeOf(typeof(NativeMethods.STORAGE_PROPERTY_QUERY)),
                        outBuffer,
                        bufferSize,
                        out bytesReturned,
                        IntPtr.Zero);

                    if (!ok)
                    {
                        continue;
                    }

                    NativeMethods.STORAGE_DEVICE_DESCRIPTOR descriptor =
                        (NativeMethods.STORAGE_DEVICE_DESCRIPTOR)Marshal.PtrToStructure(
                            outBuffer,
                            typeof(NativeMethods.STORAGE_DEVICE_DESCRIPTOR));

                    records.Add(new DiskIdentityRecord
                    {
                        Source = "IOCTL_STORAGE_QUERY_PROPERTY",
                        Index = i.ToString(CultureInfo.InvariantCulture),
                        DeviceId = devicePath,
                        Vendor = ReadDescriptorString(outBuffer, descriptor.VendorIdOffset, bufferSize),
                        Model = ReadDescriptorString(outBuffer, descriptor.ProductIdOffset, bufferSize),
                        Serial = ReadDescriptorString(outBuffer, descriptor.SerialNumberOffset, bufferSize),
                        InterfaceType = descriptor.BusType.ToString(CultureInfo.InvariantCulture)
                    });
                }
                catch
                {
                }
                finally
                {
                    if (outBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(outBuffer);
                    }

                    NativeMethods.CloseHandle(handle);
                }
            }

            return records;
        }

        private IEnumerable<DiskIdentityRecord> CaptureRegistryStorageDisks()
        {
            List<DiskIdentityRecord> records = new List<DiskIdentityRecord>();
            using (RegistryKey enumRoot = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum"))
            {
                if (enumRoot == null)
                {
                    return records;
                }

                CaptureRegistryStorageBranch(enumRoot, "SCSI", @"SYSTEM\CurrentControlSet\Enum\SCSI", records);
                CaptureRegistryStorageBranch(enumRoot, "STORAGE", @"SYSTEM\CurrentControlSet\Enum\STORAGE", records);
                CaptureRegistryStorageBranch(enumRoot, "USBSTOR", @"SYSTEM\CurrentControlSet\Enum\USBSTOR", records);
            }

            return records;
        }

        private static void CaptureRegistryStorageBranch(RegistryKey enumRoot, string branchName, string displayPath, ICollection<DiskIdentityRecord> records)
        {
            using (RegistryKey branch = enumRoot.OpenSubKey(branchName))
            {
                if (branch == null)
                {
                    return;
                }

                foreach (string deviceClass in SafeSubKeyNames(branch))
                {
                    using (RegistryKey classKey = branch.OpenSubKey(deviceClass))
                    {
                        if (classKey == null)
                        {
                            continue;
                        }

                        foreach (string instance in SafeSubKeyNames(classKey))
                        {
                            using (RegistryKey instanceKey = classKey.OpenSubKey(instance))
                            {
                                if (instanceKey == null)
                                {
                                    continue;
                                }

                                string friendlyName = Convert.ToString(instanceKey.GetValue("FriendlyName"), CultureInfo.InvariantCulture);
                                string deviceDesc = Convert.ToString(instanceKey.GetValue("DeviceDesc"), CultureInfo.InvariantCulture);
                                string parentId = Convert.ToString(instanceKey.GetValue("ParentIdPrefix"), CultureInfo.InvariantCulture);

                                records.Add(new DiskIdentityRecord
                                {
                                    Source = "Registry.StorageEnum",
                                    DeviceId = branchName + "\\" + deviceClass + "\\" + instance,
                                    Model = string.IsNullOrWhiteSpace(friendlyName) ? deviceDesc : friendlyName,
                                    Serial = string.IsNullOrWhiteSpace(parentId) ? ExtractRegistryInstanceSerial(instance) : parentId,
                                    RegistryPath = displayPath + "\\" + deviceClass + "\\" + instance
                                });
                            }
                        }
                    }
                }
            }
        }

        private IEnumerable<VolumeIdentityRecord> CaptureVolumes()
        {
            List<VolumeIdentityRecord> records = new List<VolumeIdentityRecord>();
            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (!drive.IsReady)
                    {
                        continue;
                    }

                    StringBuilder volumeName = new StringBuilder(512);
                    StringBuilder fileSystemName = new StringBuilder(512);
                    uint serial;
                    uint maxComponent;
                    uint flags;

                    if (NativeMethods.GetVolumeInformation(drive.RootDirectory.FullName, volumeName, volumeName.Capacity, out serial, out maxComponent, out flags, fileSystemName, fileSystemName.Capacity))
                    {
                        records.Add(new VolumeIdentityRecord
                        {
                            DriveName = drive.RootDirectory.FullName,
                            VolumeLabel = volumeName.ToString(),
                            FileSystem = fileSystemName.ToString(),
                            VolumeSerial = serial.ToString("X8", CultureInfo.InvariantCulture)
                        });
                    }
                }
                catch
                {
                }
            }

            return records;
        }

        private IEnumerable<MountedDeviceRecord> CaptureMountedDevices()
        {
            List<MountedDeviceRecord> records = new List<MountedDeviceRecord>();
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\MountedDevices"))
            {
                if (key == null)
                {
                    return records;
                }

                foreach (string valueName in key.GetValueNames())
                {
                    byte[] bytes = key.GetValue(valueName) as byte[];
                    records.Add(new MountedDeviceRecord
                    {
                        RegistryValueName = valueName,
                        ValueHash = HardwareIdentityUtilities.Sha256Hex(bytes)
                    });
                }
            }

            return records;
        }

        private IEnumerable<NetworkIdentityRecord> CaptureWmiNetworkAdapters()
        {
            List<NetworkIdentityRecord> records = new List<NetworkIdentityRecord>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT GUID, Name, NetConnectionID, MACAddress, PNPDeviceID, Manufacturer FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject adapter in results)
                    {
                        using (adapter)
                        {
                            string name = Convert.ToString(adapter["Name"], CultureInfo.InvariantCulture);
                            string description = Convert.ToString(adapter["NetConnectionID"], CultureInfo.InvariantCulture);
                            string manufacturer = Convert.ToString(adapter["Manufacturer"], CultureInfo.InvariantCulture);
                            string mac = Convert.ToString(adapter["MACAddress"], CultureInfo.InvariantCulture);
                            string combined = name + " " + description + " " + manufacturer;

                            records.Add(new NetworkIdentityRecord
                            {
                                Source = "WMI.Win32_NetworkAdapter",
                                Name = name,
                                Description = string.IsNullOrWhiteSpace(description) ? manufacturer : description,
                                AdapterId = Convert.ToString(adapter["GUID"], CultureInfo.InvariantCulture),
                                PnpDeviceId = Convert.ToString(adapter["PNPDeviceID"], CultureInfo.InvariantCulture),
                                MacAddress = HardwareIdentityUtilities.NormalizeMac(mac),
                                IsLocallyAdministered = HardwareIdentityUtilities.IsLocallyAdministeredMac(mac),
                                IsVirtual = HardwareIdentityUtilities.LooksVirtual(combined)
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException("HardwareIdentity", "WmiNetworkCaptureFailed", ex, null);
            }

            return records;
        }

        private static IEnumerable<NetworkIdentityRecord> CaptureNetworkInterfaceAdapters()
        {
            List<NetworkIdentityRecord> records = new List<NetworkIdentityRecord>();
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                string mac = HardwareIdentityUtilities.NormalizeMac(adapter.GetPhysicalAddress().ToString());
                if (string.IsNullOrWhiteSpace(mac))
                {
                    continue;
                }

                string combined = adapter.Name + " " + adapter.Description;
                records.Add(new NetworkIdentityRecord
                {
                    Source = "System.Net.NetworkInformation",
                    Name = adapter.Name,
                    Description = adapter.Description,
                    AdapterId = adapter.Id,
                    MacAddress = mac,
                    IsLocallyAdministered = HardwareIdentityUtilities.IsLocallyAdministeredMac(mac),
                    IsVirtual = HardwareIdentityUtilities.LooksVirtual(combined),
                    OperationalStatus = adapter.OperationalStatus.ToString()
                });
            }

            return records;
        }

        private IEnumerable<NetworkIdentityRecord> CaptureGetAdaptersAddresses()
        {
            List<NetworkIdentityRecord> records = new List<NetworkIdentityRecord>();
            int bufferSize = 15000;
            IntPtr buffer = IntPtr.Zero;

            try
            {
                int status = NativeMethods.GetAdaptersAddresses(NativeMethods.AF_UNSPEC, NativeMethods.GAA_FLAG_INCLUDE_PREFIX, IntPtr.Zero, IntPtr.Zero, ref bufferSize);
                buffer = Marshal.AllocHGlobal(bufferSize);
                status = NativeMethods.GetAdaptersAddresses(NativeMethods.AF_UNSPEC, NativeMethods.GAA_FLAG_INCLUDE_PREFIX, IntPtr.Zero, buffer, ref bufferSize);
                if (status != 0)
                {
                    return records;
                }

                IntPtr current = buffer;
                while (current != IntPtr.Zero)
                {
                    NativeMethods.IP_ADAPTER_ADDRESSES adapter =
                        (NativeMethods.IP_ADAPTER_ADDRESSES)Marshal.PtrToStructure(current, typeof(NativeMethods.IP_ADAPTER_ADDRESSES));

                    string mac = FormatMac(adapter.PhysicalAddress, adapter.PhysicalAddressLength);
                    if (!string.IsNullOrWhiteSpace(mac))
                    {
                        string friendlyName = Marshal.PtrToStringUni(adapter.FriendlyName);
                        string description = Marshal.PtrToStringUni(adapter.Description);
                        string adapterName = Marshal.PtrToStringAnsi(adapter.AdapterName);
                        string combined = friendlyName + " " + description + " " + adapterName;

                        records.Add(new NetworkIdentityRecord
                        {
                            Source = "GetAdaptersAddresses",
                            Name = friendlyName,
                            Description = description,
                            AdapterId = adapterName,
                            MacAddress = mac,
                            IsLocallyAdministered = HardwareIdentityUtilities.IsLocallyAdministeredMac(mac),
                            IsVirtual = HardwareIdentityUtilities.LooksVirtual(combined),
                            OperationalStatus = adapter.OperStatus.ToString(CultureInfo.InvariantCulture)
                        });
                    }

                    current = adapter.Next;
                }
            }
            catch (Exception ex)
            {
                _logger.LogException("HardwareIdentity", "GetAdaptersAddressesCaptureFailed", ex, null);
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return records;
        }

        private static IEnumerable<NetworkIdentityRecord> CaptureRegistryNetworkAdapters()
        {
            List<NetworkIdentityRecord> records = new List<NetworkIdentityRecord>();
            const string classPath = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
            using (RegistryKey classKey = Registry.LocalMachine.OpenSubKey(classPath))
            {
                if (classKey == null)
                {
                    return records;
                }

                foreach (string subKeyName in SafeSubKeyNames(classKey))
                {
                    using (RegistryKey adapterKey = classKey.OpenSubKey(subKeyName))
                    {
                        if (adapterKey == null)
                        {
                            continue;
                        }

                        string networkAddress = Convert.ToString(adapterKey.GetValue("NetworkAddress"), CultureInfo.InvariantCulture);
                        string driverDesc = Convert.ToString(adapterKey.GetValue("DriverDesc"), CultureInfo.InvariantCulture);
                        string netCfgId = Convert.ToString(adapterKey.GetValue("NetCfgInstanceId"), CultureInfo.InvariantCulture);
                        string componentId = Convert.ToString(adapterKey.GetValue("ComponentId"), CultureInfo.InvariantCulture);

                        if (string.IsNullOrWhiteSpace(driverDesc) && string.IsNullOrWhiteSpace(networkAddress))
                        {
                            continue;
                        }

                        string normalizedMac = HardwareIdentityUtilities.NormalizeMac(networkAddress);
                        records.Add(new NetworkIdentityRecord
                        {
                            Source = "Registry.NetworkClass",
                            Name = driverDesc,
                            Description = componentId,
                            AdapterId = netCfgId,
                            MacAddress = normalizedMac,
                            RegistryPath = classPath + "\\" + subKeyName,
                            IsLocallyAdministered = HardwareIdentityUtilities.IsLocallyAdministeredMac(normalizedMac),
                            IsVirtual = HardwareIdentityUtilities.LooksVirtual(driverDesc + " " + componentId)
                        });
                    }
                }
            }

            return records;
        }

        private IEnumerable<SystemIdentityRecord> CaptureWmiSystemIdentity()
        {
            SystemIdentityRecord record = new SystemIdentityRecord { Source = "WMI" };

            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Manufacturer, SMBIOSBIOSVersion, SerialNumber FROM Win32_BIOS"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject bios in results)
                    {
                        using (bios)
                        {
                            record.BiosVendor = Convert.ToString(bios["Manufacturer"], CultureInfo.InvariantCulture);
                            record.BiosVersion = Convert.ToString(bios["SMBIOSBIOSVersion"], CultureInfo.InvariantCulture);
                            record.BiosSerial = Convert.ToString(bios["SerialNumber"], CultureInfo.InvariantCulture);
                        }
                        break;
                    }
                }

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject board in results)
                    {
                        using (board)
                        {
                            record.BaseboardVendor = Convert.ToString(board["Manufacturer"], CultureInfo.InvariantCulture);
                            record.BaseboardProduct = Convert.ToString(board["Product"], CultureInfo.InvariantCulture);
                            record.BaseboardSerial = Convert.ToString(board["SerialNumber"], CultureInfo.InvariantCulture);
                        }
                        break;
                    }
                }

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Vendor, Name, UUID, IdentifyingNumber FROM Win32_ComputerSystemProduct"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject system in results)
                    {
                        using (system)
                        {
                            record.SystemVendor = Convert.ToString(system["Vendor"], CultureInfo.InvariantCulture);
                            record.SystemProduct = Convert.ToString(system["Name"], CultureInfo.InvariantCulture);
                            record.SystemUuid = Convert.ToString(system["UUID"], CultureInfo.InvariantCulture);
                        }
                        break;
                    }
                }

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT Manufacturer, Model, HypervisorPresent FROM Win32_ComputerSystem"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject system in results)
                    {
                        using (system)
                        {
                            string manufacturer = Convert.ToString(system["Manufacturer"], CultureInfo.InvariantCulture);
                            string model = Convert.ToString(system["Model"], CultureInfo.InvariantCulture);
                            if (string.IsNullOrWhiteSpace(record.SystemVendor))
                            {
                                record.SystemVendor = manufacturer;
                            }

                            if (string.IsNullOrWhiteSpace(record.SystemProduct))
                            {
                                record.SystemProduct = model;
                            }

                            record.HypervisorPresent = Convert.ToString(system["HypervisorPresent"], CultureInfo.InvariantCulture);
                        }
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException("HardwareIdentity", "WmiSystemCaptureFailed", ex, null);
            }

            return new[] { record };
        }

        private static IEnumerable<SystemIdentityRecord> CaptureRegistrySystemIdentity()
        {
            SystemIdentityRecord record = new SystemIdentityRecord { Source = "Registry.HardwareDescription" };
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System"))
            {
                if (key != null)
                {
                    record.BiosVersion = ValueToString(key.GetValue("SystemBiosVersion"));
                    record.SystemProduct = ValueToString(key.GetValue("Identifier"));
                }
            }

            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS"))
            {
                if (key != null)
                {
                    record.BiosVendor = Convert.ToString(key.GetValue("BIOSVendor"), CultureInfo.InvariantCulture);
                    record.BiosVersion = Convert.ToString(key.GetValue("BIOSVersion"), CultureInfo.InvariantCulture);
                    record.BiosSerial = Convert.ToString(key.GetValue("SystemSerialNumber"), CultureInfo.InvariantCulture);
                    record.BaseboardVendor = Convert.ToString(key.GetValue("BaseBoardManufacturer"), CultureInfo.InvariantCulture);
                    record.BaseboardProduct = Convert.ToString(key.GetValue("BaseBoardProduct"), CultureInfo.InvariantCulture);
                    record.BaseboardSerial = Convert.ToString(key.GetValue("BaseBoardSerialNumber"), CultureInfo.InvariantCulture);
                    record.SystemVendor = Convert.ToString(key.GetValue("SystemManufacturer"), CultureInfo.InvariantCulture);
                    record.SystemProduct = Convert.ToString(key.GetValue("SystemProductName"), CultureInfo.InvariantCulture);
                }
            }

            return new[] { record };
        }

        private SystemIdentityRecord CaptureFirmwareTableIdentity()
        {
            SystemIdentityRecord record = new SystemIdentityRecord { Source = "FirmwareTable.RSMB" };
            IntPtr buffer = IntPtr.Zero;

            try
            {
                const uint rsmb = 0x424D5352;
                uint size = NativeMethods.GetSystemFirmwareTable(rsmb, 0, IntPtr.Zero, 0);
                if (size == 0 || size > 1024 * 1024)
                {
                    return record;
                }

                buffer = Marshal.AllocHGlobal((int)size);
                uint read = NativeMethods.GetSystemFirmwareTable(rsmb, 0, buffer, size);
                if (read == 0)
                {
                    return record;
                }

                byte[] bytes = new byte[read];
                Marshal.Copy(buffer, bytes, 0, bytes.Length);
                record.FirmwareHash = HardwareIdentityUtilities.Sha256Hex(bytes);
                record.FirmwareStringSummary = string.Join("|", ExtractPrintableStrings(bytes, 24).ToArray());
            }
            catch (Exception ex)
            {
                _logger.LogException("HardwareIdentity", "FirmwareTableCaptureFailed", ex, null);
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return record;
        }

        private IEnumerable<GpuIdentityRecord> CaptureWmiGpus()
        {
            List<GpuIdentityRecord> records = new List<GpuIdentityRecord>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT Name, AdapterCompatibility, PNPDeviceID, DriverVersion, InstalledDisplayDrivers FROM Win32_VideoController"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject gpu in results)
                    {
                        using (gpu)
                        {
                            string driverPath = FirstExistingDisplayDriverPath(Convert.ToString(gpu["InstalledDisplayDrivers"], CultureInfo.InvariantCulture));
                            SignatureVerificationResult signature = string.IsNullOrWhiteSpace(driverPath)
                                ? new SignatureVerificationResult { Status = "Unavailable" }
                                : AuthenticodeVerifier.VerifyFile(driverPath);

                            string name = Convert.ToString(gpu["Name"], CultureInfo.InvariantCulture);
                            string vendor = Convert.ToString(gpu["AdapterCompatibility"], CultureInfo.InvariantCulture);

                            records.Add(new GpuIdentityRecord
                            {
                                Source = "WMI.Win32_VideoController",
                                Name = name,
                                Vendor = vendor,
                                PnpDeviceId = Convert.ToString(gpu["PNPDeviceID"], CultureInfo.InvariantCulture),
                                DriverVersion = Convert.ToString(gpu["DriverVersion"], CultureInfo.InvariantCulture),
                                DriverPath = driverPath,
                                SignatureStatus = signature.Status,
                                SignatureSubject = signature.Subject,
                                IsVirtual = HardwareIdentityUtilities.LooksVirtual(name + " " + vendor + " " + driverPath)
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException("HardwareIdentity", "WmiGpuCaptureFailed", ex, null);
            }

            return records;
        }

        private IEnumerable<TpmIdentityRecord> CaptureTpmIdentity()
        {
            List<TpmIdentityRecord> records = new List<TpmIdentityRecord>();
            try
            {
                ManagementScope scope = new ManagementScope(@"\\.\root\CIMV2\Security\MicrosoftTpm");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    scope,
                    new ObjectQuery("SELECT IsEnabled_InitialValue, IsActivated_InitialValue, IsOwned_InitialValue, ManufacturerId, ManufacturerIdTxt, ManufacturerVersion, SpecVersion, ManagedAuthLevel FROM Win32_Tpm")))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject tpm in results)
                    {
                        using (tpm)
                        {
                            records.Add(new TpmIdentityRecord
                            {
                                Source = "WMI.Win32_Tpm",
                                Present = true,
                                Enabled = ToBool(tpm["IsEnabled_InitialValue"]),
                                Activated = ToBool(tpm["IsActivated_InitialValue"]),
                                Owned = ToBool(tpm["IsOwned_InitialValue"]),
                                ManufacturerId = Convert.ToString(tpm["ManufacturerIdTxt"], CultureInfo.InvariantCulture),
                                ManufacturerVersion = Convert.ToString(tpm["ManufacturerVersion"], CultureInfo.InvariantCulture),
                                SpecVersion = Convert.ToString(tpm["SpecVersion"], CultureInfo.InvariantCulture),
                                ManagedAuthLevel = Convert.ToString(tpm["ManagedAuthLevel"], CultureInfo.InvariantCulture)
                            });
                        }
                    }
                }
            }
            catch
            {
            }

            if (records.Count == 0)
            {
                records.Add(new TpmIdentityRecord
                {
                    Source = "WMI.Win32_Tpm",
                    Present = false
                });
            }

            return records;
        }

        private IEnumerable<MonitorIdentityRecord> CaptureWmiMonitorIdentity()
        {
            List<MonitorIdentityRecord> records = new List<MonitorIdentityRecord>();
            try
            {
                ManagementScope scope = new ManagementScope(@"\\.\root\wmi");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    scope,
                    new ObjectQuery("SELECT InstanceName, ManufacturerName, ProductCodeID, SerialNumberID, UserFriendlyName FROM WmiMonitorID")))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject monitor in results)
                    {
                        using (monitor)
                        {
                            records.Add(new MonitorIdentityRecord
                            {
                                Source = "WMI.WmiMonitorID",
                                DeviceId = Convert.ToString(monitor["InstanceName"], CultureInfo.InvariantCulture),
                                InstanceId = Convert.ToString(monitor["InstanceName"], CultureInfo.InvariantCulture),
                                Manufacturer = UshortArrayToString(monitor["ManufacturerName"] as ushort[]),
                                ProductCode = UshortArrayToString(monitor["ProductCodeID"] as ushort[]),
                                Serial = UshortArrayToString(monitor["SerialNumberID"] as ushort[]),
                                FriendlyName = UshortArrayToString(monitor["UserFriendlyName"] as ushort[])
                            });
                        }
                    }
                }
            }
            catch
            {
            }

            return records;
        }

        private IEnumerable<MonitorIdentityRecord> CaptureRegistryMonitorIdentity()
        {
            List<MonitorIdentityRecord> records = new List<MonitorIdentityRecord>();
            const string displayPath = @"SYSTEM\CurrentControlSet\Enum\DISPLAY";
            using (RegistryKey displayRoot = Registry.LocalMachine.OpenSubKey(displayPath))
            {
                if (displayRoot == null)
                {
                    return records;
                }

                foreach (string device in SafeSubKeyNames(displayRoot))
                {
                    using (RegistryKey deviceKey = displayRoot.OpenSubKey(device))
                    {
                        if (deviceKey == null)
                        {
                            continue;
                        }

                        foreach (string instance in SafeSubKeyNames(deviceKey))
                        {
                            using (RegistryKey instanceKey = deviceKey.OpenSubKey(instance))
                            using (RegistryKey parametersKey = instanceKey == null ? null : instanceKey.OpenSubKey("Device Parameters"))
                            {
                                if (instanceKey == null)
                                {
                                    continue;
                                }

                                byte[] edid = parametersKey == null ? null : parametersKey.GetValue("EDID") as byte[];
                                string friendlyName = Convert.ToString(instanceKey.GetValue("FriendlyName"), CultureInfo.InvariantCulture);
                                MonitorIdentityRecord record = new MonitorIdentityRecord
                                {
                                    Source = "Registry.DisplayEnum",
                                    DeviceId = device + "\\" + instance,
                                    InstanceId = instance,
                                    FriendlyName = friendlyName,
                                    RegistryPath = displayPath + "\\" + device + "\\" + instance,
                                    EdidHash = HardwareIdentityUtilities.Sha256Hex(edid)
                                };

                                ApplyEdidIdentity(record, edid);
                                records.Add(record);
                            }
                        }
                    }
                }
            }

            return records;
        }

        private IEnumerable<DeviceStackRecord> CaptureWmiDeviceStack()
        {
            List<DeviceStackRecord> records = new List<DeviceStackRecord>();
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT DeviceID, Name, PNPClass, ClassGuid, Manufacturer, Service, Status FROM Win32_PnPEntity"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject device in results)
                    {
                        using (device)
                        {
                            string name = Convert.ToString(device["Name"], CultureInfo.InvariantCulture);
                            string manufacturer = Convert.ToString(device["Manufacturer"], CultureInfo.InvariantCulture);
                            string pnpClass = Convert.ToString(device["PNPClass"], CultureInfo.InvariantCulture);
                            string service = Convert.ToString(device["Service"], CultureInfo.InvariantCulture);

                            records.Add(new DeviceStackRecord
                            {
                                Source = "WMI.Win32_PnPEntity",
                                DeviceId = Convert.ToString(device["DeviceID"], CultureInfo.InvariantCulture),
                                Name = name,
                                PnpClass = pnpClass,
                                ClassGuid = Convert.ToString(device["ClassGuid"], CultureInfo.InvariantCulture),
                                Manufacturer = manufacturer,
                                Service = service,
                                Status = Convert.ToString(device["Status"], CultureInfo.InvariantCulture),
                                IsVirtual = HardwareIdentityUtilities.LooksVirtual(name + " " + manufacturer + " " + pnpClass + " " + service)
                            });
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogException("HardwareIdentity", "WmiDeviceStackCaptureFailed", ex, null);
            }

            return records;
        }

        private static IEnumerable<DeviceStackRecord> CaptureRegistryDeviceClassFilters()
        {
            List<DeviceStackRecord> records = new List<DeviceStackRecord>();
            const string classRootPath = @"SYSTEM\CurrentControlSet\Control\Class";
            using (RegistryKey classRoot = Registry.LocalMachine.OpenSubKey(classRootPath))
            {
                if (classRoot == null)
                {
                    return records;
                }

                foreach (string classGuid in SafeSubKeyNames(classRoot))
                {
                    using (RegistryKey classKey = classRoot.OpenSubKey(classGuid))
                    {
                        if (classKey == null)
                        {
                            continue;
                        }

                        string upper = RegistryValueToString(classKey.GetValue("UpperFilters"));
                        string lower = RegistryValueToString(classKey.GetValue("LowerFilters"));
                        if (string.IsNullOrWhiteSpace(upper) && string.IsNullOrWhiteSpace(lower))
                        {
                            continue;
                        }

                        records.Add(new DeviceStackRecord
                        {
                            Source = "Registry.DeviceClassFilters",
                            DeviceId = classGuid,
                            Name = Convert.ToString(classKey.GetValue("Class"), CultureInfo.InvariantCulture),
                            PnpClass = Convert.ToString(classKey.GetValue("Class"), CultureInfo.InvariantCulture),
                            ClassGuid = classGuid,
                            UpperFilters = upper,
                            LowerFilters = lower,
                            RegistryPath = classRootPath + "\\" + classGuid,
                            IsVirtual = HardwareIdentityUtilities.LooksVirtual(upper + " " + lower)
                        });
                    }
                }
            }

            return records;
        }

        private static string ReadDescriptorString(IntPtr buffer, uint offset, int bufferSize)
        {
            if (offset == 0 || offset >= bufferSize)
            {
                return null;
            }

            try
            {
                return Marshal.PtrToStringAnsi(IntPtr.Add(buffer, checked((int)offset)));
            }
            catch
            {
                return null;
            }
        }

        private static string ExtractRegistryInstanceSerial(string instance)
        {
            if (string.IsNullOrWhiteSpace(instance))
            {
                return null;
            }

            int ampersand = instance.IndexOf('&');
            return ampersand > 0 ? instance.Substring(0, ampersand) : instance;
        }

        private static string FormatMac(byte[] bytes, uint length)
        {
            if (bytes == null || length == 0 || length > bytes.Length)
            {
                return null;
            }

            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < length; i++)
            {
                builder.Append(bytes[i].ToString("X2", CultureInfo.InvariantCulture));
            }

            return HardwareIdentityUtilities.NormalizeMac(builder.ToString());
        }

        private static string ValueToString(object value)
        {
            string[] array = value as string[];
            if (array != null)
            {
                return string.Join("|", array);
            }

            return Convert.ToString(value, CultureInfo.InvariantCulture);
        }

        private static string RegistryValueToString(object value)
        {
            if (value == null)
            {
                return null;
            }

            string[] array = value as string[];
            if (array != null)
            {
                return string.Join(";", array);
            }

            return Convert.ToString(value, CultureInfo.InvariantCulture);
        }

        private static string[] SafeSubKeyNames(RegistryKey key)
        {
            try
            {
                return key.GetSubKeyNames();
            }
            catch
            {
                return new string[0];
            }
        }

        private static IEnumerable<string> ExtractPrintableStrings(byte[] bytes, int maxStrings)
        {
            List<string> strings = new List<string>();
            StringBuilder current = new StringBuilder();

            foreach (byte b in bytes)
            {
                if (b >= 32 && b <= 126)
                {
                    current.Append((char)b);
                }
                else
                {
                    AddCurrentString(strings, current, maxStrings);
                    if (strings.Count >= maxStrings)
                    {
                        break;
                    }
                }
            }

            AddCurrentString(strings, current, maxStrings);
            return strings;
        }

        private static void AddCurrentString(ICollection<string> strings, StringBuilder current, int maxStrings)
        {
            if (current.Length >= 4 && strings.Count < maxStrings)
            {
                strings.Add(current.ToString());
            }

            current.Length = 0;
        }

        private static bool ToBool(object value)
        {
            if (value is bool)
            {
                return (bool)value;
            }

            string text = Convert.ToString(value, CultureInfo.InvariantCulture);
            return text.Equals("true", StringComparison.OrdinalIgnoreCase) || text.Equals("1", StringComparison.OrdinalIgnoreCase);
        }

        private static string UshortArrayToString(ushort[] values)
        {
            if (values == null || values.Length == 0)
            {
                return null;
            }

            StringBuilder builder = new StringBuilder(values.Length);
            foreach (ushort value in values)
            {
                if (value == 0)
                {
                    continue;
                }

                builder.Append((char)value);
            }

            return builder.ToString();
        }

        private static void ApplyEdidIdentity(MonitorIdentityRecord record, byte[] edid)
        {
            if (record == null || edid == null || edid.Length < 16)
            {
                return;
            }

            ushort manufacturer = (ushort)((edid[8] << 8) | edid[9]);
            char a = (char)('A' + ((manufacturer >> 10) & 0x1F) - 1);
            char b = (char)('A' + ((manufacturer >> 5) & 0x1F) - 1);
            char c = (char)('A' + (manufacturer & 0x1F) - 1);
            record.Manufacturer = new string(new[] { a, b, c });
            record.ProductCode = ((ushort)(edid[10] | (edid[11] << 8))).ToString("X4", CultureInfo.InvariantCulture);

            uint serial = (uint)(edid[12] | (edid[13] << 8) | (edid[14] << 16) | (edid[15] << 24));
            if (serial != 0)
            {
                record.Serial = serial.ToString("X8", CultureInfo.InvariantCulture);
            }
        }

        private static string FirstExistingDisplayDriverPath(string installedDisplayDrivers)
        {
            if (string.IsNullOrWhiteSpace(installedDisplayDrivers))
            {
                return null;
            }

            string system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
            foreach (string rawPart in installedDisplayDrivers.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string part = rawPart.Trim();
                if (string.IsNullOrWhiteSpace(part))
                {
                    continue;
                }

                string candidate = Path.IsPathRooted(part) ? part : Path.Combine(system32, part);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }

            return null;
        }
    }
}
