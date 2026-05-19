using System;
using System.Collections.Generic;

namespace AnyWhere.Telemetry
{
    internal sealed class HardwareIdentitySnapshot
    {
        public HardwareIdentitySnapshot()
        {
            TimestampUtc = DateTime.UtcNow;
            Disks = new List<DiskIdentityRecord>();
            Volumes = new List<VolumeIdentityRecord>();
            MountedDevices = new List<MountedDeviceRecord>();
            NetworkAdapters = new List<NetworkIdentityRecord>();
            SystemIdentities = new List<SystemIdentityRecord>();
            Gpus = new List<GpuIdentityRecord>();
            Tpms = new List<TpmIdentityRecord>();
            Monitors = new List<MonitorIdentityRecord>();
            Devices = new List<DeviceStackRecord>();
        }

        public DateTime TimestampUtc { get; set; }

        public string Stage { get; set; }

        public List<DiskIdentityRecord> Disks { get; private set; }

        public List<VolumeIdentityRecord> Volumes { get; private set; }

        public List<MountedDeviceRecord> MountedDevices { get; private set; }

        public List<NetworkIdentityRecord> NetworkAdapters { get; private set; }

        public List<SystemIdentityRecord> SystemIdentities { get; private set; }

        public List<GpuIdentityRecord> Gpus { get; private set; }

        public List<TpmIdentityRecord> Tpms { get; private set; }

        public List<MonitorIdentityRecord> Monitors { get; private set; }

        public List<DeviceStackRecord> Devices { get; private set; }
    }

    internal sealed class DiskIdentityRecord
    {
        public string Source { get; set; }
        public string DeviceId { get; set; }
        public string Index { get; set; }
        public string Model { get; set; }
        public string Vendor { get; set; }
        public string Serial { get; set; }
        public string PnpDeviceId { get; set; }
        public string InterfaceType { get; set; }
        public string RegistryPath { get; set; }
    }

    internal sealed class VolumeIdentityRecord
    {
        public string DriveName { get; set; }
        public string FileSystem { get; set; }
        public string VolumeLabel { get; set; }
        public string VolumeSerial { get; set; }
    }

    internal sealed class MountedDeviceRecord
    {
        public string RegistryValueName { get; set; }
        public string ValueHash { get; set; }
    }

    internal sealed class NetworkIdentityRecord
    {
        public string Source { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string AdapterId { get; set; }
        public string PnpDeviceId { get; set; }
        public string MacAddress { get; set; }
        public string RegistryPath { get; set; }
        public bool IsVirtual { get; set; }
        public bool IsLocallyAdministered { get; set; }
        public string OperationalStatus { get; set; }
    }

    internal sealed class SystemIdentityRecord
    {
        public string Source { get; set; }
        public string BiosVendor { get; set; }
        public string BiosVersion { get; set; }
        public string BiosSerial { get; set; }
        public string BaseboardVendor { get; set; }
        public string BaseboardProduct { get; set; }
        public string BaseboardSerial { get; set; }
        public string SystemVendor { get; set; }
        public string SystemProduct { get; set; }
        public string SystemUuid { get; set; }
        public string FirmwareHash { get; set; }
        public string FirmwareStringSummary { get; set; }
        public string HypervisorPresent { get; set; }
    }

    internal sealed class GpuIdentityRecord
    {
        public string Source { get; set; }
        public string Name { get; set; }
        public string Vendor { get; set; }
        public string PnpDeviceId { get; set; }
        public string DeviceId { get; set; }
        public string DriverVersion { get; set; }
        public string DriverPath { get; set; }
        public string SignatureStatus { get; set; }
        public string SignatureSubject { get; set; }
        public bool IsVirtual { get; set; }
    }

    internal sealed class TpmIdentityRecord
    {
        public string Source { get; set; }
        public bool Present { get; set; }
        public bool Enabled { get; set; }
        public bool Activated { get; set; }
        public bool Owned { get; set; }
        public string ManufacturerId { get; set; }
        public string ManufacturerVersion { get; set; }
        public string SpecVersion { get; set; }
        public string ManagedAuthLevel { get; set; }
    }

    internal sealed class MonitorIdentityRecord
    {
        public string Source { get; set; }
        public string DeviceId { get; set; }
        public string InstanceId { get; set; }
        public string Manufacturer { get; set; }
        public string ProductCode { get; set; }
        public string Serial { get; set; }
        public string FriendlyName { get; set; }
        public string EdidHash { get; set; }
        public string RegistryPath { get; set; }
    }

    internal sealed class DeviceStackRecord
    {
        public string Source { get; set; }
        public string DeviceId { get; set; }
        public string Name { get; set; }
        public string PnpClass { get; set; }
        public string ClassGuid { get; set; }
        public string Manufacturer { get; set; }
        public string Service { get; set; }
        public string Driver { get; set; }
        public string Status { get; set; }
        public string RegistryPath { get; set; }
        public string UpperFilters { get; set; }
        public string LowerFilters { get; set; }
        public bool IsVirtual { get; set; }
    }
}
