using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal static class NativeMethods
    {
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint PROCESS_TERMINATE = 0x0001;
        public const uint PROCESS_CREATE_THREAD = 0x0002;
        public const uint PROCESS_VM_OPERATION = 0x0008;
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_VM_WRITE = 0x0020;
        public const uint PROCESS_DUP_HANDLE = 0x0040;
        public const uint PROCESS_SET_INFORMATION = 0x0200;
        public const uint PROCESS_SUSPEND_RESUME = 0x0800;
        public const uint DUPLICATE_SAME_ACCESS = 0x00000002;

        public const uint SECTION_QUERY = 0x0001;
        public const uint SECTION_MAP_WRITE = 0x0002;
        public const uint SECTION_MAP_READ = 0x0004;
        public const uint SECTION_MAP_EXECUTE = 0x0008;
        public const uint SECTION_EXTEND_SIZE = 0x0010;

        public const uint GENERIC_READ = 0x80000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint OPEN_EXISTING = 3;
        public const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;

        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_IMAGE = 0x1000000;
        public const uint MEM_MAPPED = 0x40000;
        public const uint MEM_PRIVATE = 0x20000;

        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint PAGE_GUARD = 0x100;
        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_WRITECOPY = 0x08;

        public const uint THREAD_QUERY_INFORMATION = 0x0040;
        public const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;

        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_QUERY = 0x0008;
        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

        public const int KEY_NOTIFY = 0x0010;
        public const int KEY_READ = 0x20019;

        public const uint REG_NOTIFY_CHANGE_NAME = 0x00000001;
        public const uint REG_NOTIFY_CHANGE_ATTRIBUTES = 0x00000002;
        public const uint REG_NOTIFY_CHANGE_LAST_SET = 0x00000004;
        public const uint REG_NOTIFY_CHANGE_SECURITY = 0x00000008;

        public const int SystemExtendedHandleInformation = 64;
        public const int ObjectNameInformation = 1;
        public const int ObjectTypeInformation = 2;

        public const int AF_UNSPEC = 0;
        public const uint GAA_FLAG_INCLUDE_PREFIX = 0x00000010;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, int threadId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetProcessId(IntPtr processHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            byte[] buffer,
            int size,
            out IntPtr numberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(
            IntPtr sourceProcessHandle,
            IntPtr sourceHandle,
            IntPtr targetProcessHandle,
            out IntPtr targetHandle,
            uint desiredAccess,
            bool inheritHandle,
            uint options);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeviceIoControl(
            IntPtr device,
            uint ioControlCode,
            ref STORAGE_PROPERTY_QUERY inBuffer,
            int inBufferSize,
            IntPtr outBuffer,
            int outBufferSize,
            out int bytesReturned,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int QueryDosDevice(string deviceName, StringBuilder targetPath, int max);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetVolumeInformation(
            string rootPathName,
            StringBuilder volumeNameBuffer,
            int volumeNameSize,
            out uint volumeSerialNumber,
            out uint maximumComponentLength,
            out uint fileSystemFlags,
            StringBuilder fileSystemNameBuffer,
            int fileSystemNameSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint GetSystemFirmwareTable(
            uint firmwareTableProviderSignature,
            uint firmwareTableId,
            IntPtr firmwareTableBuffer,
            uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UIntPtr VirtualQueryEx(
            IntPtr processHandle,
            IntPtr address,
            out MEMORY_BASIC_INFORMATION buffer,
            UIntPtr length);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int GetMappedFileName(
            IntPtr processHandle,
            IntPtr address,
            StringBuilder fileName,
            int size);

        [DllImport("psapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool EnumDeviceDrivers(
            [Out] IntPtr[] imageBase,
            int cb,
            out int needed);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int GetDeviceDriverFileName(
            IntPtr imageBase,
            StringBuilder fileName,
            int size);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int GetDeviceDriverBaseName(
            IntPtr imageBase,
            StringBuilder baseName,
            int size);

        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(
            int systemInformationClass,
            IntPtr systemInformation,
            int systemInformationLength,
            out int returnLength);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryObject(
            IntPtr handle,
            int objectInformationClass,
            IntPtr objectInformation,
            int objectInformationLength,
            out int returnLength);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationThread(
            IntPtr threadHandle,
            int threadInformationClass,
            out IntPtr threadInformation,
            int threadInformationLength,
            IntPtr returnLength);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetAdaptersAddresses(
            int family,
            uint flags,
            IntPtr reserved,
            IntPtr adapterAddresses,
            ref int sizePointer);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr processHandle,
            uint desiredAccess,
            out IntPtr tokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeValue(
            string systemName,
            string name,
            out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr tokenHandle,
            bool disableAllPrivileges,
            ref TOKEN_PRIVILEGES newState,
            int bufferLength,
            IntPtr previousState,
            IntPtr returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegOpenKeyEx(
            IntPtr key,
            string subKey,
            int options,
            int desiredAccess,
            out IntPtr result);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegNotifyChangeKeyValue(
            IntPtr key,
            bool watchSubtree,
            uint notifyFilter,
            IntPtr eventHandle,
            bool asynchronous);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(IntPtr key);

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
        {
            public IntPtr Object;
            public UIntPtr UniqueProcessId;
            public UIntPtr HandleValue;
            public uint GrantedAccess;
            public ushort CreatorBackTraceIndex;
            public ushort ObjectTypeIndex;
            public uint HandleAttributes;
            public uint Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STORAGE_PROPERTY_QUERY
        {
            public int PropertyId;
            public int QueryType;
            public byte AdditionalParameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STORAGE_DEVICE_DESCRIPTOR
        {
            public uint Version;
            public uint Size;
            public byte DeviceType;
            public byte DeviceTypeModifier;
            [MarshalAs(UnmanagedType.Bool)]
            public bool RemovableMedia;
            [MarshalAs(UnmanagedType.Bool)]
            public bool CommandQueueing;
            public uint VendorIdOffset;
            public uint ProductIdOffset;
            public uint ProductRevisionOffset;
            public uint SerialNumberOffset;
            public int BusType;
            public uint RawPropertiesLength;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct IP_ADAPTER_ADDRESSES
        {
            public uint Length;
            public uint IfIndex;
            public IntPtr Next;
            public IntPtr AdapterName;
            public IntPtr FirstUnicastAddress;
            public IntPtr FirstAnycastAddress;
            public IntPtr FirstMulticastAddress;
            public IntPtr FirstDnsServerAddress;
            public IntPtr DnsSuffix;
            public IntPtr Description;
            public IntPtr FriendlyName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] PhysicalAddress;
            public uint PhysicalAddressLength;
            public uint Flags;
            public uint Mtu;
            public uint IfType;
            public uint OperStatus;
            public uint Ipv6IfIndex;
        }
    }
}
