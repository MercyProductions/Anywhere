using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;

namespace AnyWhere.Telemetry
{
    internal static class DxgiAdapterInventory
    {
        public static List<GpuIdentityRecord> Capture(EventLogger logger)
        {
            List<GpuIdentityRecord> records = new List<GpuIdentityRecord>();
            IDXGIFactory1 factory;
            Guid factoryGuid = typeof(IDXGIFactory1).GUID;
            int createResult = CreateDXGIFactory1(ref factoryGuid, out factory);
            if (createResult != 0 || factory == null)
            {
                return records;
            }

            try
            {
                for (uint i = 0; i < 32; i++)
                {
                    IDXGIAdapter1 adapter;
                    int result = factory.EnumAdapters1(i, out adapter);
                    if (result != 0 || adapter == null)
                    {
                        break;
                    }

                    try
                    {
                        DXGI_ADAPTER_DESC1 desc;
                        if (adapter.GetDesc1(out desc) == 0)
                        {
                            string name = desc.Description;
                            records.Add(new GpuIdentityRecord
                            {
                                Source = "DXGI",
                                Name = name,
                                Vendor = "0x" + desc.VendorId.ToString("X", CultureInfo.InvariantCulture),
                                DeviceId = "0x" + desc.DeviceId.ToString("X", CultureInfo.InvariantCulture),
                                IsVirtual = HardwareIdentityUtilities.LooksVirtual(name)
                            });
                        }
                    }
                    finally
                    {
                        Marshal.ReleaseComObject(adapter);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogException("HardwareIdentity", "DxgiCaptureFailed", ex, null);
            }
            finally
            {
                Marshal.ReleaseComObject(factory);
            }

            return records;
        }

        [DllImport("dxgi.dll")]
        private static extern int CreateDXGIFactory1(ref Guid riid, out IDXGIFactory1 factory);

        [ComImport]
        [Guid("770aae78-f26f-4dba-a829-253c83d1b387")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IDXGIFactory1
        {
            [PreserveSig]
            int SetPrivateData(ref Guid name, uint dataSize, IntPtr data);

            [PreserveSig]
            int SetPrivateDataInterface(ref Guid name, IntPtr unknown);

            [PreserveSig]
            int GetPrivateData(ref Guid name, ref uint dataSize, IntPtr data);

            [PreserveSig]
            int GetParent(ref Guid riid, out IntPtr parent);

            [PreserveSig]
            int EnumAdapters(uint adapter, out IntPtr adapterInterface);

            [PreserveSig]
            int MakeWindowAssociation(IntPtr windowHandle, uint flags);

            [PreserveSig]
            int GetWindowAssociation(out IntPtr windowHandle);

            [PreserveSig]
            int CreateSwapChain(IntPtr device, IntPtr desc, out IntPtr swapChain);

            [PreserveSig]
            int CreateSoftwareAdapter(IntPtr module, out IntPtr adapter);

            [PreserveSig]
            int EnumAdapters1(uint adapter, out IDXGIAdapter1 adapterInterface);

            [PreserveSig]
            bool IsCurrent();
        }

        [ComImport]
        [Guid("29038f61-3839-4626-91fd-086879011a05")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IDXGIAdapter1
        {
            [PreserveSig]
            int SetPrivateData(ref Guid name, uint dataSize, IntPtr data);

            [PreserveSig]
            int SetPrivateDataInterface(ref Guid name, IntPtr unknown);

            [PreserveSig]
            int GetPrivateData(ref Guid name, ref uint dataSize, IntPtr data);

            [PreserveSig]
            int GetParent(ref Guid riid, out IntPtr parent);

            [PreserveSig]
            int EnumOutputs(uint output, out IntPtr outputInterface);

            [PreserveSig]
            int GetDesc(out DXGI_ADAPTER_DESC desc);

            [PreserveSig]
            int CheckInterfaceSupport(ref Guid interfaceName, out long umdVersion);

            [PreserveSig]
            int GetDesc1(out DXGI_ADAPTER_DESC1 desc);
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DXGI_ADAPTER_DESC
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string Description;
            public uint VendorId;
            public uint DeviceId;
            public uint SubSysId;
            public uint Revision;
            public UIntPtr DedicatedVideoMemory;
            public UIntPtr DedicatedSystemMemory;
            public UIntPtr SharedSystemMemory;
            public long AdapterLuid;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DXGI_ADAPTER_DESC1
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string Description;
            public uint VendorId;
            public uint DeviceId;
            public uint SubSysId;
            public uint Revision;
            public UIntPtr DedicatedVideoMemory;
            public UIntPtr DedicatedSystemMemory;
            public UIntPtr SharedSystemMemory;
            public long AdapterLuid;
            public uint Flags;
        }
    }
}
