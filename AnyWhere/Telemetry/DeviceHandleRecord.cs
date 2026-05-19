namespace AnyWhere.Telemetry
{
    internal sealed class DeviceHandleRecord
    {
        public int ProcessId { get; set; }

        public string ProcessName { get; set; }

        public string ObjectType { get; set; }

        public string ObjectName { get; set; }

        public uint GrantedAccess { get; set; }

        public ulong HandleValue { get; set; }
    }
}
