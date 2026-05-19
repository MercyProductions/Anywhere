namespace AnyWhere.Telemetry
{
    internal sealed class MemoryMapRecord
    {
        public int ProcessId { get; set; }

        public string ProcessName { get; set; }

        public string Path { get; set; }

        public string MappingType { get; set; }

        public ulong BaseAddress { get; set; }

        public ulong RegionSize { get; set; }

        public uint Protection { get; set; }
    }
}
