namespace AnyWhere.Telemetry
{
    internal sealed class LoadedKernelModuleRecord
    {
        public string BaseName { get; set; }

        public string Path { get; set; }

        public string NormalizedPath { get; set; }

        public string NormalizedFileName { get; set; }

        public ulong ImageBase { get; set; }
    }
}
