using System;

namespace AnyWhere.Telemetry
{
    internal sealed class DriverFileRecord
    {
        public string Path { get; set; }

        public string NormalizedFileName { get; set; }

        public long SizeBytes { get; set; }

        public DateTime CreatedUtc { get; set; }

        public DateTime ModifiedUtc { get; set; }

        public string SignatureStatus { get; set; }

        public string SignatureSubject { get; set; }

        public string Sha256 { get; set; }
    }
}
