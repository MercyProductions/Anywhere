namespace AnyWhere.Telemetry
{
    internal sealed class DriverServiceRecord
    {
        public string Name { get; set; }

        public string DisplayName { get; set; }

        public string State { get; set; }

        public string StartMode { get; set; }

        public string ServiceType { get; set; }

        public string PathName { get; set; }

        public string NormalizedPath { get; set; }

        public string NormalizedFileName { get; set; }

        public bool IsRunning
        {
            get { return string.Equals(State, "Running", System.StringComparison.OrdinalIgnoreCase); }
        }
    }
}
