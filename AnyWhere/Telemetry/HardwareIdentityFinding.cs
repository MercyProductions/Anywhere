using System.Collections.Generic;

namespace AnyWhere.Telemetry
{
    internal sealed class HardwareIdentityFinding
    {
        public HardwareIdentityFinding()
        {
            Details = new Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase);
        }

        public string Action { get; set; }

        public EventSeverity Severity { get; set; }

        public string Description { get; set; }

        public string IdentifierType { get; set; }

        public string SourceA { get; set; }

        public string SourceAValue { get; set; }

        public string SourceB { get; set; }

        public string SourceBValue { get; set; }

        public string BaselineValue { get; set; }

        public string CurrentValue { get; set; }

        public double ConfidenceScore { get; set; }

        public Dictionary<string, string> Details { get; private set; }
    }
}
