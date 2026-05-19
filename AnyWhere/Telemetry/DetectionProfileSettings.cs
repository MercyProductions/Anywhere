using System;

namespace AnyWhere.Telemetry
{
    internal sealed class DetectionProfileSettings
    {
        public string Name { get; private set; }

        public double RuleMatchThreshold { get; private set; }

        public double HighConfidenceThreshold { get; private set; }

        public double CriticalConfidenceThreshold { get; private set; }

        public double DriverWeight { get; private set; }

        public double SpooferWeight { get; private set; }

        public double MemoryWeight { get; private set; }

        public double TrustedProcessWeight { get; private set; }

        public bool SuppressKnownGoodLowSignals { get; private set; }

        public bool EmitMediumRuleMatches { get; private set; }

        public static DetectionProfileSettings FromName(string name)
        {
            string normalized = (name ?? "balanced").Trim().ToLowerInvariant().Replace("_", "-");
            DetectionProfileSettings settings = Balanced();

            if (normalized == "aggressive")
            {
                settings.Name = "aggressive";
                settings.RuleMatchThreshold = 0.50;
                settings.HighConfidenceThreshold = 0.62;
                settings.CriticalConfidenceThreshold = 0.84;
                settings.SuppressKnownGoodLowSignals = false;
                settings.EmitMediumRuleMatches = true;
            }
            else if (normalized == "silent-telemetry" || normalized == "silent")
            {
                settings.Name = "silent_telemetry";
                settings.RuleMatchThreshold = 0.78;
                settings.HighConfidenceThreshold = 0.86;
                settings.CriticalConfidenceThreshold = 0.96;
                settings.SuppressKnownGoodLowSignals = true;
                settings.EmitMediumRuleMatches = false;
            }
            else if (normalized == "anti-spoofer" || normalized == "anti-spoofer-focus")
            {
                settings.Name = "anti_spoofer_focus";
                settings.SpooferWeight = 1.35;
                settings.DriverWeight = 1.15;
                settings.RuleMatchThreshold = 0.58;
                settings.HighConfidenceThreshold = 0.68;
                settings.CriticalConfidenceThreshold = 0.88;
            }
            else if (normalized == "anti-hidden-driver" || normalized == "anti-hidden-driver-focus")
            {
                settings.Name = "anti_hidden_driver_focus";
                settings.DriverWeight = 1.35;
                settings.MemoryWeight = 1.15;
                settings.RuleMatchThreshold = 0.58;
                settings.HighConfidenceThreshold = 0.68;
                settings.CriticalConfidenceThreshold = 0.88;
            }
            else if (normalized == "development" || normalized == "testing" || normalized == "development-testing")
            {
                settings.Name = "development_testing";
                settings.RuleMatchThreshold = 0.42;
                settings.HighConfidenceThreshold = 0.55;
                settings.CriticalConfidenceThreshold = 0.80;
                settings.SuppressKnownGoodLowSignals = false;
                settings.EmitMediumRuleMatches = true;
            }

            return settings;
        }

        private static DetectionProfileSettings Balanced()
        {
            return new DetectionProfileSettings
            {
                Name = "balanced",
                RuleMatchThreshold = 0.60,
                HighConfidenceThreshold = 0.72,
                CriticalConfidenceThreshold = 0.90,
                DriverWeight = 1.0,
                SpooferWeight = 1.0,
                MemoryWeight = 1.0,
                TrustedProcessWeight = 1.0,
                SuppressKnownGoodLowSignals = true,
                EmitMediumRuleMatches = true
            };
        }
    }
}
