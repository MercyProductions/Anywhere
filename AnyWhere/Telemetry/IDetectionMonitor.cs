using System;

namespace AnyWhere.Telemetry
{
    internal interface IDetectionMonitor : IDisposable
    {
        string Name { get; }

        void Start();
    }
}
