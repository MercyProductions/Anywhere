namespace AnyWhere.Telemetry
{
    internal sealed class EventLogSubscriptionTarget
    {
        public EventLogSubscriptionTarget(string name, string logName, string query)
        {
            Name = name;
            LogName = logName;
            Query = query;
        }

        public string Name { get; private set; }

        public string LogName { get; private set; }

        public string Query { get; private set; }
    }
}
