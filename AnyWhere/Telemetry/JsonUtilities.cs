using System.Text;

namespace AnyWhere.Telemetry
{
    internal static class JsonUtilities
    {
        public static string Escape(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return string.Empty;
            }

            StringBuilder builder = new StringBuilder(value.Length + 8);
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\':
                        builder.Append("\\\\");
                        break;
                    case '"':
                        builder.Append("\\\"");
                        break;
                    case '\b':
                        builder.Append("\\b");
                        break;
                    case '\f':
                        builder.Append("\\f");
                        break;
                    case '\n':
                        builder.Append("\\n");
                        break;
                    case '\r':
                        builder.Append("\\r");
                        break;
                    case '\t':
                        builder.Append("\\t");
                        break;
                    default:
                        if (c < 32)
                        {
                            builder.Append("\\u");
                            builder.Append(((int)c).ToString("x4"));
                        }
                        else
                        {
                            builder.Append(c);
                        }
                        break;
                }
            }

            return builder.ToString();
        }

        public static void AppendStringProperty(StringBuilder builder, string name, string value, ref bool first)
        {
            if (!first)
            {
                builder.Append(",");
            }

            builder.Append("\"");
            builder.Append(Escape(name));
            builder.Append("\":");
            if (value == null)
            {
                builder.Append("null");
            }
            else
            {
                builder.Append("\"");
                builder.Append(Escape(value));
                builder.Append("\"");
            }

            first = false;
        }

        public static void AppendNumberProperty(StringBuilder builder, string name, string value, ref bool first)
        {
            if (!first)
            {
                builder.Append(",");
            }

            builder.Append("\"");
            builder.Append(Escape(name));
            builder.Append("\":");
            builder.Append(string.IsNullOrWhiteSpace(value) ? "0" : value);
            first = false;
        }
    }
}
