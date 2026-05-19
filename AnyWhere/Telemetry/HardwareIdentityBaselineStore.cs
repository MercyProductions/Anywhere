using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal sealed class HardwareIdentityBaselineStore
    {
        private readonly string _path;

        public HardwareIdentityBaselineStore(string path)
        {
            _path = path;
        }

        public bool Exists
        {
            get { return File.Exists(_path); }
        }

        public Dictionary<string, string> Load()
        {
            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (!File.Exists(_path))
            {
                return values;
            }

            foreach (string line in File.ReadAllLines(_path, Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.Ordinal))
                {
                    continue;
                }

                int separator = line.IndexOf('\t');
                if (separator <= 0)
                {
                    continue;
                }

                string key = line.Substring(0, separator);
                string value = line.Substring(separator + 1);
                values[key] = value;
            }

            return values;
        }

        public void Save(Dictionary<string, string> values)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path));
            using (StreamWriter writer = new StreamWriter(_path, false, Encoding.UTF8))
            {
                writer.WriteLine("# Aegis hardware identity baseline");
                writer.WriteLine("# CreatedUtc\t" + DateTime.UtcNow.ToString("o"));
                foreach (KeyValuePair<string, string> pair in values)
                {
                    writer.Write(pair.Key);
                    writer.Write('\t');
                    writer.WriteLine((pair.Value ?? string.Empty).Replace("\r", " ").Replace("\n", " "));
                }
            }
        }
    }
}
