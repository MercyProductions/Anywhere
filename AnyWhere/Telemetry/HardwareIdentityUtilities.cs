using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace AnyWhere.Telemetry
{
    internal static class HardwareIdentityUtilities
    {
        public static string NormalizeIdentifier(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            string trimmed = value.Trim().Trim('\0').Trim();
            if (trimmed.Length == 0)
            {
                return null;
            }

            return trimmed.ToUpperInvariant();
        }

        public static string NormalizeMac(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            StringBuilder builder = new StringBuilder();
            foreach (char c in value)
            {
                if (Uri.IsHexDigit(c))
                {
                    builder.Append(char.ToUpperInvariant(c));
                }
            }

            if (builder.Length != 12)
            {
                return null;
            }

            return builder.ToString();
        }

        public static bool IsBlankOrZero(string value)
        {
            string normalized = NormalizeIdentifier(value);
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return true;
            }

            string compact = normalized.Replace("-", string.Empty).Replace(" ", string.Empty);
            if (compact.Length == 0)
            {
                return true;
            }

            bool allZero = true;
            for (int i = 0; i < compact.Length; i++)
            {
                if (compact[i] != '0')
                {
                    allZero = false;
                    break;
                }
            }

            if (allZero)
            {
                return true;
            }

            string[] generic =
            {
                "UNKNOWN", "NONE", "NULL", "N/A", "NA", "TO BE FILLED BY O.E.M.",
                "TO BE FILLED BY OEM", "SYSTEM SERIAL NUMBER", "DEFAULT STRING",
                "OEM", "00000000", "FFFFFFFF"
            };

            foreach (string token in generic)
            {
                if (normalized.Equals(token, StringComparison.OrdinalIgnoreCase) ||
                    normalized.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        public static bool IsLocallyAdministeredMac(string mac)
        {
            string normalized = NormalizeMac(mac);
            if (string.IsNullOrWhiteSpace(normalized))
            {
                return false;
            }

            int firstOctet = int.Parse(normalized.Substring(0, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return (firstOctet & 0x02) != 0;
        }

        public static bool LooksVirtual(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            string lower = value.ToLowerInvariant();
            string[] terms =
            {
                "virtual", "vmware", "vbox", "virtualbox", "hyper-v", "hyperv", "qemu",
                "parallels", "tap-windows", "wireguard", "tailscale", "zerotier",
                "npcap", "loopback", "rdp", "remote display", "basic render",
                "microsoft basic display", "parsec", "moonlight"
            };

            foreach (string term in terms)
            {
                if (lower.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }

            return false;
        }

        public static string Sha256Hex(byte[] bytes)
        {
            if (bytes == null)
            {
                return null;
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(bytes);
                StringBuilder builder = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
                }

                return builder.ToString();
            }
        }

        public static string JoinNonEmpty(IEnumerable<string> values, string separator)
        {
            List<string> nonEmpty = new List<string>();
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    nonEmpty.Add(value);
                }
            }

            return string.Join(separator, nonEmpty.ToArray());
        }
    }
}
