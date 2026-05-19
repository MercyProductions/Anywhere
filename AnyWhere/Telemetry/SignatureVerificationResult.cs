namespace AnyWhere.Telemetry
{
    internal sealed class SignatureVerificationResult
    {
        public string Status { get; set; }

        public string Subject { get; set; }

        public int WinVerifyTrustStatus { get; set; }

        public bool IsTrusted
        {
            get { return Status == "Trusted"; }
        }
    }
}
