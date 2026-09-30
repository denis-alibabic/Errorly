namespace Errorly.EndpointAuthority;

using System.Security.Cryptography;
using System.Text;

/// <summary>Canonicalizes an HTTP endpoint to its origin authority. Paths never participate in routing attestation.</summary>
public static class CanonicalEndpointAuthority
{
    public static string Normalize(Uri endpoint)
    {
        if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));
        if (!endpoint.IsAbsoluteUri || endpoint.Scheme is not ("http" or "https") || !string.IsNullOrEmpty(endpoint.UserInfo))
            throw new ArgumentException("An absolute credential-free HTTP(S) endpoint is required.", nameof(endpoint));

        var scheme = endpoint.Scheme.ToLowerInvariant();
        var host = endpoint.IdnHost.ToLowerInvariant();
        if (host.Contains(':') && host[0] != '[') host = "[" + host + "]";
        var defaultPort = scheme == "https" ? 443 : 80;
        return endpoint.Port == defaultPort ? $"{scheme}://{host}" : $"{scheme}://{host}:{endpoint.Port}";
    }

    public static string Normalize(string endpoint)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var value))
            throw new ArgumentException("An absolute HTTP(S) endpoint is required.", nameof(endpoint));
        return Normalize(value);
    }

    public static bool TryNormalize(string? endpoint, out string? authority)
    {
        authority = null;
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var value)) return false;
        try { authority = Normalize(value); return true; }
        catch (ArgumentException) { return false; }
    }
}

/// <summary>Creates the non-secret immutable fingerprints shared by the API, SDK Lab, and child protocol.</summary>
public static class WebsiteVerificationBindingFingerprint
{
    public static string Application(Guid applicationId) => Fingerprint(applicationId.ToString("D"));

    public static string Scope(Guid organizationId, Guid applicationId) =>
        Fingerprint(string.Join("\n", organizationId.ToString("D"), applicationId.ToString("D")));

    public static string Create(Uri endpoint, Guid applicationId, string profileKind, string executionMode, string suiteRunId, string contractVersion) =>
        Create(CanonicalEndpointAuthority.Normalize(endpoint), applicationId, profileKind, executionMode, suiteRunId, contractVersion);

    public static string Create(string endpointAuthority, Guid applicationId, string profileKind, string executionMode, string suiteRunId, string contractVersion) =>
        Fingerprint(string.Join("\n", CanonicalEndpointAuthority.Normalize(endpointAuthority), Application(applicationId), profileKind, executionMode, suiteRunId, contractVersion));

    static string Fingerprint(string value)
    {
        using var sha = SHA256.Create();
        var hex = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(value))).Replace("-", string.Empty).ToLowerInvariant();
        return hex.Substring(0, 16);
    }
}
