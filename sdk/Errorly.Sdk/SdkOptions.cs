namespace Errorly;

public enum ErrorlyApplicationKind { Unknown, Console, WorkerService, Wpf, WinForms, AspNetCore }

/// <summary>Do not place credentials in application source or source-controlled configuration.</summary>
public sealed class SdkOptions
{
    public Uri? ServerBaseUrl { get; set; }
    public string? ApiKey { get; set; }
    /// <summary>Optional HTTPS DSN. A user-info credential is extracted and never retained in the endpoint.</summary>
    public string? Dsn { get; set; }
    public string? OutboxPath { get; set; }
    public string? ApplicationName { get; set; }
    public string? Environment { get; set; }
    public string? Release { get; set; }
    /// <summary>Optional build-supplied source revision used to resolve repository source at the exact build.</summary>
    public string? SourceRevision { get; set; }
    public ErrorlyApplicationKind ApplicationKind { get; set; }
    public bool AutomaticCapture { get; set; }=true;
    public bool AutomaticUpload { get; set; }=true;
    /// <summary>Refreshes the server runtime policy in the background. Verification hosts can disable this and refresh explicitly.</summary>
    public bool AutomaticPolicyRefresh { get; set; }=true;
    public TimeSpan ShutdownTimeout { get; set; }=TimeSpan.FromSeconds(2);
    /// <summary>Optional synchronous observer for bounded, non-secret SDK release diagnostics. Exceptions are contained.</summary>
    public Action<ErrorlyDiagnostic>? DiagnosticCallback { get; set; }
    /// <summary>Optional caller-owned transport, primarily useful for dependency injection.</summary>
    public System.Net.Http.HttpClient? HttpClient { get; set; }
}

public static class ErrorlySdk
{
    /// <summary>Creates an isolated lifetime. Invalid configuration safely creates a disabled client.</summary>
    public static ErrorlySdkClient Initialize(SdkOptions options)=>new(options??new SdkOptions());
}
