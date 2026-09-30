using System;
using System.Collections.Generic;
using System.Linq;

namespace Errorly.SdkLab.Contracts;

public static class SdkLabProtocol
{
    public const int SchemaVersion = 1;
    public const int MaxRequestBytes = 32 * 1024;
    public const int MaxInputBytes = 8 * 1024;
    public const int MaxResultBytes = 64 * 1024;
    public const int MaxOptions = 24;
    public const int MaxItems = 32;
    public const int MaxIdentifierLength = 96;
    public const int MaxSafeValueLength = 256;
    public const string RequestArgument = "--sdk-lab-request";
    public const string ResultArgument = "--sdk-lab-result";
    public const string ApiKeyEnvironmentVariable = "ERRORLY_SDK_LAB_API_KEY";
    public const string ChildOutboxDirectoryName = "ErrorlySdkLab";

    public static bool IsSafeIdentifier(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value!.Length <= MaxIdentifierLength &&
        value.All(character => char.IsLetterOrDigit(character) || character == '-' || character == '_' || character == '.');

    public static string GetChildOutboxPath(string temporaryRoot, string commandId)
    {
        if (string.IsNullOrWhiteSpace(temporaryRoot)) throw new ArgumentException("A temporary root is required.", nameof(temporaryRoot));
        if (!IsSafeIdentifier(commandId)) throw new ArgumentException("The command identifier is invalid.", nameof(commandId));
        var root = System.IO.Path.GetFullPath(System.IO.Path.Combine(temporaryRoot, ChildOutboxDirectoryName));
        var candidate = System.IO.Path.GetFullPath(System.IO.Path.Combine(root, commandId));
        if (!candidate.StartsWith(root + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("The command outbox escaped its root.", nameof(commandId));
        return candidate;
    }
}

public static class SdkLabTargetIds
{
    public const string Net48Console = "net48-console";
    public const string Net48Wpf = "net48-wpf";
    public const string Net48WinForms = "net48-winforms";
    public const string Net6Console = "net6-console";
    public const string Net6WebApi = "net6-webapi";
    public const string Net6Worker = "net6-worker";
    public const string Net10Console = "net10-console";
    public const string Net10WebApi = "net10-webapi";
    public const string Net10Worker = "net10-worker";

    public static readonly IReadOnlyList<string> All = Array.AsReadOnly(new[]
    {
        Net48Console, Net48Wpf, Net48WinForms, Net6Console, Net6WebApi, Net6Worker,
        Net10Console, Net10WebApi, Net10Worker
    });

    public static bool IsKnown(string? value) => value != null && All.Contains(value, StringComparer.Ordinal);
}

public static class SdkLabScenarioIds
{
    public const string InitValid = "init.valid";
    public const string ManualHandledException = "manual.handled-exception";
    public const string ManualMessage = "manual.message";
    public const string AutoConsoleUnhandled = "auto.console-unhandled";
    public const string AutoWpfDispatcher = "auto.wpf-dispatcher";
    public const string AutoWinFormsUi = "auto.winforms-ui";
    public const string AutoWorkerBackground = "auto.worker-background";
    public const string AutoAspNetRequest = "auto.aspnet-request";
    public const string DeliveryUnavailable = "delivery.unavailable";
    public const string GovernanceSupported = "governance.supported";
    public const string GovernanceDeprecated = "governance.deprecated";
    public const string GovernanceBlocked = "governance.blocked";

    public static readonly IReadOnlyList<string> All = Array.AsReadOnly(new[]
    {
        "init.valid", "init.missing-credentials", "init.malformed-config",
        "manual.handled-exception", "manual.message", "manual.breadcrumbs", "manual.tags", "manual.user-context",
        "manual.aggregate-exception", "manual.cancellation", "manual.repeated", "manual.flush-shutdown", "manual.limits", "manual.large-context",
        "auto.appdomain-unhandled", "auto.unobserved-task", "auto.wpf-dispatcher", "auto.winforms-ui", "auto.console-unhandled",
        "auto.worker-background", "auto.aspnet-request", "auto.middleware-status", "auto.minimal-api", "auto.controller-api", "auto.handler-dedup", "auto.fatal-flush",
        "privacy.log-enabled", "privacy.log-disabled", "privacy.level", "privacy.entry-byte-caps", "privacy.redaction", "privacy.identity-disabled",
        "privacy.identity-enabled", "privacy.property-filter", "privacy.default-environment", "privacy.ignore-rule", "privacy.malformed-policy", "privacy.offline-expired-policy",
        "delivery.unavailable", "delivery.timeout", "delivery.retry", "delivery.restart-recovery", "delivery.store-forward", "delivery.quota-rejection",
        "delivery.payload-rejection", "delivery.malformed-response", "delivery.flush-timeout", "delivery.classification", "delivery.quarantine-cleanup",
        "governance.supported", "governance.deprecated", "governance.blocked", "governance.cached-block-restart", "governance.cache-binding",
        "governance.cache-expiry", "governance.store-failure-known-blocked", "governance.legacy-fail-open", "governance.terminal-quarantine",
        "governance.no-retry-storm", "governance.minimum-safe", "issue.cross-target-grouping", "issue.distinct-fingerprint", "issue.runtime-neutral",
        "issue.environment-release", "issue.occurrence-runtime", "issue.runtime-summary", "issue.runtime-filter", "issue.legacy-runtime"
    });

    public static bool IsKnown(string? value) => value != null && All.Contains(value, StringComparer.Ordinal);
}

public sealed class SdkLabChildRequest
{
    public int SchemaVersion { get; set; }
    public string? RunId { get; set; }
    public string? CommandId { get; set; }
    public string? TargetId { get; set; }
    public string? ScenarioId { get; set; }
    public string? CorrelationId { get; set; }
    public string? ProfileKind { get; set; }
    public string? ProfileName { get; set; }
    public int TimeoutMs { get; set; }
    public Dictionary<string, string>? Options { get; set; }
}

public sealed class SdkLabChildInput
{
    public int SchemaVersion { get; set; }
    public string? RunId { get; set; }
    public string? CommandId { get; set; }
    public string? ServerBaseUrl { get; set; }
    public string? ApiKey { get; set; }
    public bool ExternalEndpointConfirmed { get; set; }
}

public sealed class SdkLabChildResult
{
    public int SchemaVersion { get; set; }
    public string? RunId { get; set; }
    public string? CommandId { get; set; }
    public string? TargetId { get; set; }
    public string? ScenarioId { get; set; }
    public string? CorrelationId { get; set; }
    public string? Status { get; set; }
    public DateTimeOffset StartedUtc { get; set; }
    public DateTimeOffset CompletedUtc { get; set; }
    public long DurationMs { get; set; }
    public SdkLabRuntimeFacts? Runtime { get; set; }
    public string? Expected { get; set; }
    public string? Observed { get; set; }
    public string? Verification { get; set; }
    public List<string> DiagnosticCodes { get; set; } = new();
    public int? ExitCode { get; set; }
    public string? Termination { get; set; }
    public string? Cleanup { get; set; }
    public string? IncidentId { get; set; }
    public int DeliveryAttempts { get; set; }
    public string? SafeRejectionCode { get; set; }
    public int? HttpStatusCode { get; set; }
    public string? HttpStatusFamily { get; set; }
    public SdkLabDeliveryDiagnostics? Delivery { get; set; }
    public string? ExecutionBindingEndpointAuthority { get; set; }
    public string? ExecutionBindingApplicationIdFingerprint { get; set; }
    public string? ExecutionBindingProfileKind { get; set; }
    public string? ExecutionBindingMode { get; set; }
    public string? ExecutionBindingSuiteRunId { get; set; }
    public string? ExecutionBindingContractVersion { get; set; }
    public string? ExecutionBindingFingerprint { get; set; }
    public SdkLabSourceSymbolFacts? SourceSymbols { get; set; }
}

public sealed class SdkLabSourceSymbolFacts
{
    public string? ModuleName { get; set; }
    public string? ModuleVersionId { get; set; }
    public string? PortablePdbId { get; set; }
    public int PortablePdbAge { get; set; }
    public uint PortablePdbStamp { get; set; }
    public int MethodMetadataToken { get; set; }
    public int IlOffset { get; set; }
    public string? ExpectedSourcePath { get; set; }
    public int ExpectedSourceLine { get; set; }
}

public sealed class SdkLabDeliveryDiagnostics
{
    // EndpointAuthority is retained for v7 history compatibility. New results use the explicit configured/receipt fields.
    public string? EndpointAuthority { get; set; }
    public string? ConfiguredEndpointAuthority { get; set; }
    public string? ReceiptEndpointAuthority { get; set; }
    public string? CredentialEnvelope { get; set; }
    public string? RequestProtocol { get; set; }
    public int AttemptCount { get; set; }
    public DateTimeOffset? FirstAttemptUtc { get; set; }
    public long AttemptDurationMs { get; set; }
    public long FlushDurationMs { get; set; }
    public string? FlushState { get; set; }
    public string? QueueState { get; set; }
    public string? TransportState { get; set; }
    public string? ShutdownOrdering { get; set; }
}

public sealed class SdkLabRuntimeFacts
{
    public string? PackageName { get; set; }
    public string? PackageVersion { get; set; }
    public string? TargetFramework { get; set; }
    public string? ApplicationKind { get; set; }
    public string? RuntimeFamily { get; set; }
    public string? RuntimeVersion { get; set; }
    public string? ProcessArchitecture { get; set; }
}

public static class SdkLabContractValidator
{
    public static bool TryValidate(SdkLabChildRequest? request, out string diagnosticCode)
    {
        diagnosticCode = "InvalidRequest";
        if (request == null || request.SchemaVersion != SdkLabProtocol.SchemaVersion) return false;
        if (!SdkLabTargetIds.IsKnown(request.TargetId)) { diagnosticCode = "UnknownTarget"; return false; }
        if (!SdkLabProtocol.IsSafeIdentifier(request.RunId) || !SdkLabProtocol.IsSafeIdentifier(request.CommandId) ||
            !SdkLabProtocol.IsSafeIdentifier(request.ScenarioId) || !SdkLabProtocol.IsSafeIdentifier(request.CorrelationId)) return false;
        if (request.ProfileKind != "Local" && request.ProfileKind != "Server") { diagnosticCode = "InvalidProfileKind"; return false; }
        if (request.ProfileName != null && (request.ProfileName.Length > SdkLabProtocol.MaxSafeValueLength || request.ProfileName.Any(char.IsControl))) return false;
        if (request.TimeoutMs < 250 || request.TimeoutMs > 240000) { diagnosticCode = "InvalidTimeout"; return false; }
        if ((request.Options?.Count ?? 0) > SdkLabProtocol.MaxOptions) { diagnosticCode = "TooManyOptions"; return false; }
        if (request.Options != null && request.Options.Any(pair => !SdkLabProtocol.IsSafeIdentifier(pair.Key) || pair.Value == null ||
            pair.Value.Length > SdkLabProtocol.MaxSafeValueLength || pair.Value.Any(char.IsControl))) return false;
        diagnosticCode = "Valid";
        return true;
    }

    public static bool TryValidate(SdkLabChildInput? input, SdkLabChildRequest request, out string diagnosticCode)
    {
        diagnosticCode = "InvalidInput";
        if (input == null || input.SchemaVersion != SdkLabProtocol.SchemaVersion || input.RunId != request.RunId || input.CommandId != request.CommandId) return false;
        if (string.IsNullOrEmpty(input.ApiKey) || input.ApiKey!.Length > 512 || input.ApiKey.Any(char.IsControl)) { diagnosticCode = "InvalidCredential"; return false; }
        if (!Uri.TryCreate(input.ServerBaseUrl, UriKind.Absolute, out var endpoint) || !string.IsNullOrEmpty(endpoint.UserInfo) ||
            !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment) ||
            (endpoint.IsLoopback ? endpoint.Scheme != Uri.UriSchemeHttps && endpoint.Scheme != Uri.UriSchemeHttp :
            !input.ExternalEndpointConfirmed || endpoint.Scheme != Uri.UriSchemeHttps))
        { diagnosticCode = "InvalidEndpoint"; return false; }
        diagnosticCode = "Valid";
        return true;
    }
}
