# Errorly SDK family

`Errorly.Sdk` supplies bounded manual/automatic incident capture and a durable outbox for `net462`, `net6.0`, and `net10.0`. Optional `Errorly.Wpf`, `Errorly.WinForms`, `Errorly.AspNetCore`, and `Errorly.Extensions.Logging` packages add their respective framework integrations. Desktop integrations require Windows. Native WPF replay remains the existing Windows x64 recorder exposed through `ErrorlyWpf.InitializeNative` on the .NET 10 Windows target.

```csharp
using var client = Errorly.ErrorlySdk.Initialize(new Errorly.SdkOptions {
    ServerBaseUrl = new Uri(serverFromConfiguration),
    ApiKey = keyFromSecureConfiguration,
    Environment = "Production",
    Release = "1.0.0",
    ApplicationKind = Errorly.ErrorlyApplicationKind.Console
});
client.AddBreadcrumb("Started save operation");
try { Save(); }
catch (Exception error) { await client.CaptureExceptionAsync(error); }
await client.ShutdownAsync();
```

Missing credentials produce an inert client. Use one client lifetime per application; DI integrations share that instance. Configure only nonsecret application/release/environment values. User/context/tag properties are bounded incident log context and obey the server log/privacy policy. HTTP integrations never capture request paths, bodies, cookies, authorization headers or remote identity; request paths are only inspected transiently for configured ignore rules.

The managed SDK limits in-flight captures to eight and the local outbox to 256 packages / 64 MiB, including rejected evidence. Uploads retain the incident ID across retries. Outboxes are bound to the endpoint and credential fingerprint; use a new outbox when changing credentials. Flush/shutdown are best effort and bounded by cancellation; abrupt process termination, full disks and unavailable storage cannot guarantee delivery. .NET Framework applications must enable OS-default modern TLS/strong cryptography in host configuration. The SDK does not modify process-global TLS policy.

## SDK release policy

Package name and semantic version are generated from the official package assembly at build time; application options cannot replace them. Runtime-policy requests include that identity, target framework, and application kind in bounded headers, while the incident package remains the ingestion source of truth. Older Errorly servers that omit release-policy fields continue to work normally.

A `sdk_deprecated` advisory never stops capture or delivery. It is available from `CurrentReleaseAdvisory` and through the optional `DiagnosticCallback`. A valid HTTP 426 `sdk_blocked` response is terminal for that package/version: it is not retried, matching backlog entries are quarantined, and capture is suppressed for a five-minute bounded cache window. That decision is also cached in a single, at-most-4 KiB record inside the outbox so a process restart cannot cause another immediate delivery storm. The record is bound to the existing SHA-256 digest of the server authority and credential—never their raw values—and to the exact package, semantic version, package-asset TFM, and application kind. It persists only decision metadata, required version, safe reason category, receipt time, and expiry; response bodies, messages, and documentation URLs are not stored. Cache records fail open when expired, malformed, differently bound, or mismatched. At most 16 blocked package files are retained locally as diagnostic samples; older samples are deleted. Quarantined files are never uploaded automatically. Callbacks are synchronous, contain only bounded server guidance, and callback failures cannot escape into the host application.

Release policy only controls Errorly telemetry delivery. The SDK cannot update packages, execute remote code, alter the host application's deployment, or force a customer application to upgrade. Updating and redeploying remain explicit customer operations, and a telemetry rejection never terminates or disables the host application.

.NET 6 is an explicitly supported compatibility target of this SDK; Microsoft has ended support for that runtime. Install the appropriate runtime yourself. No native replay is promised for the managed-only .NET Framework/.NET 6 adapters.
