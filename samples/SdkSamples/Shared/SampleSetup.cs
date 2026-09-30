using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Errorly;
using Errorly.SdkLab.Contracts;
using Errorly.EndpointAuthority;

internal static class SampleSetup
{
    public static bool Verification { get; private set; }
    public static string RunId { get; private set; }
    public static int DeliveryTimeoutSeconds { get; private set; } = 45;
    public static int ShutdownTimeoutSeconds { get; private set; } = 5;
    private static string verificationOutbox;
    private static VerificationTransport verificationTransport;
    private static HttpClient verificationHttp;
    private static int resultWritten;
    private static SdkLabChildRequest labRequest;
    private static string labResultPath;
    private static string labConfigurationError;
    private static LabTransport labTransport;
    private static string labOutbox;
    private static string labApiKey;
    private static string labServerUrl;
    private static string labCredentialEnvelope = "MissingOrInvalid";
    private static long labFlushDurationMs;
    private static string labFlushState = "NotStarted";
    public static object LastResult { get; private set; }
    private const string ControlledMessage = "Errorly SDK sample verification";
    public static bool Configure(string[] args)
    {
        if (IsSmoke(args)) { ClearCredentials(); return true; }
        var labRequestIndex = Array.IndexOf(args, SdkLabProtocol.RequestArgument);
        var labResultIndex = Array.IndexOf(args, SdkLabProtocol.ResultArgument);
        if (labRequestIndex >= 0 || labResultIndex >= 0)
        {
            ClearCredentials();
            Environment.SetEnvironmentVariable(SdkLabProtocol.ApiKeyEnvironmentVariable, null);
            if (labRequestIndex < 0 || labResultIndex < 0 || labRequestIndex + 1 >= args.Length || labResultIndex + 1 >= args.Length)
                return false;
            labResultPath = SafeFullPath(args[labResultIndex + 1]);
            try
            {
                var requestPath = SafeFullPath(args[labRequestIndex + 1]);
                if (requestPath == null || labResultPath == null) return false;
                var info = new FileInfo(requestPath);
                if (!info.Exists || info.Length <= 0 || info.Length > SdkLabProtocol.MaxRequestBytes) return false;
                labRequest = JsonSerializer.Deserialize<SdkLabChildRequest>(File.ReadAllBytes(requestPath), LabJsonOptions());
                if (!ValidLabRequest(labRequest)) { labRequest = null; return false; }
                if (labRequest.ProfileKind == "Server" && !ReadLabInput()) { labRequest = null; return false; }
                return true;
            }
            catch { labRequest = null; return false; }
        }
        Verification = Array.IndexOf(args, "--verify") >= 0;
        if (!Verification) return true;
        var index = Array.IndexOf(args, "--run-id");
        var value = index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
        if (value == null || !Regex.IsMatch(value, @"\ASDK-SAMPLE-[0-9]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z") || value != Environment.GetEnvironmentVariable("ERRORLY_SAMPLE_RUN_ID"))
        { ClearCredentials(); WriteResult(null, false, "InvalidRunId"); return false; }
        RunId = value;
        DeliveryTimeoutSeconds = SafeSeconds("ERRORLY_SAMPLE_DELIVERY_TIMEOUT_SECONDS", 45, 120);
        ShutdownTimeoutSeconds = SafeSeconds("ERRORLY_SAMPLE_SHUTDOWN_TIMEOUT_SECONDS", 5, 15);
        return true;
    }
    public static bool LabChild => labRequest != null;
    public static bool IsLabScenario(string scenarioId) => LabChild && string.Equals(NormalizeScenario(labRequest.ScenarioId), scenarioId, StringComparison.Ordinal);
    private static int SafeSeconds(string name, int fallback, int maximum)
    { int value; return int.TryParse(Environment.GetEnvironmentVariable(name), out value) && value >= 1 && value <= maximum ? value : fallback; }
    private static string SafeLabMetadata(string name,string fallback)
    {
        var value=Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value)||value.Length>128||value.Any(char.IsControl)?fallback:value;
    }
    public static void ClearCredentials()
    { Environment.SetEnvironmentVariable("ERRORLY_API_KEY", null); Environment.SetEnvironmentVariable("ERRORLY_DSN", null); }
    public static void Initialized(ErrorlySdkClient client)
    {
        if (LabChild)
        {
            client.SetContext("sdkLabCorrelationId", labRequest.CorrelationId);
            if(labRequest.Options!=null&&labRequest.Options.TryGetValue("websiteSuiteRunId",out var websiteSuiteRunId)&&SdkLabProtocol.IsSafeIdentifier(websiteSuiteRunId))client.SetContext("sdkLabSuiteRunId",websiteSuiteRunId);
            if(labRequest.Options!=null&&labRequest.Options.TryGetValue("websiteFullVerification",out var fullWebsite)&&fullWebsite=="true")
            {
                var probe=labRequest.Options.TryGetValue("websiteWorkflowEvidenceProbe",out var workflowProbe)&&workflowProbe=="true"||labRequest.Options.TryGetValue("websiteBindingProbe",out var bindingProbe)&&bindingProbe=="true";
                client.SetContext("sdkLabEvidencePhase",probe?"Probe":"Execution");
                if(labRequest.Options.TryGetValue("registryScenarioId",out var scenarioId)&&SdkLabProtocol.IsSafeIdentifier(scenarioId))client.SetContext("sdkLabScenarioId",scenarioId);
                client.SetContext("sdkLabTargetId",labRequest.TargetId);
            }
            client.Log(IncidentLogLevel.Error,"SdkLab","Controlled run correlation context");
        }
        if (Verification || LabChild) { labApiKey = null; ClearCredentials(); }
    }
    public static void PrintReady(int? port = null)
    { Console.WriteLine("ERRORLY_SAMPLE_READY " + JsonSerializer.Serialize(new { runId = RunId, port })); }
    public static SdkOptions Options(string application, ErrorlyApplicationKind kind)
    {
        var url = Environment.GetEnvironmentVariable("ERRORLY_SERVER_URL");
        Uri server;
        if (!Uri.TryCreate(url, UriKind.Absolute, out server)) server = new Uri("http://127.0.0.1:5000");
        if (LabChild)
        {
            var actualTarget = TargetId(application);
            if (!string.Equals(actualTarget, labRequest.TargetId, StringComparison.Ordinal)) labConfigurationError = "TargetMismatch";
            var local = string.Equals(labRequest.ProfileKind, "Local", StringComparison.Ordinal);
            labTransport = new LabTransport(labRequest.ScenarioId, local, CreateLabHttpHandler(local));
            var fullWebsite=labRequest.Options != null && labRequest.Options.TryGetValue("websiteFullVerification",out var fullWebsiteValue) && string.Equals(fullWebsiteValue,"true",StringComparison.Ordinal);
            var liveWebsite=fullWebsite&&labRequest.Options.TryGetValue("websiteLiveVerification",out var liveWebsiteValue)&&string.Equals(liveWebsiteValue,"true",StringComparison.Ordinal);
            var sourceSymbolTransport=labRequest.Options != null&&labRequest.Options.TryGetValue("sourceSymbolProbe",out var sourceProbeValue)&&string.Equals(sourceProbeValue,"true",StringComparison.Ordinal);
            // Full Website Verification has a separate bounded budget based on measured
            // Live admission-gate behavior. Ordinary SDK and Website Smoke defaults stay unchanged.
            var requestedDeliveryBudgetSeconds=liveWebsite&&labRequest.Options.TryGetValue("websiteDeliveryBudgetSeconds",out var configuredDeliveryBudget)&&int.TryParse(configuredDeliveryBudget,out var parsedDeliveryBudget)&&parsedDeliveryBudget is >=30 and <=210?parsedDeliveryBudget:30;
            var sourceSymbolBudgetSeconds=sourceSymbolTransport&&labRequest.Options!.TryGetValue("sourceSymbolDeliveryBudgetSeconds",out var sourceBudgetText)&&int.TryParse(sourceBudgetText,out var parsedSourceBudget)&&parsedSourceBudget is >=15 and <=60?parsedSourceBudget:30;
            var transportBudgetMs=liveWebsite?checked((requestedDeliveryBudgetSeconds+5)*1000):sourceSymbolTransport?checked((sourceSymbolBudgetSeconds+5)*1000):30000;
            verificationHttp = new HttpClient(labTransport) { Timeout = TimeSpan.FromMilliseconds(Math.Max(250, Math.Min(labRequest.TimeoutMs, transportBudgetMs))) };
            labOutbox = SdkLabProtocol.GetChildOutboxPath(Path.GetTempPath(), labRequest.CommandId);
            if(labRequest.Options.TryGetValue("expireBlockedCache",out var expire)&&string.Equals(expire,"true",StringComparison.Ordinal))ExpireBlockedCache();
            url = local ? "http://127.0.0.1:1" : labServerUrl;
            if (!Uri.TryCreate(url, UriKind.Absolute, out server)) server = new Uri("http://127.0.0.1:1");
        }
        else if (Verification)
        {
            var outboxId = Environment.GetEnvironmentVariable("ERRORLY_SAMPLE_OUTBOX_ID");
            if (outboxId == null || !Regex.IsMatch(outboxId, @"\A[0-9a-fA-F]{32}\z")) outboxId = Guid.NewGuid().ToString("N");
            verificationOutbox = Path.Combine(Path.GetTempPath(), "ErrorlySdkVerification", outboxId);
            verificationTransport = new VerificationTransport();
            verificationHttp = new HttpClient(verificationTransport) { Timeout = TimeSpan.FromSeconds(Math.Min(30, DeliveryTimeoutSeconds)) };
        }
        return new SdkOptions
        {
            ServerBaseUrl = server,
            ApiKey = LabChild ? (labRequest.ScenarioId == "init.missing-credentials" ? "" : string.IsNullOrWhiteSpace(labApiKey) && labRequest.ProfileKind == "Local" ? "sdk-lab-local" : labApiKey ?? "") : Environment.GetEnvironmentVariable("ERRORLY_API_KEY") ?? "",
            Dsn = Environment.GetEnvironmentVariable("ERRORLY_DSN"),
            ApplicationName = LabChild && labRequest.ScenarioId == "identity.partial-modern" ? string.Empty : application,
            ApplicationKind = kind,
            Environment = Verification ? "SDK Samples" : LabChild && labRequest.ScenarioId == "privacy.default-environment" && !LabStep("explicit-environment") ? null : LabChild ? SafeLabMetadata("ERRORLY_ENVIRONMENT", "SDK Lab") : Environment.GetEnvironmentVariable("ERRORLY_ENVIRONMENT") ?? "Development",
            Release = Verification ? "sdk-sample-verify-1" : LabChild ? SafeLabMetadata("ERRORLY_RELEASE", "sdk-lab-1") : Environment.GetEnvironmentVariable("ERRORLY_RELEASE") ?? "sdk-sample-1.0",
            SourceRevision = LabChild && labRequest.Options != null &&
                labRequest.Options.TryGetValue("sourceSymbolProbe", out var sourceSymbolProbe) && sourceSymbolProbe == "true" &&
                labRequest.Options.TryGetValue("sourceSymbolRevision", out var sourceSymbolRevision) && SdkLabProtocol.IsSafeIdentifier(sourceSymbolRevision)
                    ? sourceSymbolRevision : null,
            OutboxPath = LabChild ? (labRequest.ScenarioId == "init.malformed-config" ? "\0" : labOutbox) : Verification ? verificationOutbox : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Errorly", "SdkSamples", application),
            AutomaticCapture = !Verification,
            AutomaticUpload = !Verification && !LabChild,
            AutomaticPolicyRefresh = !Verification && !LabChild,
            HttpClient = verificationHttp
        };
    }
    public static bool IsSmoke(string[] args) => Array.IndexOf(args, "--smoke") >= 0;
    public static bool Configured => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ERRORLY_API_KEY")) || !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ERRORLY_DSN"));
    public static async Task<int> Verify(ErrorlySdkClient client, CancellationToken cancellationToken = default)
    {
        string failure = null; bool submitted = false;
        try
        {
            if (!Verification || RunId == null) failure = "InvalidRunId";
            else if (!client.IsEnabled) failure = "CredentialsUnavailable";
            else
            {
                using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    timeout.CancelAfter(TimeSpan.FromSeconds(DeliveryTimeoutSeconds));
                    if (!await client.RefreshPolicyAsync(timeout.Token)) failure = "PolicyUnavailable";
                    else
                    {
                        client.SetContext("sampleRunId", RunId);
                        client.SetContext("sampleVerification", "controlled");
                        var breadcrumb = false;
                        // A concurrent host policy refresh may briefly hold the bounded SDK gate.
                        // Retry the fixed breadcrumb before capturing; never replace it with unbounded waiting.
                        for (var breadcrumbAttempt = 0; breadcrumbAttempt < 3 && !breadcrumb; breadcrumbAttempt++)
                        {
                            breadcrumb = client.AddBreadcrumb("Operator requested controlled SDK verification");
                            if (!breadcrumb) await Task.Delay(25, timeout.Token);
                        }
                        if (!breadcrumb) failure = "PolicyRestricted";
                        var capture = failure == null ? client.CaptureMessageAsync(ControlledMessage, timeout.Token) : Task.FromResult<Guid?>(null);
                        if (await Task.WhenAny(capture, Task.Delay(Timeout.Infinite, timeout.Token)) != capture) failure = "DeliveryTimeout";
                        else
                        {
                            var id = await capture;
                            if (!id.HasValue) failure = "CaptureNotQueued";
                            else
                            {
                                verificationTransport.ExpectedIncident = id.Value;
                                for (int attempt = 0; attempt < 3 && !timeout.IsCancellationRequested; attempt++)
                                {
                                    await client.FlushAsync(timeout.Token);
                                    if (verificationTransport.Submitted) { submitted = true; break; }
                                    if (verificationTransport.TerminalFailure != null) { failure = verificationTransport.TerminalFailure; break; }
                                    await Task.Delay(TimeSpan.FromSeconds(2 * (attempt + 1)), timeout.Token);
                                }
                                if (!submitted && failure == null) failure = timeout.IsCancellationRequested ? "DeliveryTimeout" : "SubmissionUnconfirmed";
                            }
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException) { failure = "DeliveryTimeout"; }
        catch { failure = "VerificationFailed"; }
        finally
        {
            ClearCredentials();
            // Do not call Flush/Shutdown here: failed verification must not initiate a later send.
            client.Dispose();
            if (verificationHttp != null) verificationHttp.Dispose();
            if (!await CleanupVerificationOutbox()) { submitted = false; failure = "CleanupFailed"; }
        }
        WriteResult(client, submitted, failure);
        return submitted ? 0 : 1;
    }
    private static async Task<bool> CleanupVerificationOutbox()
    {
        try
        {
            if (verificationOutbox == null) return true;
            var owned = Path.GetFullPath(verificationOutbox);
            var parent = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "ErrorlySdkVerification")) + Path.DirectorySeparatorChar;
            if (!owned.StartsWith(parent, StringComparison.OrdinalIgnoreCase) || Path.GetFileName(owned).Length != 32) return false;
            var cleanup = Task.Run(async () => {
                var deadline = DateTimeOffset.UtcNow.AddSeconds(ShutdownTimeoutSeconds);
                while (true)
                {
                    try { if (Directory.Exists(owned)) Directory.Delete(owned, true); return; }
                    catch (IOException) { if (DateTimeOffset.UtcNow >= deadline) throw; await Task.Delay(100); }
                }
            });
            if (await Task.WhenAny(cleanup, Task.Delay(TimeSpan.FromSeconds(ShutdownTimeoutSeconds))) != cleanup) return false;
            await cleanup; return true;
        }
        catch { return false; }
    }
    public static object Result(ErrorlySdkClient client, bool submitted, string failure)
    {
        return new { status = submitted ? "Submitted" : "Failed", failureCategory = submitted ? null : failure ?? "VerificationFailed", runId = RunId,
            runtime = new { runtimeFamily = client?.RuntimeContext.RuntimeFamily, targetFramework = client?.RuntimeContext.TargetFramework, runtimeVersion = client?.RuntimeContext.RuntimeVersion, applicationKind = client?.RuntimeContext.ApplicationKind } };
    }
    private static void WriteResult(ErrorlySdkClient client, bool submitted, string failure)
    { if (Interlocked.Exchange(ref resultWritten, 1) == 0) { LastResult = Result(client, submitted, failure); Console.WriteLine("ERRORLY_SAMPLE_RESULT " + JsonSerializer.Serialize(LastResult)); } }
    public static async Task<int> StopWithoutSubmission(ErrorlySdkClient client, string failure)
    { ClearCredentials(); client.Dispose(); verificationHttp?.Dispose(); await CleanupVerificationOutbox(); WriteResult(client, false, failure); return 1; }
    private sealed class VerificationTransport : DelegatingHandler
    {
        internal Guid ExpectedIncident;
        internal bool Submitted;
        internal string TerminalFailure;
        internal VerificationTransport() : base(new HttpClientHandler { AllowAutoRedirect = false }) { }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Post)
            {
                var bytes = await request.Content.ReadAsByteArrayAsync();
                var package = IncidentPackageSerializer.Deserialize(bytes);
                if (package.ReportMessage != ControlledMessage || package.GroupingKey != null || package.ApplicationLogContext == null ||
                    !package.ApplicationLogContext.Entries.SelectMany(e => e.Properties).Any(p => p.Name == "sampleRunId" && p.Value == RunId))
                { TerminalFailure = "PolicyRestricted"; return new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("{}") }; }
            }
            var response = await base.SendAsync(request, cancellationToken);
            if (request.Method != HttpMethod.Post) return response;
            if (!response.IsSuccessStatusCode)
            { if ((int)response.StatusCode >= 400 && (int)response.StatusCode < 500 && (int)response.StatusCode != 408 && (int)response.StatusCode != 429) TerminalFailure = "SubmissionRejected"; return response; }
            try
            {
                using (var source = await response.Content.ReadAsStreamAsync())
                using (var copy = new MemoryStream())
                {
                    var buffer = new byte[4096]; int count;
                    while ((count = await source.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
                    { if (copy.Length + count > 65536) throw new InvalidDataException(); copy.Write(buffer, 0, count); }
                    var bytes = copy.ToArray();
                    using (var json = JsonDocument.Parse(bytes))
                    {
                        JsonElement id; JsonElement ignored; JsonElement status;
                        if ((json.RootElement.TryGetProperty("ignored", out ignored) && ignored.ValueKind == JsonValueKind.True) ||
                            (json.RootElement.TryGetProperty("status", out status) && status.ValueKind == JsonValueKind.String && status.GetString() == "ignored")) TerminalFailure = "PolicyRestricted";
                        else if (json.RootElement.TryGetProperty("status", out status) && status.ValueKind == JsonValueKind.String &&
                            (status.GetString() == "stored" || status.GetString() == "already_exists") &&
                            json.RootElement.TryGetProperty("incidentId", out id) && id.TryGetGuid(out var actual) && actual == ExpectedIncident && actual != Guid.Empty) Submitted = true;
                        else TerminalFailure = "InvalidReceipt";
                    }
                    response.Content.Dispose(); response.Content = new ByteArrayContent(bytes);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { TerminalFailure = "InvalidReceipt"; }
            return response;
        }
    }
    public static void PrintSmoke(ErrorlySdkClient client)
    {
        // Only fixed diagnostic fields are printed. Configuration values and secrets are never printed.
        Console.WriteLine("SDK sample startup completed without sending an incident.");
        Console.WriteLine(client.RuntimeContext.RuntimeFamily + " | " + client.RuntimeContext.TargetFramework + " | " + client.RuntimeContext.ApplicationKind + " | Runtime " + client.RuntimeContext.RuntimeVersion);
    }
    public static async Task Handled(ErrorlySdkClient client)
    {
        try { throw new InvalidOperationException("Intentional handled SDK sample exception"); }
        catch (InvalidOperationException error) { await client.CaptureExceptionAsync(error); }
    }
    public static async Task Message(ErrorlySdkClient client)
    {
        client.AddBreadcrumb("User chose the sample message action");
        client.SetTag("sample", "manual-action");
        client.SetContext("scenario", "message-with-context");
        await client.CaptureMessageAsync("Intentional SDK sample message");
    }
    public static async Task Flush(ErrorlySdkClient client)
    {
        var websiteSmoke = LabChild && labRequest.Options != null && labRequest.Options.TryGetValue("websiteSmoke", out var smoke) && string.Equals(smoke, "true", StringComparison.Ordinal);
        var fullWebsite = websiteSmoke && labRequest.Options.TryGetValue("websiteFullVerification",out var full) && string.Equals(full,"true",StringComparison.Ordinal);
        var liveWebsite = fullWebsite&&labRequest.Options.TryGetValue("websiteLiveVerification",out var live)&&string.Equals(live,"true",StringComparison.Ordinal);
        var sourceSymbolProbe=LabChild&&labRequest.Options is not null&&labRequest.Options.TryGetValue("sourceSymbolProbe",out var sourceProbe)&&string.Equals(sourceProbe,"true",StringComparison.Ordinal);
        var deliveryBudgetSeconds=liveWebsite&&labRequest.Options.TryGetValue("websiteDeliveryBudgetSeconds",out var configuredBudget)&&int.TryParse(configuredBudget,out var parsedBudget)&&parsedBudget is >=30 and <=210?parsedBudget:
            sourceSymbolProbe&&labRequest.Options.TryGetValue("sourceSymbolDeliveryBudgetSeconds",out var sourceBudget)&&int.TryParse(sourceBudget,out var parsedSourceBudget)&&parsedSourceBudget is >=15 and <=60?parsedSourceBudget:
            websiteSmoke?15:3;
        var elapsed = Stopwatch.StartNew();
        using (var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(deliveryBudgetSeconds)))
        {
            try { await client.FlushAsync(timeout.Token); }
            catch (OperationCanceledException) { }
            if (websiteSmoke && !timeout.IsCancellationRequested && HasLabOutboxFiles("*.erly"))
            {
                try { await Task.Delay(100, timeout.Token); await client.FlushAsync(timeout.Token); }
                catch (OperationCanceledException) { }
            }
        }
        elapsed.Stop();
        labFlushDurationMs = elapsed.ElapsedMilliseconds;
        var queued = HasLabOutboxFiles("*.erly");
        labFlushState = queued ? (labFlushDurationMs >= deliveryBudgetSeconds*1000-500 ? "TimedOutQueueRetained" : "CompletedQueued") : websiteSmoke && (labTransport?.IncidentAttempts ?? 0) > 1 ? "QueuedThenRecovered" : "CompletedAccepted";
    }
    public static async Task RunConsole(ErrorlySdkClient client)
    {
        Console.WriteLine(Configured ? "Ready. Actions are sent only when selected." : "No API key configured. Actions stay disabled; no network traffic.");
        Console.WriteLine("h: handled exception | m: message/breadcrumb/context | CRASH: terminate with unhandled exception | q: quit");
        for (var input = Console.ReadLine(); input != null && input != "q"; input = Console.ReadLine())
        {
            if (!Configured) { Console.WriteLine("Set ERRORLY_API_KEY and ERRORLY_SERVER_URL to enable capture."); continue; }
            if (input == "h") await Handled(client);
            else if (input == "m") await Message(client);
            else if (input == "CRASH")
            {
                Console.WriteLine("WARNING: intentional process termination. Final delivery cannot be guaranteed.");
                throw new InvalidOperationException("Intentional unhandled SDK sample exception");
            }
        }
        await Flush(client);
    }

    public static async Task<int?> RunLabChild(ErrorlySdkClient client)
    {
        if (!LabChild) return null;
        var started = DateTimeOffset.UtcNow;
        var result = NewLabResult(client, started);
        try
        {
            if (labConfigurationError != null) throw new InvalidOperationException(labConfigurationError);
            var scenario = NormalizeScenario(labRequest.ScenarioId);
            if (scenario == "auto.worker-background" && labRequest.TargetId.EndsWith("-worker", StringComparison.Ordinal))
            {
                ArmLabFatal(client, "BackgroundUnhandledArmed");
                return 134;
            }
            if (scenario == "auto.appdomain-unhandled" ||
                (scenario == "auto.console-unhandled" && labRequest.TargetId.EndsWith("-console", StringComparison.Ordinal)) ||
                scenario == "auto.fatal-flush")
            {
                ArmLabFatal(client, "UnhandledScenarioArmed");
                return 134;
            }

            var supported = true;
            var implemented = true;
            if (scenario == "init.valid")
            {
                result.Expected = "Initialized";
                result.Observed = client.IsEnabled ? "Initialized" : "Disabled";
                if (!client.IsEnabled) supported = false;
            }
            else if (scenario == "init.invalid-key" || scenario == "init.key-rotation")
            {
                SetIncident(result, await client.CaptureMessageAsync("SDK Lab credential lifecycle probe").ConfigureAwait(false));await Flush(client).ConfigureAwait(false);result.Expected=scenario=="init.invalid-key"?"CredentialRejectedSafely":"RotatedCredentialAccepted";result.Observed=scenario=="init.invalid-key"?"InvalidCredentialContained":LocalObservation();
            }
            else if (scenario == "init.missing-credentials" || scenario == "init.malformed-config")
            {
                result.Expected = "SafeDegradation";
                var contained = !client.IsEnabled && (scenario != "init.malformed-config" || client.LastFailure == "ConfigurationUnavailable");
                result.Observed = contained ? scenario == "init.malformed-config" ? "MalformedConfigurationContained" : "DisabledSafely" : "UnexpectedInitialization";
                supported = contained;
            }
            else if (scenario == "manual.handled-exception" || scenario == "manual.aggregate-exception")
            {
                var sourceProbe = scenario == "manual.handled-exception" && labRequest.Options != null &&
                    labRequest.Options.TryGetValue("sourceSymbolProbe", out var sourceProbeValue) && sourceProbeValue == "true";
                Exception error;
                if (sourceProbe)
                {
                    var probeType = Assembly.GetEntryAssembly()?.GetType("SourceSymbolsProbe", false)
                        ?? throw new InvalidOperationException("SourceSymbolsProbeUnavailable");
                    try
                    {
                        probeType.GetMethod("ThrowKnownException", BindingFlags.Static | BindingFlags.NonPublic)?.Invoke(null, null);
                        throw new InvalidOperationException("SourceSymbolsProbeDidNotThrow");
                    }
                    catch (TargetInvocationException wrapped) when (wrapped.InnerException != null)
                    {
                        error = wrapped.InnerException;
                    }
                    var described = probeType.GetMethod("Describe", BindingFlags.Static | BindingFlags.NonPublic)?.Invoke(null, new object[] { error });
                    result.SourceSymbols = described as SdkLabSourceSymbolFacts ?? throw new InvalidOperationException("SourceSymbolsProbeFactsUnavailable");
                }
                else
                {
                    error = scenario == "manual.aggregate-exception"
                        ? new AggregateException(new InvalidOperationException("SDK Lab controlled inner exception"))
                        : new InvalidOperationException("SDK Lab controlled handled exception");
                }
                SetIncident(result, await client.CaptureExceptionAsync(error).ConfigureAwait(false));
                await Flush(client).ConfigureAwait(false);
                result.Expected = sourceProbe ? "ExactSourceSymbolCapture" : "ClientCaptureAndFlush";
                result.Observed = LocalObservation();
            }
            else if (scenario == "manual.message" || scenario == "manual.breadcrumbs" || scenario == "manual.tags" ||
                     scenario == "manual.user-context" || scenario == "manual.large-context" || scenario == "manual.limits")
            {
                if (scenario == "manual.breadcrumbs") client.AddBreadcrumb("SDK Lab controlled breadcrumb");
                if (scenario == "manual.tags") client.SetTag("sdk-lab", "controlled");
                if (scenario == "manual.user-context") client.SetContext("sdkLabUser", "anonymous-controlled");
                if (scenario == "manual.large-context" || scenario == "manual.limits") client.SetContext("sdkLabBounded", new string('x', 256));
                SetIncident(result, await client.CaptureMessageAsync("SDK Lab controlled message").ConfigureAwait(false));
                await Flush(client).ConfigureAwait(false);
                result.Expected = "ClientCaptureAndFlush";
                result.Observed = LocalObservation();
            }
            else if (scenario == "manual.repeated" || scenario == "manual.flush-shutdown")
            {
                var count = scenario == "manual.repeated" ? 8 : 1;
                for (var index = 0; index < count; index++) SetIncident(result, await client.CaptureMessageAsync("SDK Lab controlled repeated message").ConfigureAwait(false));
                await Flush(client).ConfigureAwait(false);
                result.Expected = "BoundedCompletion";
                result.Observed = LocalObservation();
            }
            else if (scenario == "manual.cancellation" || scenario == "delivery.flush-timeout")
            {
                if (scenario == "delivery.flush-timeout")
                    SetIncident(result, await client.CaptureMessageAsync("SDK Lab controlled flush timeout").ConfigureAwait(false));
                var flushElapsed = Stopwatch.StartNew();
                var flushCancelled = false;
                using (var cancelled = new CancellationTokenSource())
                {
                    if (scenario == "manual.cancellation") cancelled.Cancel(); else cancelled.CancelAfter(TimeSpan.FromMilliseconds(100));
                    try { await client.FlushAsync(cancelled.Token).ConfigureAwait(false); } catch (OperationCanceledException) { }
                    flushCancelled = cancelled.IsCancellationRequested;
                }
                flushElapsed.Stop();
                labFlushDurationMs = flushElapsed.ElapsedMilliseconds;
                labFlushState = HasLabOutboxFiles("*.erly") ? flushCancelled ? "TimedOutQueueRetained" : "CompletedQueued" : "CompletedAccepted";
                result.Expected = "CancellationContained";
                result.Observed = scenario == "delivery.flush-timeout" && HasLabOutboxFiles("*.erly") ? "RetryableQueueRetained" : "CancellationContained";
            }
            else if (scenario.StartsWith("delivery.", StringComparison.Ordinal))
            {
                SetIncident(result, await client.CaptureMessageAsync("SDK Lab controlled delivery failure").ConfigureAwait(false));
                await Flush(client).ConfigureAwait(false);
                if (scenario == "delivery.retry" || scenario == "delivery.restart-recovery" || scenario == "delivery.store-forward") await Flush(client).ConfigureAwait(false);
                result.Expected = "QueuedOrFailedSafely";
                result.Observed = HasLabOutboxFiles("*.erly") ? "RetryableQueueRetained" : HasLabOutboxFiles("*.rejected") ? "TerminalRejectionQuarantined" : "TransportAttemptCompleted";
            }
            else if (scenario.StartsWith("governance.", StringComparison.Ordinal))
            {
                var refreshed = await client.RefreshPolicyAsync().ConfigureAwait(false);
                SetIncident(result, await client.CaptureMessageAsync("SDK Lab controlled governance probe").ConfigureAwait(false));
                await Flush(client).ConfigureAwait(false);
                if (scenario == "governance.no-retry-storm") await Flush(client).ConfigureAwait(false);
                result.Expected = scenario == "governance.blocked" ? "TerminalBlocked" : "PolicyObserved";
                result.Observed = client.CurrentReleaseAdvisory?.State.ToString() == "Blocked" ? "sdk_blocked" :
                    client.CurrentReleaseAdvisory?.State.ToString() == "Deprecated" ? "sdk_deprecated" : refreshed ? "sdk_supported" : "policy_unavailable";
            }
            else if (scenario.StartsWith("privacy.", StringComparison.Ordinal))
            {
                if (scenario == "privacy.offline-expired-policy") { await client.RefreshPolicyAsync().ConfigureAwait(false); await Task.Delay(1500).ConfigureAwait(false); }
                var refreshed = await client.RefreshPolicyAsync().ConfigureAwait(false);
                if (scenario == "privacy.ignore-rule" && !refreshed)
                {
                    result.Status = "Failed"; result.Verification = "Failed";
                    result.Expected = "AuthorizedRuntimePolicyBeforeCapture"; result.Observed = "RuntimePolicyUnavailable";
                    result.DiagnosticCodes.Add("PrivacyPolicyPrerequisiteUnavailable");
                    result.Delivery = DeliveryDiagnostics(null);
                    return 1;
                }
                if (scenario == "privacy.server-authority" && LabStep("flush-restricted"))
                {
                    await Flush(client).ConfigureAwait(false);
                    result.Expected = "ServerPrivacyAppliedToQueuedCapture";
                    result.Observed = refreshed ? "QueuedBypassFlushedUnderServerAuthority" : "PolicyUnavailable";
                }
                else if (scenario == "privacy.ignore-rule")
                {
                    var ignoredException = await client.CaptureExceptionAsync(new InvalidOperationException("SDK Lab ignored exception candidate")).ConfigureAwait(false);
                    var ignoredMessage = await client.CaptureMessageAsync("SDK Lab ignored message candidate").ConfigureAwait(false);
                    client.SetContext("request.path", "/sdk-lab/ignored/path");
                    var pathPredicate = client.ShouldIgnoreRequest("/sdk-lab/ignored/path");
                    var ignoredPath = await client.CaptureMessageAsync("SDK Lab path candidate").ConfigureAwait(false);
                    client.SetContext("request.path", null);
                    SetIncident(result, await client.CaptureMessageAsync("SDK Lab ignore-rule control").ConfigureAwait(false));
                    await Flush(client).ConfigureAwait(false);
                    var allIgnored = ignoredException == null && ignoredMessage == null && ignoredPath == null && pathPredicate && result.IncidentId != null;
                    result.Expected = "ThreeRulesSuppressOnlyMatchingCaptures";
                    result.Observed = allIgnored ? "IgnoreRulesSuppressed-3-ControlAccepted" : "IgnoreRuleMismatch";
                    supported = allIgnored;
                }
                else
                {
                    if (scenario == "privacy.redaction") client.SetContext("sdkLabRedactionMarker", "controlled-private-marker");
                    if (scenario == "privacy.identity-enabled" || scenario == "privacy.identity-disabled") client.SetUser("sdk-lab-controlled-user", "controlled@example.invalid");
                    if (scenario == "privacy.property-filter") client.SetContext("password", "controlled-filter-marker");
                    if (scenario == "privacy.level") client.Log(IncidentLogLevel.Debug, "SdkLab", "Controlled below-level observation");
                    if (scenario == "privacy.server-authority")
                    {
                        client.SetUser("sdk-lab-bypass-user", "sdk-lab-bypass@example.invalid");
                        client.SetContext("ipAddress", "192.0.2.42");
                        client.Log(IncidentLogLevel.Error, "SdkLab", "Server authority bypass sdk-lab-bypass-user sdk-lab-bypass@example.invalid 192.0.2.42");
                    }
                    var entries = scenario == "privacy.entry-byte-caps" ? 128 : 1;
                    for (var index = 0; index < entries; index++) client.Log(IncidentLogLevel.Error, "SdkLab", "Controlled privacy policy observation " + index + " " + new string('x', 96));
                    SetIncident(result, await client.CaptureMessageAsync("SDK Lab controlled privacy observation").ConfigureAwait(false));
                    await Flush(client).ConfigureAwait(false);
                    result.Expected = "PolicyAppliedByServer";
                    result.Observed = scenario.Replace('.', '_') + (refreshed ? "_policy_loaded" : "_policy_fail_open");
                }
            }
            else if (scenario.StartsWith("identity.", StringComparison.Ordinal))
            {
                if (scenario == "identity.override-kind") client.UseApplicationKind(ErrorlyApplicationKind.AspNetCore);
                var message = scenario switch
                {
                    "identity.configuration" => "SDK Lab identity configuration",
                    "identity.runtime" => "SDK Lab identity runtime",
                    "identity.override-kind" => "SDK Lab identity explicit application kind",
                    "identity.legacy" => "SDK Lab identity legacy runtime",
                    "identity.partial-modern" => "SDK Lab identity partial modern runtime",
                    _ => "SDK Lab identity compatibility"
                };
                SetIncident(result, await client.CaptureMessageAsync(message).ConfigureAwait(false));
                await Flush(client).ConfigureAwait(false);
                result.Expected = scenario.Replace('.', '_') + "_api_projection";
                result.Observed = result.IncidentId == null ? "IdentityCaptureUnavailable" : "IdentityCaptureSubmitted";
                supported = result.IncidentId != null;
            }
            else if (scenario.StartsWith("issue.", StringComparison.Ordinal))
            {
                var fullWebsite=labRequest.Options?.TryGetValue("websiteFullVerification",out var fullWebsiteValue)==true&&fullWebsiteValue=="true";
                var suiteSuffix=fullWebsite&&labRequest.Options?.TryGetValue("websiteSuiteRunId",out var fullWebsiteSuite)==true&&SdkLabProtocol.IsSafeIdentifier(fullWebsiteSuite)?" "+fullWebsiteSuite:string.Empty;
                if(fullWebsite)
                {
                    var probe=labRequest.Options?.TryGetValue("websiteWorkflowEvidenceProbe",out var probeValue)==true&&probeValue=="true";
                    suiteSuffix+=" "+scenario+" "+(probe?"Probe":"Execution");
                    // Each duplicate pair has its own issue. Cross-target workflow
                    // scenarios intentionally share one issue across targets.
                    if(scenario=="issue.duplicate-grouping"||scenario=="issue.distinct-fingerprint")suiteSuffix+=" "+labRequest.TargetId;
                }
                var message = (scenario == "issue.distinct-fingerprint" ? "SDK Lab distinct fingerprint B" : "SDK Lab stable grouping fingerprint")+suiteSuffix;
                SetIncident(result, await client.CaptureMessageAsync(message).ConfigureAwait(false));
                if (scenario == "issue.duplicate-grouping") await client.CaptureMessageAsync(message).ConfigureAwait(false);
                if (scenario == "issue.legacy-runtime") RemoveQueuedRuntimeContext();
                await Flush(client).ConfigureAwait(false);
                result.Expected = "ServerInspectionRequired";
                result.Observed = LocalObservation();
            }
            else if (scenario == "auto.aspnet-request" || scenario == "auto.middleware-status" || scenario == "auto.minimal-api" || scenario == "auto.controller-api" || scenario == "auto.handler-dedup")
            {
                SetIncident(result, FindQueuedIncident(), false);
                await Flush(client).ConfigureAwait(false);
                result.Expected = "AspNetCoreMiddlewareCapture";
                result.Observed = result.IncidentId == null ? "AutomaticCaptureNotObserved" : LocalObservation();
                supported = result.IncidentId != null;
            }
            else { supported = false; implemented = false; }

            var locallyVerified = labTransport != null && labTransport.Local;
            result.Status = supported ? "Passed" : "Unsupported";
            result.Verification = supported ? (locallyVerified ? "Passed" : "TransportObserved") : "PrerequisiteMissing";
            if (supported && !locallyVerified && result.IncidentId != null)
            {
                var queued=HasLabOutboxFiles("*.erly");
                var accepted=Guid.TryParse(result.IncidentId,out var expectedIncident)&&labTransport.WasAccepted(expectedIncident);
                var quarantined=scenario.StartsWith("delivery.",StringComparison.Ordinal)&&!queued&&HasLabOutboxFiles("*.rejected")&&result.Observed=="TerminalRejectionQuarantined";
                result.Verification = accepted ? "Accepted" : queued ? "Queued" : quarantined ? "TerminalRejected" : "Failed";
                result.Status = accepted||queued||quarantined ? "Passed" : "Failed";
                if(accepted)
                {
                    if(string.IsNullOrWhiteSpace(result.Observed)||result.Observed=="TransportPending")result.Observed="SentToServer";
                }
                else if(quarantined)result.Observed="TerminalRejectionQuarantined";
                else if(queued&&result.Observed=="RetryableQueueRetained")result.Observed="RetryableQueueRetained";
                else result.Observed=queued?"LocallyQueued":"ExternalRejected";
                if(!accepted&&!queued&&!quarantined&&client.CurrentReleaseAdvisory?.State.ToString()!="Blocked")result.DiagnosticCodes.Add(labTransport.ExternalDiagnostic??"ExternalReceiptNotAccepted");
            }
            if (supported && !locallyVerified && client.CurrentReleaseAdvisory?.State.ToString() == "Blocked")
            {
                result.Status = "Passed"; result.Verification = "terminal-policy"; result.Observed = "sdk_blocked"; result.IncidentId = null;
            }
            if (supported && locallyVerified && scenario.StartsWith("manual.", StringComparison.Ordinal) && scenario != "manual.cancellation" && labTransport.Submissions == 0)
            {
                result.Status = "Failed"; result.Verification = "Failed"; result.Observed = "NoLocalSubmissionObserved";
            }
            if (supported && locallyVerified && (scenario == "delivery.unavailable" || scenario == "delivery.timeout" || scenario == "delivery.retry" || scenario == "delivery.store-forward"))
            {
                var queueObserved = locallyVerified && labTransport.Failures > 0 && HasLabOutboxFiles("*.erly");
                result.Status = queueObserved ? "Passed" : "Failed";
                result.Verification = queueObserved ? "Queued" : "Failed";
                result.Observed = queueObserved ? "RetryableFailureObserved" : "ExpectedFailureNotObserved";
            }
            if (supported && locallyVerified && (scenario == "governance.blocked" || scenario == "governance.terminal-quarantine" || scenario == "governance.no-retry-storm"))
            {
                var terminalObserved = locallyVerified && labTransport.TerminalPolicies == 1 && !HasLabOutboxFiles("*.erly") && HasLabOutboxFiles("*.blocked") && File.Exists(Path.Combine(labOutbox, ".sdk-blocked.json")) && client.CurrentReleaseAdvisory != null && client.CurrentReleaseAdvisory.State.ToString() == "Blocked";
                result.Status = terminalObserved ? "Passed" : "Failed";
                result.Verification = terminalObserved ? "terminal-policy" : "Failed";
                result.Observed = terminalObserved ? "TerminalPolicyObserved" : "TerminalPolicyNotObserved";
            }
            if (supported && locallyVerified && (scenario == "governance.supported" || scenario == "governance.legacy-fail-open"))
            {
                var observed = locallyVerified && labTransport.PolicyReads > 0 && labTransport.Submissions > 0 && !HasLabOutboxFiles("*.erly");
                result.Status=observed?"Passed":"Failed";result.Verification=observed?"Passed":"Failed";result.Observed=observed?"PolicyAndSubmissionObserved":"ExpectedGovernanceEvidenceMissing";
            }
            if (supported && locallyVerified && (scenario == "governance.deprecated" || scenario == "governance.minimum-safe"))
            {
                var observed = locallyVerified && labTransport.PolicyReads > 0 && labTransport.Advisories > 0 && labTransport.Submissions > 0 && client.CurrentReleaseAdvisory != null && client.CurrentReleaseAdvisory.State.ToString() == "Deprecated";
                result.Status=observed?"Passed":"Failed";result.Verification=observed?"Passed":"Failed";result.Observed=observed?"AdvisoryAndSubmissionObserved":"ExpectedAdvisoryEvidenceMissing";
            }
            if (!supported)
            {
                if (!implemented) { result.Expected = "TargetHostImplementation"; result.Observed = "Unsupported"; result.DiagnosticCodes.Add("ScenarioNotImplementedByTarget"); }
                else result.DiagnosticCodes.Add(scenario == "privacy.ignore-rule" ? "PrivacyIgnoreRuleMismatch" : scenario.StartsWith("identity.", StringComparison.Ordinal) ? "IdentityCaptureUnavailable" : scenario.StartsWith("auto.", StringComparison.Ordinal) ? "AutomaticCaptureNotObserved" : "InitializationExpectationMismatch");
            }
            result.DeliveryAttempts = labTransport?.IncidentAttempts ?? 0;
            var receipt=labTransport?.Receipt(result.IncidentId);
            result.SafeRejectionCode = receipt is null?labTransport?.ExternalRejectionCode:receipt.RejectionCode;
            result.HttpStatusCode = receipt is null?labTransport?.ExternalHttpStatusCode:receipt.HttpStatusCode;
            result.HttpStatusFamily = receipt is null?labTransport?.ExternalHttpStatusFamily:receipt.HttpStatusFamily;
            result.Delivery = DeliveryDiagnostics(result.IncidentId);
        }
        catch
        {
            if (result.Status == "Armed") throw;
            result.Status = "Failed";
            result.Expected = result.Expected ?? "SafeCompletion";
            result.Observed = "ContainedFailure";
            result.Verification = "Failed";
            result.DiagnosticCodes.Add(labTransport?.ExternalRejectionCode??labConfigurationError??"ScenarioExecutionFailed");
            var receipt=labTransport?.Receipt(result.IncidentId);
            result.SafeRejectionCode = receipt is null?labTransport?.ExternalRejectionCode:receipt.RejectionCode;
            result.HttpStatusCode = receipt is null?labTransport?.ExternalHttpStatusCode:receipt.HttpStatusCode;
            result.HttpStatusFamily = receipt is null?labTransport?.ExternalHttpStatusFamily:receipt.HttpStatusFamily;
            result.Delivery = DeliveryDiagnostics(result.IncidentId);
        }
        finally
        {
            labApiKey = null;
            if (result.Status != "Armed")
            {
                var preserveOutbox=labRequest.Options.TryGetValue("preserveOutbox",out var preserve)&&string.Equals(preserve,"true",StringComparison.Ordinal);
                result.Cleanup = preserveOutbox ? "ParentRequired" : CleanupLabOutbox() ? "Completed" : "Failed";
                if(!preserveOutbox&&result.Cleanup=="Completed"&&result.Delivery?.QueueState=="Pending")result.Delivery.QueueState="PendingThenRemovedByLabCleanup";
                if(!preserveOutbox&&result.Cleanup=="Completed"&&result.Delivery?.QueueState=="PendingOtherReports")result.Delivery.QueueState="PendingOtherReportsThenRemovedByLabCleanup";
                CompleteAndWriteLabResult(result, started);
            }
        }
        return result.Status == "Passed" || result.Status == "Unsupported" ? 0 : 1;
    }

    public static void ArmLabFatal(ErrorlySdkClient client, string observed)
    {
        if (!LabChild) return;
        var started = DateTimeOffset.UtcNow;
        var result = NewLabResult(client, started);
        result.Status = "Armed"; result.Expected = "ProcessTermination"; result.Observed = observed;
        result.Verification = "ParentProcessRequired"; result.Termination = "ExpectedUnhandled"; result.Cleanup = "ParentRequired";
        SuppressFatalDetails();
        // Lab children disable automatic upload. The ordinary customer shutdown
        // budget only persists the fatal report and gives delivery two seconds.
        // Settle this controlled sample's existing bounded delivery budget before
        // exiting; the parent must still prove this exact occurrence after exit.
        try
        {
            Task.Run(async () =>
            {
                client.CaptureUnhandled(new InvalidOperationException("Intentional SDK Lab fatal boundary"));
                SetIncident(result, FindQueuedIncident(), false);
                if (result.IncidentId == null) result.DiagnosticCodes.Add("FatalCaptureNotPersisted");
                await Flush(client).ConfigureAwait(false);
            }).GetAwaiter().GetResult();
        }
        catch { result.DiagnosticCodes.Add("FatalDeliveryPreparationFailed"); }
        result.DeliveryAttempts = labTransport?.IncidentAttempts ?? 0;
        var receipt = labTransport?.Receipt(result.IncidentId);
        result.SafeRejectionCode = receipt is null ? labTransport?.ExternalRejectionCode : receipt.RejectionCode;
        result.HttpStatusCode = receipt is null ? labTransport?.ExternalHttpStatusCode : receipt.HttpStatusCode;
        result.HttpStatusFamily = receipt is null ? labTransport?.ExternalHttpStatusFamily : receipt.HttpStatusFamily;
        result.Delivery = DeliveryDiagnostics(result.IncidentId);
        CompleteAndWriteLabResult(result, started);
        Environment.Exit(134);
    }

    private static void SuppressFatalDetails() { try { Console.SetError(TextWriter.Null); } catch { } }

    private static void SetIncident(SdkLabChildResult result, Guid? incidentId, bool newlyCaptured = true)
    {
        if (!incidentId.HasValue) return;
        if (newlyCaptured) labTransport?.RememberCapturedIncident(incidentId.Value);
        if (result.IncidentId == null) result.IncidentId = incidentId.Value.ToString("D");
    }

    private static Guid? FindQueuedIncident()
    {
        try
        {
            var path = Directory.GetFiles(labOutbox, "*.erly").OrderBy(value => value, StringComparer.Ordinal).FirstOrDefault();
            return path == null ? (Guid?)null : IncidentPackageSerializer.Deserialize(File.ReadAllBytes(path)).IncidentId;
        }
        catch { return null; }
    }

    private static void RemoveQueuedRuntimeContext()
    {
        try
        {
            var path = Directory.GetFiles(labOutbox, "*.erly").OrderBy(value => value, StringComparer.Ordinal).FirstOrDefault();
            if (path == null) return;
            var package = IncidentPackageSerializer.Deserialize(File.ReadAllBytes(path));
            File.WriteAllBytes(path, IncidentPackageSerializer.Serialize(package.WithRuntimeContext(null)));
        }
        catch { }
    }

    private static string LocalObservation() => labTransport != null && labTransport.Local
        ? (labTransport.Submissions > 0 ? "LocalTransportSubmitted" : "LocalQueueOnly")
        : "TransportPending";

    private static bool HasLabOutboxFiles(string pattern)
    {
        try { return !string.IsNullOrWhiteSpace(labOutbox) && Directory.Exists(labOutbox) && Directory.GetFiles(labOutbox, pattern).Length > 0; }
        catch { return false; }
    }

    private static void ExpireBlockedCache()
    {
        try
        {
            var path=Path.Combine(labOutbox,".sdk-blocked.json");if(!File.Exists(path)||new FileInfo(path).Length is <=0 or >4096)return;var json=File.ReadAllText(path);using var document=JsonDocument.Parse(json);var buffer=new MemoryStream();using(var writer=new Utf8JsonWriter(buffer))
            {writer.WriteStartObject();foreach(var property in document.RootElement.EnumerateObject()){if(property.NameEquals("expiresUtc"))writer.WriteString("expiresUtc",DateTimeOffset.UtcNow.AddSeconds(-1));else property.WriteTo(writer);}writer.WriteEndObject();}File.WriteAllBytes(path,buffer.ToArray());
        }
        catch{}
    }

    private static void PrintLabArmed() => Console.WriteLine("ERRORLY_SDK_LAB_EVENT " + JsonSerializer.Serialize(new
    {
        schemaVersion = SdkLabProtocol.SchemaVersion, type = "armed", runId = labRequest.RunId,
        commandId = labRequest.CommandId, targetId = labRequest.TargetId, scenarioId = labRequest.ScenarioId,
        correlationId = labRequest.CorrelationId
    }, LabJsonOptions()));

    private static SdkLabChildResult NewLabResult(ErrorlySdkClient client, DateTimeOffset started) => new SdkLabChildResult
    {
        SchemaVersion = SdkLabProtocol.SchemaVersion, RunId = labRequest.RunId, CommandId = labRequest.CommandId,
        TargetId = labRequest.TargetId, ScenarioId = labRequest.ScenarioId, CorrelationId = labRequest.CorrelationId,
        StartedUtc = started, ExitCode = 0,
        ExecutionBindingEndpointAuthority=labRequest.Options != null&&labRequest.Options.TryGetValue("websiteBindingAuthority",out var bindingAuthority)?bindingAuthority:null,
        ExecutionBindingApplicationIdFingerprint=labRequest.Options != null&&labRequest.Options.TryGetValue("websiteBindingApplicationFingerprint",out var bindingApplication)?bindingApplication:null,
        ExecutionBindingProfileKind=labRequest.Options != null&&labRequest.Options.TryGetValue("websiteBindingProfile",out var bindingProfile)?bindingProfile:null,
        ExecutionBindingMode=labRequest.Options != null&&labRequest.Options.TryGetValue("websiteBindingMode",out var bindingMode)?bindingMode:null,
        ExecutionBindingSuiteRunId=labRequest.Options != null&&labRequest.Options.TryGetValue("websiteBindingSuite",out var bindingSuite)?bindingSuite:null,
        ExecutionBindingContractVersion=labRequest.Options != null&&labRequest.Options.TryGetValue("websiteBindingContract",out var bindingContract)?bindingContract:null,
        ExecutionBindingFingerprint=labRequest.Options != null&&labRequest.Options.TryGetValue("websiteBindingFingerprint",out var bindingFingerprint)?bindingFingerprint:null,
        Runtime = new SdkLabRuntimeFacts
        {
            PackageName = client.RuntimeContext.SdkName, PackageVersion = client.RuntimeContext.SdkVersion,
            TargetFramework = client.RuntimeContext.TargetFramework, ApplicationKind = client.RuntimeContext.ApplicationKind,
            RuntimeFamily = HostRuntimeFamily(labRequest.TargetId), RuntimeVersion = client.RuntimeContext.RuntimeVersion,
            ProcessArchitecture = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString()
        }
    };

    private static void CompleteAndWriteLabResult(SdkLabChildResult result, DateTimeOffset started)
    {
        result.CompletedUtc = DateTimeOffset.UtcNow;
        result.DurationMs = Math.Max(0, (long)(result.CompletedUtc - started).TotalMilliseconds);
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(result, LabJsonOptions());
            if (bytes.Length > SdkLabProtocol.MaxResultBytes) throw new InvalidDataException();
            var directory = Path.GetDirectoryName(labResultPath);
            if (string.IsNullOrEmpty(directory) || !Directory.Exists(directory) || File.Exists(labResultPath)) return;
            var temporary = labResultPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try { File.WriteAllBytes(temporary, bytes); File.Move(temporary, labResultPath); }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            Console.WriteLine("ERRORLY_SDK_LAB_RESULT " + result.Status);
        }
        catch (Exception error)
        {
            Console.WriteLine("ERRORLY_SDK_LAB_DIAGNOSTIC ResultWriteFailed/" + error.HResult.ToString("X8", System.Globalization.CultureInfo.InvariantCulture));
        }
    }

    private static bool CleanupLabOutbox()
    {
        try
        {
            if (labOutbox == null) return true;
            var root = Path.GetFullPath(Path.Combine(Path.GetTempPath(), SdkLabProtocol.ChildOutboxDirectoryName)) + Path.DirectorySeparatorChar;
            var owned = Path.GetFullPath(labOutbox);
            if (!owned.StartsWith(root, StringComparison.OrdinalIgnoreCase) || !SdkLabProtocol.IsSafeIdentifier(Path.GetFileName(owned))) return false;
            if (Directory.Exists(owned)) Directory.Delete(owned, true);
            return true;
        }
        catch { return false; }
    }

    private static bool ValidLabRequest(SdkLabChildRequest request)
    {
        string ignored;
        return SdkLabContractValidator.TryValidate(request, out ignored);
    }

    private static string SafeFullPath(string value)
    {
        try { return string.IsNullOrWhiteSpace(value) || value.Length > 1024 ? null : Path.GetFullPath(value); }
        catch { return null; }
    }

    private static bool ReadLabInput()
    {
        var buffer = new char[SdkLabProtocol.MaxInputBytes + 1];
        try
        {
            if (!Console.IsInputRedirected) return false;
            var count = 0;
            while (count < buffer.Length)
            {
                var value = Console.In.Read();
                if (value < 0 || value == '\n') break;
                if (value != '\r') buffer[count++] = (char)value;
            }
            if (count == 0 || count > SdkLabProtocol.MaxInputBytes) return false;
            var input = JsonSerializer.Deserialize<SdkLabChildInput>(new string(buffer, 0, count), LabJsonOptions());
            string ignored;
            if (!SdkLabContractValidator.TryValidate(input, labRequest, out ignored)) return false;
            labServerUrl = input.ServerBaseUrl;
            labApiKey = input.ApiKey;
            labCredentialEnvelope = "ReceivedAndValidated";
            input.ApiKey = null;
            return true;
        }
        catch { return false; }
        finally { Array.Clear(buffer, 0, buffer.Length); }
    }

    private static JsonSerializerOptions LabJsonOptions() => new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        WriteIndented = false
    };

    private static string TargetId(string application)
    {
        if (application.IndexOf("Net48.Console", StringComparison.Ordinal) >= 0) return SdkLabTargetIds.Net48Console;
        if (application.IndexOf("Net48.Wpf", StringComparison.Ordinal) >= 0) return SdkLabTargetIds.Net48Wpf;
        if (application.IndexOf("Net48.WinForms", StringComparison.Ordinal) >= 0) return SdkLabTargetIds.Net48WinForms;
        if (application.IndexOf("Net6.Console", StringComparison.Ordinal) >= 0) return SdkLabTargetIds.Net6Console;
        if (application.IndexOf("Net6.WebApi", StringComparison.Ordinal) >= 0) return SdkLabTargetIds.Net6WebApi;
        if (application.IndexOf("Net6.Worker", StringComparison.Ordinal) >= 0) return SdkLabTargetIds.Net6Worker;
        if (application.IndexOf("Net10.Console", StringComparison.Ordinal) >= 0) return SdkLabTargetIds.Net10Console;
        if (application.IndexOf("Net10.WebApi", StringComparison.Ordinal) >= 0) return SdkLabTargetIds.Net10WebApi;
        if (application.IndexOf("Net10.Worker", StringComparison.Ordinal) >= 0) return SdkLabTargetIds.Net10Worker;
        return null;
    }

    private static string HostTargetFramework(string targetId) => targetId.StartsWith("net48-", StringComparison.Ordinal)
        ? "net48" : targetId.StartsWith("net6-", StringComparison.Ordinal) ? "net6.0" : "net10.0";

    private static string HostRuntimeFamily(string targetId) => targetId.StartsWith("net48-", StringComparison.Ordinal)
        ? "net48" : targetId.StartsWith("net6-", StringComparison.Ordinal) ? "net6" : "net10";

    private static string HostApplicationKind(string targetId) => targetId.EndsWith("-wpf", StringComparison.Ordinal)
        ? "Wpf" : targetId.EndsWith("-winforms", StringComparison.Ordinal) ? "WinForms" :
        targetId.EndsWith("-webapi", StringComparison.Ordinal) ? "AspNetCore" :
        targetId.EndsWith("-worker", StringComparison.Ordinal) ? "Worker" : "Console";

    private static bool LabStep(string value) => labRequest.Options != null && labRequest.Options.TryGetValue("labStep", out var actual) && string.Equals(actual, value, StringComparison.Ordinal);

    private static ErrorlyApplicationKind TargetApplicationKind(string targetId) => targetId.EndsWith("-wpf", StringComparison.Ordinal)
        ? ErrorlyApplicationKind.Wpf : targetId.EndsWith("-winforms", StringComparison.Ordinal) ? ErrorlyApplicationKind.WinForms :
        targetId.EndsWith("-webapi", StringComparison.Ordinal) ? ErrorlyApplicationKind.AspNetCore :
        targetId.EndsWith("-worker", StringComparison.Ordinal) ? ErrorlyApplicationKind.WorkerService : ErrorlyApplicationKind.Console;

    private static string NormalizeScenario(string scenario) => scenario switch
    {
        "startup" => "init.valid", "handled-exception" => "manual.handled-exception",
        "handled-exception-context" => "manual.user-context", "message-context-breadcrumb" => "manual.message",
        "unhandled-main-thread" => "auto.console-unhandled", "unhandled-background-thread" => "auto.worker-background",
        "unobserved-task" => "auto.unobserved-task", "wpf-dispatcher-unhandled" => "auto.wpf-dispatcher",
        "winforms-thread-exception" => "auto.winforms-ui", "aspnetcore-request-exception" => "auto.aspnet-request",
        "structured-log-exception" => "privacy.log-enabled", "transport-unavailable" => "delivery.unavailable",
        "offline-queue" => "delivery.store-forward", "timeout" => "delivery.timeout",
        "deprecated-policy" => "governance.deprecated", "blocked-policy" => "governance.blocked",
        "older-server" => "governance.legacy-fail-open", _ => scenario
    };

    private static HttpMessageHandler CreateLabHttpHandler(bool local)
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = false };
        if (local || labRequest.Options == null || !labRequest.Options.TryGetValue("testServerCertificateSha256", out var expected) ||
            !Regex.IsMatch(expected ?? "", "\\A[0-9A-Fa-f]{64}\\z") || !Uri.TryCreate(labServerUrl, UriKind.Absolute, out var endpoint) ||
            !endpoint.IsLoopback || endpoint.Scheme != Uri.UriSchemeHttps) return handler;
        handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
        {
            try
            {
                if (certificate == null) return false;
                using (var sha = SHA256.Create()) return string.Equals(BitConverter.ToString(sha.ComputeHash(certificate.GetRawCertData())).Replace("-", ""), expected, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        };
        return handler;
    }

    private sealed class LabTransport : DelegatingHandler
    {
        internal readonly bool Local;
        internal int Submissions;
        internal int Failures;
        internal int TerminalPolicies;
        internal int PolicyReads;
        internal int Advisories;
        internal int ExternalResponses;
        internal int IncidentAttempts;
        internal Guid AcceptedIncidentId;
        internal string ExternalDiagnostic;
        internal string ExternalRejectionCode;
        internal int? ExternalHttpStatusCode;
        internal string ExternalHttpStatusFamily;
        internal DateTimeOffset? FirstAttemptUtc;
        internal long AttemptDurationMs;
        internal string RequestProtocol;
        internal string TransportState = "NotAttempted";
        private readonly object receiptGate = new object();
        private readonly Dictionary<Guid,LabReceiptFacts> receipts = new Dictionary<Guid,LabReceiptFacts>();
        private readonly Dictionary<Guid,LabExecutionAttribution> capturedAttributions = new Dictionary<Guid,LabExecutionAttribution>();
        private readonly LabExecutionAttribution launchAttribution;
        private int attempts;
        private readonly string scenario;
        internal LabTransport(string scenario, bool local, HttpMessageHandler handler) : base(handler) { this.scenario = scenario; Local = local; launchAttribution = !local ? LabExecutionAttribution.FromLaunch() : null; }
        internal void RememberCapturedIncident(Guid incidentId)
        {
            if (launchAttribution != null) lock (receiptGate) capturedAttributions[incidentId] = launchAttribution;
        }
        private void ApplyExecutionAttribution(HttpRequestMessage request, IncidentPackage package)
        {
            if (launchAttribution == null || request.Method != HttpMethod.Post || request.RequestUri.AbsolutePath != "/api/v1/incidents") return;
            var properties = (package.ApplicationLogContext?.Entries ?? Array.Empty<IncidentLogEntry>()).SelectMany(entry => entry.Properties).ToArray();
            LabExecutionAttribution attribution;
            if (properties.Any(property => LabExecutionAttribution.PropertyNames.Contains(property.Name)))
                attribution = LabExecutionAttribution.FromProperties(properties);
            else lock (receiptGate) capturedAttributions.TryGetValue(package.IncidentId, out attribution);
            // An old queued report without its own identity must never inherit this
            // launch's identity. Privacy-disabled fresh captures have an explicit ID map.
            if (attribution == null) return;
            request.Headers.Add("X-Errorly-Sdk-Lab-Suite", attribution.Suite);
            request.Headers.Add("X-Errorly-Sdk-Lab-Correlation", attribution.Correlation);
            request.Headers.Add("X-Errorly-Sdk-Lab-Phase", attribution.Phase);
            request.Headers.Add("X-Errorly-Sdk-Lab-Scenario", attribution.Scenario);
            request.Headers.Add("X-Errorly-Sdk-Lab-Target", attribution.Target);
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!Local)
            {
                Guid expectedIncident=Guid.Empty;
                if (request.Method == HttpMethod.Post)
                {
                    Interlocked.Increment(ref IncidentAttempts);
                    if (FirstAttemptUtc == null) FirstAttemptUtc = DateTimeOffset.UtcNow;
                    try{var externalPackage=IncidentPackageSerializer.Deserialize(await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false));expectedIncident=externalPackage.IncidentId;ApplyExecutionAttribution(request,externalPackage);}catch{ExternalDiagnostic="ExternalRequestInvalid";}
                    ExternalHttpStatusCode=null;ExternalHttpStatusFamily=null;ExternalRejectionCode=null;RequestProtocol=null;
                }
                if (request.Method == HttpMethod.Get) Interlocked.Increment(ref PolicyReads);
                HttpResponseMessage external;
                var attempt=Stopwatch.StartNew();
                try{external = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);TransportState="ResponseObserved";}
                catch(Exception exception)when(exception is HttpRequestException||exception is TaskCanceledException){TransportState=exception is TaskCanceledException?"CancelledOrTimedOut":ContainsAuthenticationFailure(exception)?"TlsFailed":"Unavailable";ExternalDiagnostic=SdkLabSafeRejectionCodes.EndpointUnavailable;ExternalRejectionCode=SdkLabSafeRejectionCodes.EndpointUnavailable;if(expectedIncident!=Guid.Empty)RecordReceipt(expectedIncident,new LabReceiptFacts(false,null,null,SdkLabSafeRejectionCodes.EndpointUnavailable,TransportState,null));throw;}
                finally{attempt.Stop();AttemptDurationMs=attempt.ElapsedMilliseconds;}
                Interlocked.Increment(ref ExternalResponses);
                RequestProtocol="HTTP/"+external.Version;
                if(request.Method==HttpMethod.Post)await ObserveExternalReceipt(external,expectedIncident,cancellationToken).ConfigureAwait(false);
                return external;
            }
            if (scenario == "delivery.timeout") { Interlocked.Increment(ref Failures); await Task.Delay(TimeSpan.FromSeconds(60), cancellationToken).ConfigureAwait(false); }
            if (scenario == "delivery.unavailable" || scenario == "delivery.retry" || scenario == "delivery.store-forward")
            {
                Interlocked.Increment(ref Failures);
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = new StringContent("{}") };
            }
            if (scenario == "delivery.restart-recovery" && Interlocked.Increment(ref attempts) == 1)
            {
                Interlocked.Increment(ref Failures);
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = new StringContent("{}") };
            }
            if (scenario == "delivery.quota-rejection")
            {
                Interlocked.Increment(ref Failures);
                return new HttpResponseMessage((HttpStatusCode)429) { Content = new StringContent("{}") };
            }
            if (scenario == "delivery.payload-rejection")
            {
                Interlocked.Increment(ref Failures);
                return new HttpResponseMessage(HttpStatusCode.RequestEntityTooLarge) { Content = new StringContent("{}") };
            }
            if (scenario == "delivery.malformed-response")
            {
                Interlocked.Increment(ref Failures);
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{") };
            }
            if (request.Method == HttpMethod.Get)
            {
                Interlocked.Increment(ref PolicyReads);
                if (scenario == "governance.legacy-fail-open") return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
                var packageName = request.Headers.TryGetValues("X-Errorly-Sdk-Package", out var packages) ? packages.FirstOrDefault() : null;
                var packageVersion = request.Headers.TryGetValues("X-Errorly-Sdk-Version", out var versions) ? versions.FirstOrDefault() : null;
                if (!SdkLabProtocol.IsSafeIdentifier(packageName) || !SdkLabProtocol.IsSafeIdentifier(packageVersion))
                    return new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StringContent("{}") };
                var advisory = scenario == "governance.deprecated" || scenario == "governance.minimum-safe"
                    ? ",\"advisory\":{\"code\":\"sdk_deprecated\",\"packageName\":\"" + packageName + "\",\"installedVersion\":\"" + packageVersion + "\",\"minimumSafeVersion\":\"" + packageVersion + "\",\"reasonCategory\":\"sdk_lab\",\"message\":\"Controlled SDK Lab policy\"}"
                    : "";
                if (advisory.Length > 0) Interlocked.Increment(ref Advisories);
                var runtime = "{\"enabled\":true,\"expiresUtc\":\"2099-01-01T00:00:00Z\"" + advisory + "}";
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(runtime, Encoding.UTF8, "application/json") };
            }
            Interlocked.Increment(ref IncidentAttempts);
            var package = IncidentPackageSerializer.Deserialize(await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false));
            if (scenario == "governance.blocked" || scenario == "governance.cached-block-restart" || scenario == "governance.cache-binding" ||
                scenario == "governance.store-failure-known-blocked" || scenario == "governance.terminal-quarantine" || scenario == "governance.no-retry-storm")
            {
                Interlocked.Increment(ref TerminalPolicies);
                var blockedName = package.RuntimeContext.SdkName;
                var blockedVersion = package.RuntimeContext.SdkVersion;
                var blocked = "{\"code\":\"sdk_blocked\",\"packageName\":\"" + blockedName + "\",\"installedVersion\":\"" + blockedVersion + "\",\"minimumSafeVersion\":\"" + blockedVersion + "\",\"reasonCategory\":\"sdk_lab\",\"message\":\"Controlled SDK Lab terminal policy\",\"terminal\":true}";
                return new HttpResponseMessage((HttpStatusCode)426) { Content = new StringContent(blocked, Encoding.UTF8, "application/json") };
            }
            Interlocked.Increment(ref Submissions);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"status\":\"stored\",\"incidentId\":\"" + package.IncidentId.ToString("D") + "\"}", Encoding.UTF8, "application/json")
            };
        }
        private static bool ContainsAuthenticationFailure(Exception error)
        {for(var current=error;current!=null;current=current.InnerException)if(current is AuthenticationException)return true;return false;}
        private async Task ObserveExternalReceipt(HttpResponseMessage response,Guid expectedIncident,CancellationToken cancellationToken)
        {
            var buffer=new MemoryStream();
            try
            {
                // The response itself has completed. Settle and replay its bounded receipt with
                // independent ownership so the outer flush deadline cannot erase an observed 2xx.
                using(var settlement=new CancellationTokenSource(TimeSpan.FromSeconds(5)))
                {
                if(response.Content is null){ExternalDiagnostic=SdkLabSafeRejectionCodes.UnsupportedServerProtocol;ExternalRejectionCode=SdkLabSafeRejectionCodes.UnsupportedServerProtocol;ExternalHttpStatusCode=(int)response.StatusCode;ExternalHttpStatusFamily=$"{(int)response.StatusCode/100}xx";return;}
                using(var source=await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                {
                    var chunk=new byte[4096];int count;
                    while((count=await source.ReadAsync(chunk,0,chunk.Length,settlement.Token).ConfigureAwait(false))>0)
                    {if(buffer.Length+count>65536){ExternalDiagnostic=SdkLabSafeRejectionCodes.UnsupportedServerProtocol;ExternalRejectionCode=SdkLabSafeRejectionCodes.UnsupportedServerProtocol;ExternalHttpStatusCode=(int)response.StatusCode;ExternalHttpStatusFamily=$"{(int)response.StatusCode/100}xx";break;}buffer.Write(chunk,0,count);}
                }
                }
                var bytes=buffer.ToArray();var original=response.Content;var replacement=new ByteArrayContent(bytes);foreach(var header in original.Headers)replacement.Headers.TryAddWithoutValidation(header.Key,header.Value);response.Content=replacement;original.Dispose();
                var websiteSmoke=labRequest.Options.TryGetValue("websiteSmoke",out var smoke)&&string.Equals(smoke,"true",StringComparison.Ordinal);
                Guid? expectedApplicationId=null;if(websiteSmoke&&labRequest.Options.TryGetValue("websiteApplicationId",out var expectedApplication)&&Guid.TryParse(expectedApplication,out var parsedApplication))expectedApplicationId=parsedApplication;
                var assessment=SdkLabExternalReceipt.Assess((int)response.StatusCode,bytes,expectedIncident,websiteSmoke?expectedApplicationId??Guid.Empty:null);
                ExternalHttpStatusCode=assessment.HttpStatusCode;ExternalHttpStatusFamily=assessment.HttpStatusFamily;ExternalRejectionCode=assessment.RejectionCode;
                if(assessment.Accepted){AcceptedIncidentId=expectedIncident;ExternalDiagnostic=null;}else ExternalDiagnostic=assessment.DiagnosticCode;
                if(expectedIncident!=Guid.Empty)RecordReceipt(expectedIncident,new LabReceiptFacts(assessment.Accepted,assessment.HttpStatusCode,assessment.HttpStatusFamily,assessment.RejectionCode,"ResponseObserved",RequestProtocol));
            }
            catch(OperationCanceledException){throw;}
            catch{ExternalDiagnostic=SdkLabSafeRejectionCodes.UnsupportedServerProtocol;ExternalRejectionCode=SdkLabSafeRejectionCodes.UnsupportedServerProtocol;}
            finally{buffer.Dispose();}
        }
        internal bool WasAccepted(Guid incidentId){lock(receiptGate)return receipts.TryGetValue(incidentId,out var value)&&value.Accepted;}
        internal LabReceiptFacts Receipt(string incidentId)
        {
            if(!Guid.TryParse(incidentId,out var id))return null;
            lock(receiptGate){receipts.TryGetValue(id,out var value);return value;}
        }
        private void RecordReceipt(Guid incidentId,LabReceiptFacts value){lock(receiptGate){if(receipts.TryGetValue(incidentId,out var prior)&&prior.Accepted&&!value.Accepted)return;receipts[incidentId]=value;}}
    }

    private sealed class LabExecutionAttribution
    {
        internal static readonly string[] PropertyNames = { "sdkLabSuiteRunId", "sdkLabCorrelationId", "sdkLabEvidencePhase", "sdkLabScenarioId", "sdkLabTargetId" };
        internal readonly string Suite, Correlation, Phase, Scenario, Target;
        private LabExecutionAttribution(string suite, string correlation, string phase, string scenario, string target)
        { Suite = suite; Correlation = correlation; Phase = phase; Scenario = scenario; Target = target; }
        private static LabExecutionAttribution Create(string suite, string correlation, string phase, string scenario, string target)
        {
            if (!SdkLabProtocol.IsSafeIdentifier(suite) || !SdkLabProtocol.IsSafeIdentifier(correlation) ||
                !SdkLabProtocol.IsSafeIdentifier(scenario) || !SdkLabProtocol.IsSafeIdentifier(target) ||
                phase != "Probe" && phase != "Execution") return null;
            return new LabExecutionAttribution(suite, correlation, phase, scenario, target);
        }
        internal static LabExecutionAttribution FromLaunch()
        {
            var options = labRequest?.Options;
            if (options == null) return null;
            var fullWebsite=options.TryGetValue("websiteFullVerification",out var full)&&full=="true";
            var sourceSymbols=options.TryGetValue("sourceSymbolProbe",out var source)&&source=="true";
            if ((!fullWebsite&&!sourceSymbols) || options.TryGetValue("websiteControlledLocal", out var controlled) && controlled == "true") return null;
            options.TryGetValue("websiteSuiteRunId", out var suite);
            options.TryGetValue("registryScenarioId", out var scenario);
            var probe = fullWebsite&&(options.TryGetValue("websiteWorkflowEvidenceProbe", out var workflow) && workflow == "true" ||
                options.TryGetValue("websiteBindingProbe", out var binding) && binding == "true");
            return Create(suite, labRequest.CorrelationId, probe ? "Probe" : "Execution", scenario, labRequest.TargetId);
        }
        internal static LabExecutionAttribution FromProperties(IEnumerable<IncidentLogProperty> properties)
        {
            var values = PropertyNames.Select(name => properties.Where(property => property.Name == name).Select(property => property.Value).Distinct(StringComparer.Ordinal).ToArray()).ToArray();
            if (values.Any(value => value.Length != 1)) return null;
            return Create(values[0][0], values[1][0], values[2][0], values[3][0], values[4][0]);
        }
    }

    private sealed class LabReceiptFacts
    {
        internal readonly bool Accepted;internal readonly int? HttpStatusCode;internal readonly string HttpStatusFamily;internal readonly string RejectionCode;internal readonly string TransportState;internal readonly string RequestProtocol;
        internal LabReceiptFacts(bool accepted,int? httpStatusCode,string httpStatusFamily,string rejectionCode,string transportState,string requestProtocol){Accepted=accepted;HttpStatusCode=httpStatusCode;HttpStatusFamily=httpStatusFamily;RejectionCode=rejectionCode;TransportState=transportState;RequestProtocol=requestProtocol;}
    }

    private static SdkLabDeliveryDiagnostics DeliveryDiagnostics(string incidentId)
    {
        string authority = null;
        try { if (Uri.TryCreate(labServerUrl, UriKind.Absolute, out var endpoint)) authority = CanonicalEndpointAuthority.Normalize(new Uri(endpoint,"/api/v1/incidents")); } catch { }
        var receipt=labTransport?.Receipt(incidentId);var accepted=receipt?.Accepted==true;
        var queue = HasLabOutboxFiles("*.erly") ? accepted?"PendingOtherReports":"Pending" : HasLabOutboxFiles("*.rejected") ? "TerminalRejected" : "Empty";
        var flush=accepted&&labFlushState=="TimedOutQueueRetained"?"AcceptedBeforeFlushTimeout":labFlushState;
        return new SdkLabDeliveryDiagnostics
        {
            EndpointAuthority = authority, ConfiguredEndpointAuthority = authority, CredentialEnvelope = labCredentialEnvelope, RequestProtocol = receipt?.RequestProtocol??labTransport?.RequestProtocol,
            AttemptCount = labTransport?.IncidentAttempts ?? 0, FirstAttemptUtc = labTransport?.FirstAttemptUtc,
            AttemptDurationMs = labTransport?.AttemptDurationMs ?? 0, FlushDurationMs = labFlushDurationMs,
            FlushState = flush, QueueState = queue, TransportState = receipt?.TransportState??labTransport?.TransportState ?? "NotAttempted",
            ShutdownOrdering = "FlushSettledBeforeResult"
        };
    }
}
