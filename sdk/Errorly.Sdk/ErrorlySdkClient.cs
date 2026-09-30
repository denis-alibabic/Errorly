using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;

namespace Errorly;

/// <summary>A bounded incident recorder with a durable, retryable outbox. Public capture failures never escape to the host.</summary>
public sealed class ErrorlySdkClient:IDisposable
{
    private readonly object gate=new();
    private readonly object flushGate=new();private Task? activeFlush;
    private readonly Dictionary<string,string> context=new(StringComparer.Ordinal);
    private readonly List<IncidentLogEntry> logs=new();
    private readonly Guid session=Guid.NewGuid();
    private readonly SemaphoreSlim delivery=new(1,1);private readonly SemaphoreSlim persistence=new(1,1);private readonly SemaphoreSlim captureSlots=new(8,8);
    private readonly CancellationTokenSource stop=new();
    private readonly HttpClient? http;private readonly bool ownsHttp;
    private readonly Uri? endpoint;private readonly string? key,outbox;private readonly string? outboxIdentity,sourceRevision;private readonly Action<ErrorlyDiagnostic>? diagnosticCallback;
    private readonly TimeSpan shutdownTimeout;
    private readonly Task? worker;
    private const string BlockedDecisionFile=".sdk-blocked.json";
    private SdkPolicy policy=new();private long sequence;private int disposed;private DateTimeOffset blockedUntilUtc;private string? blockedTargetFramework,blockedApplicationKind;
    private long logSecond;private int rateCount;private uint dropped;
    private IDisposable? automatic;
    public IncidentRuntimeContext RuntimeContext {get;private set;}
    public bool IsEnabled=>endpoint is not null&&key is not null&&outbox is not null&&Volatile.Read(ref disposed)==0;
    /// <summary>Only safe fixed operational classifications; never contains exception messages or endpoints.</summary>
    public string? LastFailure {get;private set;}
    /// <summary>The most recent safe release advisory returned by the server, if any.</summary>
    public SdkReleaseAdvisory? CurrentReleaseAdvisory {get;private set;}

    internal ErrorlySdkClient(SdkOptions options)
    {
        try{RuntimeContext=RuntimeDetection.Detect(options);sourceRevision=RuntimeDetection.Safe(options.SourceRevision);}catch{RuntimeContext=new IncidentRuntimeContext(SdkName:"Errorly.Sdk",ApplicationKind:"Unknown");}diagnosticCallback=options.DiagnosticCallback;shutdownTimeout=options.ShutdownTimeout>TimeSpan.Zero&&options.ShutdownTimeout<=TimeSpan.FromSeconds(3)?options.ShutdownTimeout:TimeSpan.FromSeconds(2);
        try
        {
            var url=options.ServerBaseUrl;var credential=options.ApiKey;
            if(!string.IsNullOrWhiteSpace(options.Dsn)){var dsn=new Uri(options.Dsn);if(!string.IsNullOrEmpty(dsn.UserInfo))credential=Uri.UnescapeDataString(dsn.UserInfo);url=new UriBuilder(dsn){UserName="",Password="",Query="",Fragment=""}.Uri;}
            if(url is null||string.IsNullOrWhiteSpace(credential)){LastFailure="NotConfigured";return;}
            if(!url.IsAbsoluteUri||!string.IsNullOrEmpty(url.UserInfo)||url.Scheme!="https"&&!(url.Scheme=="http"&&url.IsLoopback))throw new ArgumentException();
            key=credential;endpoint=url;using(var hash=System.Security.Cryptography.SHA256.Create())outboxIdentity=Convert.ToBase64String(hash.ComputeHash(Encoding.UTF8.GetBytes(url.GetLeftPart(UriPartial.Authority)+"\n"+credential)));outbox=Path.GetFullPath(options.OutboxPath??Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Errorly","outbox",SafeDirectory(RuntimeContext.ApplicationName)));
            http=options.HttpClient??new HttpClient{Timeout=TimeSpan.FromSeconds(30)};ownsHttp=options.HttpClient is null;
            LoadBlockedDecision();
            if(options.AutomaticCapture)automatic=AutomaticCapture.Register(this);
            // Network/policy retrieval and delivery never run on the caller's UI thread.
            if(options.AutomaticUpload||options.AutomaticPolicyRefresh)worker=Task.Run(()=>RunAsync(options.AutomaticUpload,stop.Token));
        }
        catch{LastFailure="ConfigurationUnavailable";endpoint=null;key=null;outbox=null;}
    }
    private static string SafeDirectory(string? value)=>new string((value??"application").Where(c=>char.IsLetterOrDigit(c)||c=='-'||c=='_').Take(64).ToArray());

    /// <summary>Framework adapters set a known host kind; desktop/request integrations resolve ambiguous hosts.</summary>
    public void UseApplicationKind(ErrorlyApplicationKind kind)
    {try{if(!Monitor.TryEnter(gate))return;try{if(RuntimeContext.ApplicationKind=="Unknown"||kind is ErrorlyApplicationKind.Wpf or ErrorlyApplicationKind.WinForms or ErrorlyApplicationKind.AspNetCore){var next=RuntimeDetection.Name(kind);if(RuntimeContext.ApplicationKind!=next)ClearBlockedInMemory();RuntimeContext=RuntimeContext with{ApplicationKind=next,HostingModel=null};}}finally{Monitor.Exit(gate);}LoadBlockedDecision();}catch{}}
    internal void UsePackageIdentity(System.Reflection.Assembly assembly)
    {try{var identity=RuntimeDetection.PackageIdentity(assembly);if(identity.Name is not "Errorly.Wpf" and not "Errorly.WinForms" and not "Errorly.AspNetCore" and not "Errorly.Extensions.Logging")return;lock(gate){if(RuntimeContext.SdkName!=identity.Name||RuntimeContext.SdkVersion!=identity.Version||RuntimeContext.TargetFramework!=identity.TargetFramework)ClearBlockedInMemory();RuntimeContext=RuntimeContext with{SdkName=identity.Name,SdkVersion=identity.Version,TargetFramework=identity.TargetFramework};}LoadBlockedDecision();}catch{}}
    public void SetTag(string name,string? value){if(name is not null&&name.Length<=60)SetValue("tag."+name,value);}
    public void SetContext(string name,string? value)=>SetValue(name,value);
    public void SetUser(string? id,string? email=null){SetValue("userId",id);SetValue("userEmail",email);}
    private void SetValue(string name,string? value){try{if(string.IsNullOrWhiteSpace(name)||name.Length>64||!Monitor.TryEnter(gate))return;try{if(value is null){context.Remove(name);return;}if(context.Count>=16&&!context.ContainsKey(name))return;context[name]=SdkPolicy.Limit(value,256);}finally{Monitor.Exit(gate);}}catch{}}
    public bool AddBreadcrumb(string message)=>Log(IncidentLogLevel.Information,"Breadcrumb",message);
    public bool Log(IncidentLogLevel level,string? category,string? message,Exception? exception=null)
    {
        try
        {
            if(!Monitor.TryEnter(gate))return false;
            try
            {
                var current=CurrentPolicy();if(!current.Enabled||level<current.MinimumLevel)return false;
                var second=Stopwatch.GetTimestamp()/Stopwatch.Frequency;if(second!=logSecond){logSecond=second;rateCount=0;}if(++rateCount>current.RateLimit){dropped++;return false;}
                var hidden=context.Where(p=>!current.Keep(p.Key)).Select(p=>p.Value).ToArray();var budget=Stopwatch.StartNew();
                string? Redact(string? text){if(budget.ElapsedMilliseconds>8)throw new InvalidOperationException("Log processing budget.");return current.Redact(text,hidden);}
                var properties=context.Where(p=>current.Keep(p.Key)).Select(p=>new IncidentLogProperty(p.Key,Redact(p.Value)??"")).ToArray();
                logs.Add(new(DateTimeOffset.UtcNow,(ulong)++sequence,level,Redact(category),null,Redact(message),exception?.GetType().FullName,null,properties));
                while(logs.Count>current.EntryCap||logs.Sum(Size)>current.ByteCap){logs.RemoveAt(0);dropped++;}return true;
            }finally{Monitor.Exit(gate);}
        }catch{return false;}
    }
    private static int Size(IncidentLogEntry e)=>128+Encoding.UTF8.GetByteCount(e.RenderedMessage??"")+e.Properties.Sum(p=>Encoding.UTF8.GetByteCount(p.Name)+Encoding.UTF8.GetByteCount(p.Value));
    public Task<Guid?> CaptureMessageAsync(string message,CancellationToken cancellationToken=default)=>CaptureAsync(null,message,cancellationToken);
    public Task<Guid?> CaptureExceptionAsync(Exception exception,CancellationToken cancellationToken=default)=>exception is null?Task.FromResult<Guid?>(null):CaptureAsync(exception,null,cancellationToken);
    private async Task<Guid?> CaptureAsync(Exception? exception,string? message,CancellationToken token)
    {
        if(!IsEnabled)return null;
        if(IsLocallyBlocked()){LastFailure="SdkBlocked";return null;}
        if(!captureSlots.Wait(0)){LastFailure="CaptureCapacity";return null;}
        if(exception is not null&&!AutomaticCapture.TryReserve(exception)){captureSlots.Release();return null;}
        var succeeded=false;
        try
        {
            var package=await Task.Run(()=>CreatePackage(exception,message),token).ConfigureAwait(false);if(ShouldIgnore(package)){LastFailure="IgnoredByPolicy";succeeded=true;return null;}var bytes=IncidentPackageSerializer.Serialize(package);
            if(bytes.Length>4*1024*1024){LastFailure="PayloadLimit";return null;}
            await persistence.WaitAsync(token).ConfigureAwait(false);try{await Task.Run(()=>Persist(package.IncidentId,bytes,token),token).ConfigureAwait(false);}finally{persistence.Release();}
            succeeded=true;return package.IncidentId;
        }
        catch(OperationCanceledException){return null;}catch{LastFailure="PersistenceUnavailable";return null;}
        finally{if(exception is not null){if(!succeeded)AutomaticCapture.Release(exception);else AutomaticCapture.Complete(exception);}captureSlots.Release();}
    }
    internal IncidentPackage CreatePackage(Exception? exception,string? message)
    {
        lock(gate)
        {
            var policy=CurrentPolicy();var hidden=context.Where(p=>!policy.Keep(p.Key)).Select(p=>p.Value).ToArray();var now=DateTimeOffset.UtcNow;var ticks=(ulong)Stopwatch.GetTimestamp();
            var entries=policy.Enabled?logs.Where(l=>l.Level>=policy.MinimumLevel).Select(l=>new IncidentLogEntry(l.Timestamp,l.Sequence,l.Level,policy.Redact(l.Category,hidden),null,policy.Redact(l.RenderedMessage,hidden),l.ExceptionType,null,l.Properties.Where(p=>policy.Keep(p.Name)).Select(p=>new IncidentLogProperty(p.Name,policy.Redact(p.Value,hidden)??"")).ToArray())).ToArray():Array.Empty<IncidentLogEntry>();
            var exceptions=exception is null?Array.Empty<ErrorlyExceptionInfo>():new[]{ExceptionMetadata.Capture(exception,new HashSet<string>{System.Reflection.Assembly.GetEntryAssembly()?.GetName().Name??""})};
            exceptions=exceptions.Select(e=>e with{RawStackTrace=null,Frames=e.Frames.Select(f=>f with{File=ExceptionMetadata.NormalizePath(f.File)}).ToArray()}).ToArray();
            if(policy.Enabled&&context.Count>0&&policy.MinimumLevel<=IncidentLogLevel.Information)
            {
                var scope=new IncidentLogEntry(now,(ulong)++sequence,IncidentLogLevel.Information,"Context",null,null,null,null,context.Where(p=>policy.Keep(p.Key)).Select(p=>new IncidentLogProperty(p.Key,policy.Redact(p.Value,hidden)??"")).ToArray());
                if(scope.Properties.Count>0)entries=entries.Concat(new[]{scope}).ToArray();
            }
            while(entries.Length>policy.EntryCap||entries.Sum(Size)>policy.ByteCap)entries=entries.Skip(1).ToArray();
            string? RuntimeValue(string? value)=>RuntimeDetection.Safe(policy.Redact(value,hidden));
            var runtime=RuntimeContext with{ApplicationName=RuntimeValue(RuntimeContext.ApplicationName),Environment=RuntimeValue(RuntimeContext.Environment??policy.DefaultEnvironment),Release=RuntimeValue(RuntimeContext.Release)};
            var package=new IncidentPackage(Guid.NewGuid(),now,null,runtime.Environment,session,ErrorlyIncidentReportType.Problem,policy.Redact(message,hidden),(ulong)Stopwatch.Frequency,ticks,now.UtcDateTime.ToFileTimeUtc(),ticks,ticks,Array.Empty<IncidentPackageRecord>(),sourceRevision:sourceRevision,exceptions:exceptions,applicationVersion:runtime.Release,applicationLogContext:policy.Enabled?new IncidentLogContext(entries,dropped,processId:Process.GetCurrentProcess().Id):null,freezeTicks:ticks,runtimeContext:runtime);
            return package.WithRedactedTextEvidence(hidden);
        }
    }
    /// <summary>Checks configured request-path ignore prefixes without retaining the path in incident evidence.</summary>
    public bool ShouldIgnoreRequest(string path)
    {
        try{if(path is null)return false;return Volatile.Read(ref policy).IgnoreRules.Any(rule=>rule.Key=="RequestPathPrefix"&&path.StartsWith(rule.Value,StringComparison.Ordinal));}catch{return false;}
    }
    private bool ShouldIgnore(IncidentPackage package)
    {
        lock(gate)
        {
            foreach(var rule in CurrentPolicy().IgnoreRules)
            {
                if(rule.Key=="ExceptionType"&&package.Exceptions.Any(e=>e.Type==rule.Value))return true;
                if(rule.Key=="MessageContains"&&((package.ReportMessage?.IndexOf(rule.Value,StringComparison.Ordinal)??-1)>=0||(package.ApplicationLogContext?.Entries??Array.Empty<IncidentLogEntry>()).Any(e=>(e.RenderedMessage?.IndexOf(rule.Value,StringComparison.Ordinal)??-1)>=0)))return true;
                if(rule.Key=="RequestPathPrefix"&&(package.ApplicationLogContext?.Entries??Array.Empty<IncidentLogEntry>()).SelectMany(e=>e.Properties).Any(p=>(p.Name.Replace(".","").ToLowerInvariant() is "requestpath" or "httprequestpath")&&p.Value.StartsWith(rule.Value,StringComparison.Ordinal)))return true;
            }
            return false;
        }
    }
    private void Persist(Guid id,byte[] bytes,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();Directory.CreateDirectory(outbox!);var path=Path.Combine(outbox!,id.ToString("N")+".erly");
        // A cross-process outbox gate bounds enumeration and prevents capacity races. Never overwrite another incident.
        using var guard=OpenOutboxGate();BindOutbox(true);var files=Directory.EnumerateFiles(outbox!).Where(p=>p.EndsWith(".erly",StringComparison.Ordinal)||p.EndsWith(".rejected",StringComparison.Ordinal)||p.EndsWith(".blocked",StringComparison.Ordinal)||p.EndsWith(".tmp",StringComparison.Ordinal)).Take(257).ToArray();if(files.Length>=256||files.Sum(p=>new FileInfo(p).Length)+bytes.Length>64L*1024*1024)throw new IOException("Outbox capacity reached.");
        var temporary=path+".tmp";
        try{using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){stream.Write(bytes,0,bytes.Length);stream.Flush(true);}token.ThrowIfCancellationRequested();File.Move(temporary,path);}finally{if(File.Exists(temporary))File.Delete(temporary);}
    }
    private void BindOutbox(bool create)
    {
        var owner=Path.Combine(outbox!,".owner");
        if(File.Exists(owner)){if(new FileInfo(owner).Length>128||File.ReadAllText(owner)!=outboxIdentity)throw new IOException("Outbox scope mismatch.");return;}
        if(!create||Directory.EnumerateFiles(outbox!,"*.erly").Any())throw new IOException("Unbound outbox.");
        using var stream=new FileStream(owner,FileMode.CreateNew,FileAccess.Write,FileShare.Read);var bytes=Encoding.UTF8.GetBytes(outboxIdentity!);stream.Write(bytes,0,bytes.Length);stream.Flush(true);
    }
    private FileStream OpenOutboxGate()=>new(Path.Combine(outbox!,".lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
    public Task FlushAsync(CancellationToken cancellationToken=default)
    {
        try{lock(flushGate){if(activeFlush is null||activeFlush.IsCompleted)activeFlush=Task.Run(()=>FlushCoreAsync(cancellationToken));return cancellationToken.CanBeCanceled?WaitForFlushAsync(activeFlush,cancellationToken):activeFlush;}}catch{return Task.CompletedTask;}
    }
    private static async Task WaitForFlushAsync(Task task,CancellationToken cancellationToken)
    {
        // Keep the public boundary failure-contained, but never report completion while
        // the delivery task still owns the HTTP request or outbox.
        try
        {
            var cancelled=Task.Delay(Timeout.Infinite,cancellationToken);
            await Task.WhenAny(task,cancelled).ConfigureAwait(false);
            await task.ConfigureAwait(false);
        }
        catch{}
    }
    private async Task FlushCoreAsync(CancellationToken cancellationToken)
    {
        if(!IsEnabled)return;
        try
        {
            await delivery.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if(!Directory.Exists(outbox!))return;
                using var guard=new FileStream(Path.Combine(outbox!,".delivery"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None);
                BindOutbox(false);
                foreach(var path in Directory.EnumerateFiles(outbox!,"*.erly").Take(256).OrderBy(p=>p,StringComparer.Ordinal).ToArray())
                {
                    using var attempt=CancellationTokenSource.CreateLinkedTokenSource(cancellationToken,stop.Token);attempt.CancelAfter(TimeSpan.FromSeconds(30));
                    cancellationToken.ThrowIfCancellationRequested();var info=new FileInfo(path);if(info.Length>4*1024*1024){LastFailure="PayloadLimit";continue;}
                    byte[] bytes;IncidentPackage package;try{bytes=File.ReadAllBytes(path);package=IncidentPackageSerializer.Deserialize(bytes);}catch{File.Move(path,path+".rejected");LastFailure="InvalidPackage";continue;}
                    using var request=new HttpRequestMessage(HttpMethod.Post,new Uri(endpoint!,"/api/v1/incidents"));request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",key);AddRuntimeHeaders(request,package.RuntimeContext);request.Content=new ByteArrayContent(bytes);request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/octet-stream");
                    using var response=await http!.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,attempt.Token).ConfigureAwait(false);
                    if(response.IsSuccessStatusCode)
                    {
                        // Once success headers are observed, this attempt owns bounded receipt
                        // settlement. A caller deadline may stop later queue entries, but cannot
                        // turn this completed response back into an unavailable/queued result.
                        using var settlement=new CancellationTokenSource(TimeSpan.FromSeconds(5));
                        var json=await ReadBoundedAsync(response.Content,settlement.Token).ConfigureAwait(false);using var result=JsonDocument.Parse(json);if(result.RootElement.TryGetProperty("incidentId",out var value)&&value.TryGetGuid(out var receipt)&&receipt==package.IncidentId){File.Delete(path);LastFailure=null;ApplyAdvisory(SdkReleasePolicyParser.ParseAccepted(json),package.RuntimeContext);}else LastFailure="InvalidReceipt";
                    }
                    else if((int)response.StatusCode==426)
                    {
                        string? json=null;try{json=await ReadBoundedAsync(response.Content,attempt.Token).ConfigureAwait(false);}catch{}var advisory=json is null?null:SdkReleasePolicyParser.ParseBlocked(json);
                        if(advisory is not null&&Matches(advisory,package.RuntimeContext)){ApplyAdvisory(advisory,package.RuntimeContext);PersistBlockedDecision(advisory,package.RuntimeContext!);QuarantineBlocked(package);LastFailure="SdkBlocked";break;}
                        File.Move(path,path+".rejected");LastFailure="DeliveryRejected";
                    }
                    else if((int)response.StatusCode>=400&&(int)response.StatusCode<500&&(int)response.StatusCode is not 408 and not 429){File.Move(path,path+".rejected");LastFailure="DeliveryRejected";}
                    else {LastFailure="DeliveryUnavailable";break;}
                }
            }
            finally{delivery.Release();}
        }
        catch(OperationCanceledException){LastFailure="DeliveryUnavailable";}catch{LastFailure="DeliveryUnavailable";}
    }
    private bool IsLocallyBlocked()
    {
        var expired=false;lock(gate){if(CurrentReleaseAdvisory?.State!=SdkReleaseState.Blocked)return false;if(CurrentReleaseAdvisory.PackageName!=RuntimeContext.SdkName||CurrentReleaseAdvisory.InstalledVersion!=RuntimeContext.SdkVersion||blockedTargetFramework!=RuntimeContext.TargetFramework||blockedApplicationKind!=RuntimeContext.ApplicationKind){ClearBlockedInMemory();return false;}if(blockedUntilUtc>DateTimeOffset.UtcNow)return true;ClearBlockedInMemory();expired=true;}
        if(expired)DeleteBlockedDecision();return false;
    }
    private static bool Matches(SdkReleaseAdvisory advisory,IncidentRuntimeContext? runtime)=>advisory.PackageName==runtime?.SdkName&&advisory.InstalledVersion==runtime?.SdkVersion;
    private void ApplyAdvisory(SdkReleaseAdvisory? advisory,IncidentRuntimeContext? runtime)
    {
        if(advisory is null||!Matches(advisory,runtime))return;
        lock(gate){CurrentReleaseAdvisory=advisory;if(advisory.State==SdkReleaseState.Blocked){blockedUntilUtc=DateTimeOffset.UtcNow.AddMinutes(5);blockedTargetFramework=runtime?.TargetFramework;blockedApplicationKind=runtime?.ApplicationKind;}}
        try{diagnosticCallback?.Invoke(new ErrorlyDiagnostic(advisory.State==SdkReleaseState.Blocked?ErrorlyDiagnosticCode.SdkBlocked:ErrorlyDiagnosticCode.SdkDeprecated,advisory));}catch{}
    }
    private void QuarantineBlocked(IncidentPackage rejected)
    {
        foreach(var candidate in Directory.EnumerateFiles(outbox!,"*.erly").Take(256).ToArray())
        {
            try{var package=IncidentPackageSerializer.Deserialize(File.ReadAllBytes(candidate));if(package.RuntimeContext?.SdkName==rejected.RuntimeContext?.SdkName&&package.RuntimeContext?.SdkVersion==rejected.RuntimeContext?.SdkVersion)File.Move(candidate,candidate+".blocked");}catch{}
        }
        // Keep only a small local diagnostic sample. The server response is terminal, so these files are never retried.
        foreach(var stale in Directory.EnumerateFiles(outbox!,"*.blocked").OrderByDescending(File.GetLastWriteTimeUtc).Skip(16).ToArray()){try{File.Delete(stale);}catch{}}
    }
    private void PersistBlockedDecision(SdkReleaseAdvisory advisory,IncidentRuntimeContext runtime)
    {
        try
        {
            if(outbox is null||outboxIdentity is null||!Directory.Exists(outbox))return;var expires=blockedUntilUtc;
            var json=JsonSerializer.Serialize(new{schemaVersion=1,binding=outboxIdentity,receivedUtc=DateTimeOffset.UtcNow,expiresUtc=expires,code="sdk_blocked",packageName=advisory.PackageName,installedVersion=advisory.InstalledVersion,targetFramework=runtime.TargetFramework,applicationKind=runtime.ApplicationKind,minimumSafeVersion=advisory.MinimumSafeVersion,reasonCategory=advisory.ReasonCategory,terminal=true});
            if(Encoding.UTF8.GetByteCount(json)>4096)return;var path=Path.Combine(outbox,BlockedDecisionFile);var temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";var bytes=Encoding.UTF8.GetBytes(json);
            try{using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){stream.Write(bytes,0,bytes.Length);stream.Flush(true);}if(File.Exists(path))File.Replace(temporary,path,null);else File.Move(temporary,path);}finally{if(File.Exists(temporary))File.Delete(temporary);}
        }catch{}
    }
    private void LoadBlockedDecision()
    {
        try
        {
            if(outbox is null||outboxIdentity is null||!Directory.Exists(outbox))return;var owner=Path.Combine(outbox,".owner");var path=Path.Combine(outbox,BlockedDecisionFile);
            if(!File.Exists(owner)||!File.Exists(path)||new FileInfo(owner).Length>128||File.ReadAllText(owner)!=outboxIdentity)return;
            var info=new FileInfo(path);if(info.Length is <=0 or >4096){DeleteBlockedDecision();return;}var json=File.ReadAllText(path);using var document=JsonDocument.Parse(json);var root=document.RootElement;
            if(!root.TryGetProperty("schemaVersion",out var schema)||schema.ValueKind!=JsonValueKind.Number||schema.GetInt32()!=1||!root.TryGetProperty("binding",out var binding)||binding.ValueKind!=JsonValueKind.String||binding.GetString()!=outboxIdentity||!root.TryGetProperty("receivedUtc",out var received)||!root.TryGetProperty("expiresUtc",out var expiry)){DeleteBlockedDecision();return;}
            var receivedUtc=received.GetDateTimeOffset();var expires=expiry.GetDateTimeOffset();var now=DateTimeOffset.UtcNow;if(receivedUtc>now.AddMinutes(1)||expires<=now||expires<=receivedUtc||expires>receivedUtc.AddMinutes(5)||expires>now.AddMinutes(5)){DeleteBlockedDecision();return;}var advisory=SdkReleasePolicyParser.ParseCachedBlocked(json);if(advisory is null){DeleteBlockedDecision();return;}
            if(!root.TryGetProperty("targetFramework",out var target)||target.ValueKind!=JsonValueKind.String||!root.TryGetProperty("applicationKind",out var appKind)||appKind.ValueKind!=JsonValueKind.String)return;
            if(!Matches(advisory,RuntimeContext)||target.GetString()!=RuntimeContext.TargetFramework||appKind.GetString()!=RuntimeContext.ApplicationKind)return;
            lock(gate){if(CurrentReleaseAdvisory?.State==SdkReleaseState.Blocked&&blockedUntilUtc>=expires&&blockedTargetFramework==target.GetString()&&blockedApplicationKind==appKind.GetString())return;CurrentReleaseAdvisory=advisory;blockedUntilUtc=expires;blockedTargetFramework=target.GetString();blockedApplicationKind=appKind.GetString();}try{diagnosticCallback?.Invoke(new ErrorlyDiagnostic(ErrorlyDiagnosticCode.SdkBlocked,advisory));}catch{}
        }catch{DeleteBlockedDecision();}
    }
    private void ClearBlockedInMemory(){CurrentReleaseAdvisory=null;blockedUntilUtc=default;blockedTargetFramework=null;blockedApplicationKind=null;}
    private void DeleteBlockedDecision(){try{if(outbox is not null){var path=Path.Combine(outbox,BlockedDecisionFile);if(File.Exists(path))File.Delete(path);}}catch{}}
    public async Task<bool> RefreshPolicyAsync(CancellationToken cancellationToken=default)
    {
        if(!IsEnabled)return false;
        try{using var request=new HttpRequestMessage(HttpMethod.Get,new Uri(endpoint!,"/api/v1/runtime-policy"));request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",key);AddRuntimeHeaders(request,RuntimeContext);using var response=await http!.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,cancellationToken).ConfigureAwait(false);if(!response.IsSuccessStatusCode)return false;var json=await ReadBoundedAsync(response.Content,cancellationToken).ConfigureAwait(false);if(json.Length>65536)return false;var next=SdkPolicy.Parse(json);lock(gate){policy=next;logs.Clear();}ApplyAdvisory(SdkReleasePolicyParser.ParseAccepted(json),RuntimeContext);return true;}catch{return false;}
    }
    private static void AddRuntimeHeaders(HttpRequestMessage request,IncidentRuntimeContext? runtime)
    {
        if(runtime is null)return;void Add(string name,string? value){if(value is not null&&!string.IsNullOrEmpty(value)&&value.Length<=128)request.Headers.TryAddWithoutValidation(name,value);}
        Add("X-Errorly-Sdk-Package",runtime.SdkName);Add("X-Errorly-Sdk-Version",runtime.SdkVersion);Add("X-Errorly-Target-Framework",runtime.TargetFramework);Add("X-Errorly-Application-Kind",runtime.ApplicationKind);
    }
    private SdkPolicy CurrentPolicy()
    {
        if(policy.ExpiresUtc!=default&&policy.ExpiresUtc<=DateTimeOffset.UtcNow)
        {
            // Retain custom redactors while revoking privacy permissions when a policy expires.
            policy=new SdkPolicy{Enabled=policy.Enabled,MinimumLevel=policy.MinimumLevel,EntryCap=policy.EntryCap,ByteCap=policy.ByteCap,RateLimit=policy.RateLimit,Patterns=policy.Patterns,DefaultEnvironment=policy.DefaultEnvironment,IgnoreRules=policy.IgnoreRules};
        }
        return policy;
    }
    private static async Task<string> ReadBoundedAsync(HttpContent content,CancellationToken token)
    {
        using var stream=await content.ReadAsStreamAsync().ConfigureAwait(false);using var result=new MemoryStream();var buffer=new byte[4096];int count;
        while((count=await stream.ReadAsync(buffer,0,buffer.Length,token).ConfigureAwait(false))>0){if(result.Length+count>65536)throw new InvalidDataException("Response bound exceeded.");result.Write(buffer,0,count);}
        return Encoding.UTF8.GetString(result.ToArray());
    }
    private async Task RunAsync(bool upload,CancellationToken token)
    {
        var retry=5;var nextPolicy=DateTimeOffset.MinValue;
        while(!token.IsCancellationRequested)
        {
            try{if(DateTimeOffset.UtcNow>=nextPolicy){await RefreshPolicyAsync(token).ConfigureAwait(false);nextPolicy=DateTimeOffset.UtcNow.AddMinutes(1);}if(upload)await FlushAsync(token).ConfigureAwait(false);retry=LastFailure=="DeliveryUnavailable"?Math.Min(300,retry*2):5;await Task.Delay(TimeSpan.FromSeconds(retry),token).ConfigureAwait(false);}catch(OperationCanceledException){break;}catch{LastFailure="WorkerUnavailable";try{await Task.Delay(TimeSpan.FromSeconds(30),token).ConfigureAwait(false);}catch{break;}}
        }
    }
    public void CaptureUnhandled(Exception exception)
    {try{using var timeout=new CancellationTokenSource(shutdownTimeout);var capture=CaptureExceptionAsync(exception,timeout.Token);Task.WhenAll(capture,AutomaticCapture.Pending(exception)).Wait(shutdownTimeout);}catch{}}
    public async Task ShutdownAsync(CancellationToken token=default){try{using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(shutdownTimeout);await Task.WhenAny(FlushAsync(timeout.Token),Task.Delay(shutdownTimeout)).ConfigureAwait(false);}catch{}finally{Dispose();}}
    public void Dispose(){if(Interlocked.Exchange(ref disposed,1)!=0)return;try{automatic?.Dispose();}catch{}try{stop.Cancel();}catch{}if(ownsHttp&&http is not null){if(worker is null||worker.IsCompleted)http.Dispose();else _=worker.ContinueWith(_=>http.Dispose(),TaskScheduler.Default);}GC.SuppressFinalize(this);}
}

internal static class AutomaticCapture
{
    private sealed class Marker{internal readonly TaskCompletionSource<bool> Completion=new(TaskCreationOptions.RunContinuationsAsynchronously);}
    private static readonly ConditionalWeakTable<Exception,Marker> Seen=new();
    private static readonly object Gate=new();private static readonly List<ErrorlySdkClient> Clients=new();
    internal static bool TryReserve(Exception exception){lock(Gate){if(Seen.TryGetValue(exception,out _))return false;Seen.Add(exception,new());return true;}}
    internal static Task Pending(Exception exception){lock(Gate)return Seen.TryGetValue(exception,out var marker)?marker.Completion.Task:Task.CompletedTask;}
    internal static void Complete(Exception exception){lock(Gate)if(Seen.TryGetValue(exception,out var marker))marker.Completion.TrySetResult(true);}
    internal static void Release(Exception exception){lock(Gate){if(Seen.TryGetValue(exception,out var marker))marker.Completion.TrySetResult(false);Seen.Remove(exception);}}
    internal static IDisposable Register(ErrorlySdkClient client){lock(Gate){if(Clients.Count==0){AppDomain.CurrentDomain.UnhandledException+=Unhandled;TaskScheduler.UnobservedTaskException+=Unobserved;AppDomain.CurrentDomain.ProcessExit+=Exit;}Clients.Add(client);}return new Registration(client);}
    private static ErrorlySdkClient? Current(){lock(Gate)return Clients.FirstOrDefault(c=>c.IsEnabled);}
    private static void Unhandled(object? sender,UnhandledExceptionEventArgs args){if(args.ExceptionObject is Exception e)Current()?.CaptureUnhandled(e);}
    private static void Unobserved(object? sender,UnobservedTaskExceptionEventArgs args){try{var client=Current();var failures=args.Exception.Flatten().InnerExceptions;if(client is not null)_=client.CaptureExceptionAsync(failures.Count==1?failures[0]:args.Exception);}catch{} /* Never mark the exception observed. */}
    private static void Exit(object? sender,EventArgs args){try{Current()?.ShutdownAsync().Wait(TimeSpan.FromSeconds(2));}catch{}}
    private sealed class Registration(ErrorlySdkClient client):IDisposable{public void Dispose(){lock(Gate){Clients.Remove(client);if(Clients.Count==0){AppDomain.CurrentDomain.UnhandledException-=Unhandled;TaskScheduler.UnobservedTaskException-=Unobserved;AppDomain.CurrentDomain.ProcessExit-=Exit;}}}}
}









