using System.Collections.ObjectModel;

namespace Errorly;

internal static class ProtocolTextCompatibility
{
    internal static System.Text.RegularExpressions.RegexOptions LiteralRegexOptions=>
#if NET7_0_OR_GREATER
        System.Text.RegularExpressions.RegexOptions.CultureInvariant|System.Text.RegularExpressions.RegexOptions.NonBacktracking;
#else
        System.Text.RegularExpressions.RegexOptions.CultureInvariant;
#endif
    internal static string Utf8(ReadOnlyMemory<byte> value)
    {
#if NETFRAMEWORK
        return System.Text.Encoding.UTF8.GetString(value.ToArray());
#else
        return System.Text.Encoding.UTF8.GetString(value.Span);
#endif
    }
}

/// <summary>Identifies the controlled report that created an incident package.</summary>
public enum ErrorlyIncidentReportType : byte { Problem = 1 }

/// <summary>Centralized hard limits for incident package serialization.</summary>
public static class IncidentPackageLimits
{
    public const int MaximumPackageBytes=64*1024*1024;
    public const int MaximumRecords=4096;
    public const int MaximumFrames=2048;
    public const int MaximumJpegBytes=2*1024*1024;
    public const int MaximumRecordPayloadBytes=2*1024*1024;
    public const int MaximumStringBytes=4096;
    public const int MaximumGroupingKeyBytes=4096;
    public const int MaximumStackFrames=2048;
    public const int MaximumEnvironmentBytes=128;
    public const int MaximumLogEntries=2000;
    public const int MaximumLogContextBytes=4*1024*1024;
    public const int MaximumLogEntryBytes=8192;
    public const int MaximumLogProperties=16;
    public const int MaximumLogPropertyBytes=512;
}

/// <summary>Identifies the severity of an application log entry captured with an incident.</summary>
public enum IncidentLogLevel : byte { Trace, Debug, Information, Warning, Error, Critical }

/// <summary>One primitive, already-redacted structured application log value.</summary>
public sealed class IncidentLogProperty
{
    public IncidentLogProperty(string name,string value){Name=name;Value=value;}
    public string Name{get;} public string Value{get;}
}

/// <summary>One bounded application log entry associated with a captured incident.</summary>
public sealed class IncidentLogEntry
{
    public IncidentLogEntry(DateTimeOffset timestamp,ulong sequence,IncidentLogLevel level,string? category,string? messageTemplate,string? renderedMessage,string? exceptionType,string? exceptionMessage,IReadOnlyList<IncidentLogProperty>? properties=null)
    { Timestamp=timestamp.ToUniversalTime();Sequence=sequence;Level=level;Category=category;MessageTemplate=messageTemplate;RenderedMessage=renderedMessage;ExceptionType=exceptionType;ExceptionMessage=exceptionMessage;Properties=new ReadOnlyCollection<IncidentLogProperty>((properties??[]).ToArray()); }
    public DateTimeOffset Timestamp{get;} public ulong Sequence{get;} public IncidentLogLevel Level{get;} public string? Category{get;} public string? MessageTemplate{get;} public string? RenderedMessage{get;} public string? ExceptionType{get;} public string? ExceptionMessage{get;} public IReadOnlyList<IncidentLogProperty> Properties{get;}
}

/// <summary>Versioned, bounded application log context attached only to an incident package.</summary>
public sealed class IncidentLogContext
{
    public const byte CurrentVersion=1;
    public IncidentLogContext(IReadOnlyList<IncidentLogEntry>? entries,uint droppedEntryCount=0,bool rateLimited=false,bool truncated=false,int processId=0,byte version=CurrentVersion)
    { Version=version;Entries=new ReadOnlyCollection<IncidentLogEntry>((entries??[]).ToArray());DroppedEntryCount=droppedEntryCount;RateLimited=rateLimited;Truncated=truncated;ProcessId=processId; }
    public byte Version{get;} public IReadOnlyList<IncidentLogEntry> Entries{get;} public uint DroppedEntryCount{get;} public bool RateLimited{get;} public bool Truncated{get;} public int ProcessId{get;}
}

/// <summary>Provides conservative redaction for application log text and structured properties.</summary>
public static class IncidentLogSanitizer
{
    private static readonly System.Text.RegularExpressions.Regex SensitiveAssignment=new(@"(?ix)\b(password|passwd|pwd|token|api[_-]?key|authorization|connection\s*string)\s*[:=]\s*([^\s;,&]+)",System.Text.RegularExpressions.RegexOptions.CultureInvariant,System.TimeSpan.FromMilliseconds(50));
    private static readonly System.Text.RegularExpressions.Regex BearerToken=new(@"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+",System.Text.RegularExpressions.RegexOptions.CultureInvariant,System.TimeSpan.FromMilliseconds(50));
    public static string? RedactText(string? value)
    { try{return value is null?null:SensitiveAssignment.Replace(BearerToken.Replace(value,"Bearer [REDACTED]"),"$1=[REDACTED]");}catch(System.Text.RegularExpressions.RegexMatchTimeoutException){return "[REDACTED]";} }
    public static IncidentLogContext? Sanitize(IncidentLogContext? context)
    {
        if(context is null)return null;
        var entries=new List<IncidentLogEntry>(Math.Min(context.Entries.Count,IncidentPackageLimits.MaximumLogEntries));
        foreach(var entry in context.Entries.Take(IncidentPackageLimits.MaximumLogEntries))
        {
            var properties=entry.Properties.Take(IncidentPackageLimits.MaximumLogProperties).Select(property=>new IncidentLogProperty(Limit(RedactText(property.Name),IncidentPackageLimits.MaximumLogPropertyBytes)??string.Empty,IsSensitiveName(property.Name)?"[REDACTED]":Limit(RedactText(property.Value),IncidentPackageLimits.MaximumLogPropertyBytes)??string.Empty)).ToArray();
            entries.Add(new(entry.Timestamp,entry.Sequence,entry.Level,Limit(RedactText(entry.Category),IncidentPackageLimits.MaximumStringBytes),Limit(RedactText(entry.MessageTemplate),IncidentPackageLimits.MaximumStringBytes),Limit(RedactText(entry.RenderedMessage),IncidentPackageLimits.MaximumStringBytes),Limit(RedactText(entry.ExceptionType),IncidentPackageLimits.MaximumStringBytes),Limit(RedactText(entry.ExceptionMessage),IncidentPackageLimits.MaximumStringBytes),properties));
        }
        return new(entries,context.DroppedEntryCount,context.RateLimited,context.Truncated,Math.Max(0,context.ProcessId),context.Version);
    }
    private static bool IsSensitiveName(string? name){var normalized=(name??string.Empty).Replace("_",string.Empty).Replace("-",string.Empty);return normalized.IndexOf("password",StringComparison.OrdinalIgnoreCase)>=0||normalized.IndexOf("token",StringComparison.OrdinalIgnoreCase)>=0||normalized.IndexOf("apikey",StringComparison.OrdinalIgnoreCase)>=0||normalized.IndexOf("authorization",StringComparison.OrdinalIgnoreCase)>=0||normalized.IndexOf("connectionstring",StringComparison.OrdinalIgnoreCase)>=0;}
    private static string? Limit(string? value,int maximum){if(value is null||System.Text.Encoding.UTF8.GetByteCount(value)<=maximum)return value;var bytes=0;var length=0;foreach(var character in value){var next=System.Text.Encoding.UTF8.GetByteCount(value.Substring(length,1));if(bytes+next>maximum)break;bytes+=next;length++;}return value.Substring(0,length);}
}

internal static class IncidentEnvironment
{
    internal static string? Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var normalized=value.Trim();
        if (System.Text.Encoding.UTF8.GetByteCount(normalized)>IncidentPackageLimits.MaximumEnvironmentBytes || normalized.Any(char.IsControl)) throw new InvalidDataException("Incident environment is invalid.");
        return normalized;
    }
}

/// <summary>One immutable serialized timeline record.</summary>
public sealed class IncidentPackageRecord
{
    internal IncidentPackageRecord(uint type,uint flags,ulong sequence,ulong timestamp,ulong windowId,uint width,uint height,uint provider,uint resolutionTier,byte[] payload)
    { Type=type;Flags=flags;Sequence=sequence;Timestamp=timestamp;WindowId=windowId;Width=width;Height=height;Provider=provider;ResolutionTier=resolutionTier;Payload=payload; }
    public uint Type{get;} public uint Flags{get;} public ulong Sequence{get;} public ulong Timestamp{get;} public ulong WindowId{get;}
    public uint Width{get;} public uint Height{get;} public uint Provider{get;} public uint ResolutionTier{get;}
    public ReadOnlyMemory<byte> Payload{get;}
}

/// <summary>Immutable, backend-usable representation of a frozen incident.</summary>
public sealed class IncidentPackage
{
    internal IncidentPackage(Guid incidentId,DateTimeOffset createdUtc,string? applicationId,string? environment,Guid sessionId,ErrorlyIncidentReportType reportType,string? reportMessage,ulong qpcFrequency,ulong qpcAnchor,long utcAnchorFileTime,ulong startTicks,ulong endTicks,IReadOnlyList<IncidentPackageRecord> records,string? sourceRevision=null,IReadOnlyList<ErrorlyExceptionInfo>? exceptions=null,string? applicationVersion=null,string? groupingKey=null,IncidentLogContext? applicationLogContext=null,ulong? freezeTicks=null,IncidentRuntimeContext? runtimeContext=null)
    { IncidentId=incidentId;CreatedUtc=createdUtc;ApplicationId=applicationId;ApplicationVersion=NormalizeApplicationVersion(applicationVersion);Environment=IncidentEnvironment.Normalize(environment);SessionId=sessionId;ReportType=reportType;ReportMessage=reportMessage;QpcFrequency=qpcFrequency;QpcAnchor=qpcAnchor;UtcAnchorFileTime=utcAnchorFileTime;StartTicks=startTicks;EndTicks=endTicks;FreezeTicks=freezeTicks;Records=new ReadOnlyCollection<IncidentPackageRecord>(records.ToArray());SourceRevision=sourceRevision;Exceptions=new ReadOnlyCollection<ErrorlyExceptionInfo>((exceptions??[]).ToArray());GroupingKey=NormalizeGroupingKey(groupingKey);ApplicationLogContext=applicationLogContext;RuntimeContext=runtimeContext; }
    public const ushort SchemaVersion=10;
    public Guid IncidentId{get;} public DateTimeOffset CreatedUtc{get;} public string? ApplicationId{get;} public string? ApplicationVersion{get;} public string? Environment{get;} public Guid SessionId{get;}
    public ErrorlyIncidentReportType ReportType{get;} public string? ReportMessage{get;}
    public ulong QpcFrequency{get;} public ulong QpcAnchor{get;} public long UtcAnchorFileTime{get;} public ulong StartTicks{get;} public ulong EndTicks{get;} public ulong? FreezeTicks{get;}
    public IReadOnlyList<IncidentPackageRecord> Records{get;}
    public string? SourceRevision{get;}
    public IReadOnlyList<ErrorlyExceptionInfo> Exceptions{get;}
    public string? GroupingKey{get;}
    public IncidentLogContext? ApplicationLogContext{get;}
    public IncidentRuntimeContext? RuntimeContext{get;}
    public IncidentPackage WithRuntimeContext(IncidentRuntimeContext? context)=>new(IncidentId,CreatedUtc,ApplicationId,Environment,SessionId,ReportType,ReportMessage,QpcFrequency,QpcAnchor,UtcAnchorFileTime,StartTicks,EndTicks,Records,SourceRevision,Exceptions,ApplicationVersion,GroupingKey,ApplicationLogContext,FreezeTicks,context);
    /// <summary>Returns an otherwise identical package with sanitized or omitted application log context.</summary>
    public IncidentPackage WithApplicationLogContext(IncidentLogContext? context)=>new(IncidentId,CreatedUtc,ApplicationId,Environment,SessionId,ReportType,ReportMessage,QpcFrequency,QpcAnchor,UtcAnchorFileTime,StartTicks,EndTicks,Records,SourceRevision,Exceptions,ApplicationVersion,GroupingKey,context,FreezeTicks,RuntimeContext);
    /// <summary>Returns an otherwise identical frozen package with reporting metadata overridden for an explicit report.</summary>
    public IncidentPackage WithReportingMetadata(string? applicationVersion,string? environment,string? sourceRevision)=>new(IncidentId,CreatedUtc,ApplicationId,environment,SessionId,ReportType,ReportMessage,QpcFrequency,QpcAnchor,UtcAnchorFileTime,StartTicks,EndTicks,Records,sourceRevision,Exceptions,applicationVersion,GroupingKey,ApplicationLogContext,FreezeTicks,RuntimeContext);
    /// <summary>Returns a copy with known private scalar values removed from textual evidence.
    /// Binary replay images are unchanged. Excessive values or matching timeout omit textual
    /// evidence rather than retain a partially filtered value. Log context is filtered separately.</summary>
    public IncidentPackage WithRedactedTextEvidence(IReadOnlyList<string> privateValues)
    {
        if(privateValues.Count==0)return this;
        var values=privateValues.Where(value=>!string.IsNullOrEmpty(value)).Distinct(StringComparer.Ordinal).OrderByDescending(value=>value.Length).ToArray();
        if(values.Length==0)return this;
        System.Text.RegularExpressions.Regex? matcher=null;
        if(values.Length<=128&&values.Sum(value=>(long)value.Length)<=16384)
        {
            try{matcher=new(string.Join("|",values.Select(System.Text.RegularExpressions.Regex.Escape)),ProtocolTextCompatibility.LiteralRegexOptions,TimeSpan.FromMilliseconds(50));}
            catch(NotSupportedException){ /* Omit text if the bounded matcher cannot be constructed. */ }
        }
        string? Redact(string? text)
        {
            if(string.IsNullOrEmpty(text))return text;
            if(matcher is null)return "*";
            try{return matcher.Replace(text,"*");}
            catch(System.Text.RegularExpressions.RegexMatchTimeoutException){return "*";}
        }
        var records=Records.Select(record=>
        {
            if(!((record.Type==2&&record.Flags is 0 or 1)||(record.Type==4&&record.Flags==2)))return record;
            var payload=System.Text.Encoding.UTF8.GetBytes(Redact(ProtocolTextCompatibility.Utf8(record.Payload))??"");
            return new IncidentPackageRecord(record.Type,record.Flags,record.Sequence,record.Timestamp,record.WindowId,record.Width,record.Height,record.Provider,record.ResolutionTier,payload);
        }).ToArray();
        var exceptions=Exceptions.Select(exception=>exception with{Type=Redact(exception.Type)??"*",RawStackTrace=Redact(exception.RawStackTrace),Frames=exception.Frames.Select(frame=>frame with{Method=Redact(frame.Method),DeclaringType=Redact(frame.DeclaringType),Assembly=Redact(frame.Assembly),File=Redact(frame.File)}).ToArray()}).ToArray();
        var groupingKey=Redact(GroupingKey);
        // A replacement marker must not become a common explicit identity for unrelated issues.
        if(!string.Equals(groupingKey,GroupingKey,StringComparison.Ordinal))groupingKey=null;
        return new(IncidentId,CreatedUtc,Redact(ApplicationId),Redact(Environment),SessionId,ReportType,Redact(ReportMessage),QpcFrequency,QpcAnchor,UtcAnchorFileTime,StartTicks,EndTicks,records,Redact(SourceRevision),exceptions,Redact(ApplicationVersion),groupingKey,ApplicationLogContext,FreezeTicks,RuntimeContext);
    }
    internal static string? NormalizeApplicationVersion(string? value)=>string.IsNullOrWhiteSpace(value)?null:value;
    public static string? NormalizeGroupingKey(string? value){if(string.IsNullOrWhiteSpace(value))return null;var normalized=value.Trim();if(normalized.Any(char.IsControl)||System.Text.Encoding.UTF8.GetByteCount(normalized)>IncidentPackageLimits.MaximumGroupingKeyBytes)throw new ArgumentException("GroupingKey is invalid.",nameof(value));return normalized;}
}



