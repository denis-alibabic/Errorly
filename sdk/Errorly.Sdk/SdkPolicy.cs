using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;

namespace Errorly;

internal sealed class SdkPolicy
{
    internal bool Enabled=true,CaptureIpAddress=false,CaptureUserIdentity=false,CaptureUserEmail=false;
    internal int EntryCap=100,ByteCap=64*1024,RateLimit=100;
    internal IncidentLogLevel MinimumLevel=IncidentLogLevel.Information;
    internal DateTimeOffset ExpiresUtc;
    internal Regex[] Patterns=Array.Empty<Regex>();
    internal string? DefaultEnvironment;internal KeyValuePair<string,string>[] IgnoreRules=Array.Empty<KeyValuePair<string,string>>();
    internal static SdkPolicy Parse(string json)
    {
        using var document=JsonDocument.Parse(json);var root=document.RootElement;var result=new SdkPolicy();
        bool Bool(string name,bool fallback)=>root.TryGetProperty(name,out var p)?p.GetBoolean():fallback;
        int Number(string name,int fallback,int max){var v=root.TryGetProperty(name,out var p)?p.GetInt32():fallback;if(v<1||v>max)throw new InvalidDataException("Invalid policy bounds.");return v;}
        result.Enabled=Bool("enabled",true);result.CaptureIpAddress=Bool("captureIpAddress",false);result.CaptureUserIdentity=Bool("captureUserIdentity",false);result.CaptureUserEmail=Bool("captureUserEmail",false);
        result.EntryCap=Number("entryCap",100,IncidentPackageLimits.MaximumLogEntries);result.ByteCap=Number("byteCap",65536,IncidentPackageLimits.MaximumLogContextBytes);result.RateLimit=Number("rateLimitPerSecond",100,100000);
        if(root.TryGetProperty("minimumLevel",out var level))result.MinimumLevel=level.ValueKind==JsonValueKind.String?(IncidentLogLevel)Enum.Parse(typeof(IncidentLogLevel),level.GetString()!,true):(IncidentLogLevel)level.GetInt32();
        if(!Enum.IsDefined(typeof(IncidentLogLevel),result.MinimumLevel))throw new InvalidDataException("Invalid policy level.");
        result.ExpiresUtc=root.GetProperty("expiresUtc").GetDateTimeOffset();if(result.ExpiresUtc<=DateTimeOffset.UtcNow)throw new InvalidDataException("Expired policy.");
        if(root.TryGetProperty("redactionPatterns",out var patterns)&&patterns.ValueKind==JsonValueKind.Array){if(patterns.GetArrayLength()>40)throw new InvalidDataException("Invalid policy patterns.");result.Patterns=patterns.EnumerateArray().Select(p=>{var value=p.GetString()!;if(string.IsNullOrWhiteSpace(value)||value.Length>256)throw new InvalidDataException("Invalid policy pattern.");return new Regex(value,RegexOptions.CultureInvariant,TimeSpan.FromMilliseconds(5));}).ToArray();}
        if(root.TryGetProperty("defaultEnvironment",out var environment)&&environment.ValueKind==JsonValueKind.String){var value=environment.GetString();if(value is not null&&(Encoding.UTF8.GetByteCount(value)>128||value.Any(char.IsControl)))throw new InvalidDataException("Invalid default environment.");result.DefaultEnvironment=value;}
        if(root.TryGetProperty("ignoreRules",out var rules)&&rules.ValueKind==JsonValueKind.Array)
        {
            if(rules.GetArrayLength()>100)throw new InvalidDataException("Invalid ignore rules.");
            result.IgnoreRules=rules.EnumerateArray().Select(rule=>{var type=rule.GetProperty("type").GetString()!;var value=rule.GetProperty("value").GetString()!;if(type is not "ExceptionType" and not "MessageContains" and not "RequestPathPrefix"||string.IsNullOrEmpty(value)||value.Length>256)throw new InvalidDataException("Invalid ignore rule.");return new KeyValuePair<string,string>(type,value);}).ToArray();
        }
        return result;
    }
    internal bool Keep(string name)
    {
        if(name.StartsWith("tag.",StringComparison.Ordinal))name=name.Substring(4);var key=name.Replace("_","").Replace(".","").Replace("-","").ToLowerInvariant();
        if(key.Contains("password")||key.Contains("token")||key.Contains("apikey")||key.Contains("authorization")||key.Contains("connectionstring")||key.Contains("cookie"))return false;
        return key switch { "ip" or "ipaddress" or "clientip" or "remoteip" or "remoteipaddress"=>CaptureIpAddress,"userid" or "useridentifier" or "username"=>CaptureUserIdentity,"email" or "useremail" or "emailaddress"=>CaptureUserEmail,_=>true };
    }
    internal string? Redact(string? value,IEnumerable<string>? privateValues=null)
    {
        if(value is null)return null;
        try{value=Limit(value,2048);var timer=System.Diagnostics.Stopwatch.StartNew();value=IncidentLogSanitizer.RedactText(value);if(privateValues is not null)foreach(var hidden in privateValues.Where(v=>!string.IsNullOrEmpty(v)).Take(128))value=value!.Replace(hidden,"[REDACTED]");foreach(var pattern in Patterns){if(timer.ElapsedMilliseconds>=5)return "[REDACTED]";value=pattern.Replace(value!,"[REDACTED]");}return Limit(value!,2048);}catch{return "[REDACTED]";}
    }
    internal static string Limit(string value,int bytes){if(value.Length>bytes)value=value.Substring(0,bytes);while(Encoding.UTF8.GetByteCount(value)>bytes)value=value.Substring(0,value.Length-1);return value;}
}



