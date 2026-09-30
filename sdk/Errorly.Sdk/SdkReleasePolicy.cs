using System.Text.Json;

namespace Errorly;

public enum SdkReleaseState { Deprecated, Blocked }

/// <summary>Safe, non-secret release guidance returned by Errorly.</summary>
public sealed class SdkReleaseAdvisory
{
    internal SdkReleaseAdvisory(SdkReleaseState state,string packageName,string installedVersion,string? minimumSafeVersion,string? reasonCategory,string message,string? documentationUrl)
    {State=state;PackageName=packageName;InstalledVersion=installedVersion;MinimumSafeVersion=minimumSafeVersion;ReasonCategory=reasonCategory;Message=message;DocumentationUrl=documentationUrl;}
    public SdkReleaseState State {get;}
    public string PackageName {get;}
    public string InstalledVersion {get;}
    public string? MinimumSafeVersion {get;}
    public string? ReasonCategory {get;}
    public string Message {get;}
    public string? DocumentationUrl {get;}
}

public enum ErrorlyDiagnosticCode { SdkDeprecated, SdkBlocked }

/// <summary>A bounded local operational diagnostic. It never includes incident data, credentials, or endpoints.</summary>
public sealed class ErrorlyDiagnostic
{
    internal ErrorlyDiagnostic(ErrorlyDiagnosticCode code,SdkReleaseAdvisory advisory){Code=code;Advisory=advisory;}
    public ErrorlyDiagnosticCode Code {get;}
    public SdkReleaseAdvisory Advisory {get;}
}

internal static class SdkReleasePolicyParser
{
    internal static SdkReleaseAdvisory? ParseAccepted(string json)
    {
        try{using var document=JsonDocument.Parse(json);var root=document.RootElement;if(root.TryGetProperty("advisory",out var advisory)&&advisory.ValueKind==JsonValueKind.Object)return Parse(advisory,false);return null;}catch{return null;}
        // An older or malformed advisory never changes successful receipt handling.
    }

    internal static SdkReleaseAdvisory? ParseBlocked(string json)
    {
        try{using var document=JsonDocument.Parse(json);var root=document.RootElement;if(root.TryGetProperty("advisory",out var advisory)&&advisory.ValueKind==JsonValueKind.Object)root=advisory;return Parse(root,true);}catch{return null;}
    }

    internal static SdkReleaseAdvisory? ParseCachedBlocked(string json)
    {
        try
        {
            using var document=JsonDocument.Parse(json);var root=document.RootElement;
            if(!Text(root,"code",32,true,out var code)||code!="sdk_blocked"||!Text(root,"packageName",64,true,out var package)||!OfficialPackage(package!)||!Text(root,"installedVersion",64,true,out var installed)||!SemanticVersion.IsValid(installed!))return null;
            if(Text(root,"minimumSafeVersion",64,false,out var minimum)&&minimum is not null&&!SemanticVersion.IsValid(minimum))return null;
            if(!Text(root,"reasonCategory",64,true,out var reason)||!SafeToken(reason!))return null;
            if(!root.TryGetProperty("terminal",out var terminal)||terminal.ValueKind!=JsonValueKind.True)return null;
            return new SdkReleaseAdvisory(SdkReleaseState.Blocked,package!,installed!,minimum,reason,"Errorly telemetry from this SDK version is not accepted. Update the package and redeploy your application.",null);
        }catch{return null;}
    }

    private static SdkReleaseAdvisory? Parse(JsonElement root,bool requireBlocked)
    {
        var expected=requireBlocked?"sdk_blocked":"sdk_deprecated";
        if(!Text(root,"code",32,true,out var code)||code!=expected)return null;
        if(!Text(root,"packageName",64,true,out var package)||!OfficialPackage(package!))return null;
        if(!Text(root,"installedVersion",64,true,out var installed)||!SemanticVersion.IsValid(installed!))return null;
        if(Text(root,"minimumSafeVersion",64,false,out var minimum)&&minimum is not null&&!SemanticVersion.IsValid(minimum))return null;
        if(!Text(root,"message",256,true,out var message))return null;
        if(!Text(root,"reasonCategory",64,requireBlocked,out var reason)||reason is not null&&!SafeToken(reason))return null;
        if(!Text(root,"documentationUrl",512,false,out var documentation)||documentation is not null&&!SafeDocumentationUrl(documentation))return null;
        if(requireBlocked&&root.TryGetProperty("terminal",out var terminal)&&(terminal.ValueKind!=JsonValueKind.True&&terminal.ValueKind!=JsonValueKind.False||!terminal.GetBoolean()))return null;
        return new SdkReleaseAdvisory(requireBlocked?SdkReleaseState.Blocked:SdkReleaseState.Deprecated,package!,installed!,minimum,reason,message!,documentation);
    }

    private static bool Text(JsonElement root,string name,int max,bool required,out string? value)
    {
        value=null;if(!root.TryGetProperty(name,out var property)||property.ValueKind==JsonValueKind.Null)return !required;
        if(property.ValueKind!=JsonValueKind.String)return false;value=property.GetString();
        return value is not null&&!string.IsNullOrWhiteSpace(value)&&value.Length<=max&&!value.Any(char.IsControl);
    }
    private static bool OfficialPackage(string value)=>value is "Errorly.Sdk" or "Errorly.Wpf" or "Errorly.WinForms" or "Errorly.AspNetCore" or "Errorly.Extensions.Logging" or "Errorly.DotNet";
    private static bool SafeToken(string value)=>value.All(c=>c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c is '_' or '-');
    private static bool SafeDocumentationUrl(string value)=>Uri.TryCreate(value,UriKind.Absolute,out var uri)&&uri.Scheme==Uri.UriSchemeHttps&&!string.IsNullOrEmpty(uri.Host)&&string.IsNullOrEmpty(uri.UserInfo);
}

internal static class SemanticVersion
{
    internal static bool IsValid(string value)
    {
        if(string.IsNullOrEmpty(value)||value.Length>64)return false;var build=value.IndexOf('+');var core=build<0?value:value.Substring(0,build);
        if(build>=0&&!Identifiers(value.Substring(build+1),false))return false;var dash=core.IndexOf('-');var pre=dash<0?null:core.Substring(dash+1);core=dash<0?core:core.Substring(0,dash);
        var parts=core.Split('.');return parts.Length==3&&parts.All(Number)&&((pre is null)||Identifiers(pre,true));
    }
    private static bool Number(string value)=>value.Length>0&&(value.Length==1||value[0]!='0')&&value.All(c=>c>='0'&&c<='9');
    private static bool Identifiers(string value,bool rejectNumericLeadingZero)=>value.Length>0&&value.Split('.').All(part=>part.Length>0&&part.All(c=>c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c=='-')&&(!rejectNumericLeadingZero||!part.All(c=>c>='0'&&c<='9')||Number(part)));
}
