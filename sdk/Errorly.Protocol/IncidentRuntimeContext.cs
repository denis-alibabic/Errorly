namespace Errorly;

/// <summary>Versioned runtime facts, independent of user tags and issue identity.</summary>
public sealed record IncidentRuntimeContext(int SchemaVersion=1,string? SdkName=null,string? SdkVersion=null,string? RuntimeFamily=null,string? TargetFramework=null,string? RuntimeVersion=null,string? FrameworkDescription=null,string? OsFamily=null,string? OsVersion=null,string? OsArchitecture=null,string? ProcessArchitecture=null,string? ApplicationKind=null,string? ApplicationName=null,string? Environment=null,string? Release=null,string? HostingModel=null)
{
    internal string?[] Values=>new[]{SdkName,SdkVersion,RuntimeFamily,TargetFramework,RuntimeVersion,FrameworkDescription,OsFamily,OsVersion,OsArchitecture,ProcessArchitecture,ApplicationKind,ApplicationName,Environment,Release,HostingModel};
}
