using System.Reflection;

namespace Errorly;

internal static class RuntimeDetection
{
    internal static IncidentRuntimeContext Detect(SdkOptions options)
    {
        var entry=Assembly.GetEntryAssembly();
        var kind=options.ApplicationKind;
        if(true)
        {
            // Assembly references distinguish desktop frameworks without loading them into core hosts.
            var references=entry?.GetReferencedAssemblies().Select(a=>a.Name).ToArray()??Array.Empty<string>();
            if(references.Any(n=>n=="PresentationFramework"))kind=ErrorlyApplicationKind.Wpf;else if(references.Any(n=>n=="System.Windows.Forms"))kind=ErrorlyApplicationKind.WinForms;else if(kind==ErrorlyApplicationKind.Unknown&&references.Any(n=>n=="System.Console"))kind=ErrorlyApplicationKind.Console;
        }
#if NETFRAMEWORK
        var family=".NET Framework";var description=".NET Framework "+FrameworkVersion();
        var runtimeVersion=FrameworkVersion();var os="Windows";
        var osArch=Environment.Is64BitOperatingSystem?"X64":"X86";var processArch=Environment.Is64BitProcess?"X64":"X86";
#else
        var family=".NET";var description=System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription;
        var runtimeVersion=Environment.Version.ToString();var os=System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)?"Windows":System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Linux)?"Linux":System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.OSX)?"macOS":"Unknown";
        var osArch=System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString();var processArch=System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture.ToString();
#endif
        var identity=PackageIdentity(typeof(ErrorlySdkClient).Assembly);
        return new(1,identity.Name,identity.Version,family,identity.TargetFramework,runtimeVersion,Safe(description),os,Safe(Environment.OSVersion.Version.ToString()),osArch,processArch,Name(kind),Safe(options.ApplicationName??entry?.GetName().Name),Safe(options.Environment),Safe(options.Release),null);
    }
    internal static (string Name,string Version,string TargetFramework) PackageIdentity(Assembly assembly)
    {
        var metadata=assembly.GetCustomAttributes<AssemblyMetadataAttribute>().ToArray();
        var name=metadata.FirstOrDefault(a=>a.Key=="PackageId")?.Value;var version=metadata.FirstOrDefault(a=>a.Key=="PackageVersion")?.Value;var target=metadata.FirstOrDefault(a=>a.Key=="TargetFramework")?.Value;
        if(name is null||version is null||target is null||!SemanticVersion.IsValid(version)||!ValidTargetFramework(target))throw new InvalidOperationException("SDK package identity is unavailable.");
        return (name,version,target);
    }
    private static bool ValidTargetFramework(string value)=>value.Length is >0 and <=64&&value.All(c=>c>='a'&&c<='z'||c>='A'&&c<='Z'||c>='0'&&c<='9'||c is '.' or '-');
    internal static string Name(ErrorlyApplicationKind kind)=>kind switch { ErrorlyApplicationKind.Wpf=>"WPF",ErrorlyApplicationKind.WinForms=>"WinForms",ErrorlyApplicationKind.AspNetCore=>"ASP.NET Core",ErrorlyApplicationKind.WorkerService=>"Worker Service",ErrorlyApplicationKind.Console=>"Console",_=>"Unknown" };
    internal static string? Safe(string? text)=>string.IsNullOrWhiteSpace(text)?null:text!.Length>128||text.Any(c=>c>127||!char.IsLetterOrDigit(c)&&c is not ' ' and not '.' and not '_' and not '+' and not '(' and not ')' and not '-')?null:text;
#if NETFRAMEWORK
    private static string FrameworkVersion()
    {
        try { using(var key=Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full")) { var value=Convert.ToInt32(key?.GetValue("Release")??0);return value>=533320?"4.8.1":value>=528040?"4.8":value>=461808?"4.7.2":value>=461308?"4.7.1":value>=460798?"4.7":value>=394802?"4.6.2":Environment.Version.ToString(); } }catch{return Environment.Version.ToString();}
    }
#endif
}




