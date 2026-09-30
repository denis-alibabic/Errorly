using System.Diagnostics;
using System.Reflection;
using System.Collections.Concurrent;
using System.Reflection.PortableExecutable;

namespace Errorly;

public enum ErrorlyStackFrameClassification : byte { UserCode = 1, ExternalCode = 2 }
public enum ErrorlySourceAvailability : byte { NoSourceInformation = 0, AvailableMetadata = 1, ExternalCode = 2 }

public sealed record ErrorlyStackFrame(int Index,string? Method,string? DeclaringType,string? Assembly,string? File,int? Line,int? Column,ErrorlyStackFrameClassification Classification,ErrorlySourceAvailability SourceAvailability,Guid? ModuleVersionId=null,int? MethodMetadataToken=null,int? ILOffset=null,Guid? PortablePdbId=null);
public sealed record ErrorlyExceptionInfo(string Type,string? RawStackTrace,IReadOnlyList<ErrorlyStackFrame> Frames);

internal static class ExceptionMetadata
{
    private static readonly ConcurrentDictionary<string,Guid?> PortablePdbIds=new(StringComparer.OrdinalIgnoreCase);
    internal static ErrorlyExceptionInfo Capture(Exception exception,IEnumerable<string> userAssemblies)
    {
        var frames=new List<ErrorlyStackFrame>();
        try
        {
            var stack=new StackTrace(exception,true);
            var index=0;
            foreach(var frame in stack.GetFrames()??[])
            {
                var method=frame.GetMethod();
                var type=method?.DeclaringType;
                var assembly=type?.Assembly.GetName().Name;
                Guid? moduleVersionId=null;int? methodMetadataToken=null;int? ilOffset=null;
                Guid? portablePdbId=null;try{if(method is not null){moduleVersionId=method.Module.ModuleVersionId;methodMetadataToken=method.MetadataToken>0?method.MetadataToken:null;portablePdbId=GetPortablePdbId(method.Module);}ilOffset=frame.GetILOffset() is var offset and >=0?offset:null;}catch{}
                var user=assembly is not null&&userAssemblies.Contains(assembly);
                var file=NormalizePath(frame.GetFileName());
                int? line=frame.GetFileLineNumber() is var value and >0?value:null;
                int? column=frame.GetFileColumnNumber() is var columnValue and >0?columnValue:null;
                var hasSource=file is not null||line.HasValue;
                frames.Add(new(index++,method?.ToString(),type?.FullName,assembly,file,line,column,user?ErrorlyStackFrameClassification.UserCode:ErrorlyStackFrameClassification.ExternalCode,user?hasSource?ErrorlySourceAvailability.AvailableMetadata:ErrorlySourceAvailability.NoSourceInformation:ErrorlySourceAvailability.ExternalCode,moduleVersionId,methodMetadataToken,ilOffset,portablePdbId));
                if(frames.Count>=IncidentPackageLimits.MaximumStackFrames)break;
            }
        }
        catch { }
        return new(exception.GetType().FullName??exception.GetType().Name,exception.StackTrace,frames);
    }

    private static Guid? GetPortablePdbId(Module module)
    {
        var path=module.FullyQualifiedName;if(string.IsNullOrWhiteSpace(path)||!File.Exists(path))return null;
        return PortablePdbIds.GetOrAdd(path,static value=>
        {
            try{using var stream=File.OpenRead(value);using var pe=new PEReader(stream);foreach(var entry in pe.ReadDebugDirectory())if(entry.Type==DebugDirectoryEntryType.CodeView)return pe.ReadCodeViewDebugDirectoryData(entry).Guid;}catch{}return null;
        });
    }

    internal static string? NormalizePath(string? path)
    {
        if(string.IsNullOrWhiteSpace(path))return null;
        var value=path.Trim().Replace('\\','/');
        var segments=value.Split(new[]{'/'},StringSplitOptions.RemoveEmptyEntries);
        var sourceIndex=Array.FindIndex(segments,x=>string.Equals(x,"src",StringComparison.OrdinalIgnoreCase));
        if(sourceIndex>=0)return string.Join("/",segments.Skip(sourceIndex));
        return segments.Length==0?null:segments[segments.Length-1];
    }
}


