using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Runtime.CompilerServices;
using Errorly.SdkLab.Contracts;

internal static class SourceSymbolsProbe
{
    internal const string SourcePath = "samples/SdkSamples/Errorly.Sample.Net10.Console/SourceSymbolsProbe.cs";
    internal const int ThrowLine = 17;

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    internal static void ThrowKnownException()
    {
        throw new InvalidOperationException("Controlled SDK Lab source and symbols probe");
    }

    internal static SdkLabSourceSymbolFacts Describe(Exception error)
    {
        var frame = new System.Diagnostics.StackTrace(error, false).GetFrames()?.FirstOrDefault(value => value.GetMethod()?.DeclaringType == typeof(SourceSymbolsProbe));
        var method = frame?.GetMethod() ?? typeof(SourceSymbolsProbe).GetMethod(nameof(ThrowKnownException), BindingFlags.Static | BindingFlags.NonPublic)!;
        return new SdkLabSourceSymbolFacts
        {
            ModuleName = method.Module.Name,
            ModuleVersionId = method.Module.ModuleVersionId.ToString("D"),
            PortablePdbId = ReadPortablePdbIdentity(method.Module.FullyQualifiedName)?.Guid.ToString("D"),
            PortablePdbAge = ReadPortablePdbIdentity(method.Module.FullyQualifiedName)?.Age ?? 0,
            PortablePdbStamp = ReadPortablePdbIdentity(method.Module.FullyQualifiedName)?.Stamp ?? 0,
            MethodMetadataToken = method.MetadataToken,
            IlOffset = frame?.GetILOffset() ?? -1,
            ExpectedSourcePath = SourcePath,
            ExpectedSourceLine = ThrowLine
        };
    }

    private static (Guid Guid, int Age, uint Stamp)? ReadPortablePdbIdentity(string assemblyPath)
    {
        try
        {
            using var stream = File.OpenRead(assemblyPath);
            using var pe = new PEReader(stream);
            foreach (var entry in pe.ReadDebugDirectory())
                if (entry.Type == DebugDirectoryEntryType.CodeView)
                {
                    var identity = pe.ReadCodeViewDebugDirectoryData(entry);
                    return (identity.Guid, identity.Age, entry.Stamp);
                }
        }
        catch { }
        return null;
    }
}
