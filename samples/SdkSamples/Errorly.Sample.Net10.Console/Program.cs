using System.Threading.Tasks;
using Errorly;
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        if (!SampleSetup.Configure(args)) return 2;
        using (var client = ErrorlySdk.Initialize(SampleSetup.Options("Errorly.Sample.Net10.Console", ErrorlyApplicationKind.Console)))
        {
            SampleSetup.Initialized(client);
            var labResult = await SampleSetup.RunLabChild(client);
            if (labResult.HasValue) return labResult.Value;
            if (SampleSetup.IsSmoke(args)) { SampleSetup.PrintSmoke(client); return 0; }
            if (SampleSetup.Verification) { SampleSetup.PrintReady(); return await SampleSetup.Verify(client); }
            await SampleSetup.RunConsole(client);
            return 0;
        }
    }
}
