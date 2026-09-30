# Errorly Source & Symbols probe

This repository contains only the source and project dependencies needed to build the dedicated Errorly SDK Lab Source & Symbols probe.

Build the `samples/SdkSamples/Errorly.Sample.Net10.Console/Errorly.Sample.Net10.Console.csproj` project in Release. In SDK Lab, choose **Choose built DLL** and select the resulting `Errorly.Sample.Net10.Console.dll` under `bin/Release/net10.0`.

SDK Lab validates the matching Portable PDB, module MVID, embedded Git revision, controlled probe file/line, runtime configuration, and dependency manifest before executing it. Commit source changes before building so the embedded revision exists in this repository.

