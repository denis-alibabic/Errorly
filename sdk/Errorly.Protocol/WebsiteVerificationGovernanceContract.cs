using System.Security.Cryptography;
using System.Text;

namespace Errorly;

/// <summary>Exact SDK identity used for release-policy lookup, rather than the host project's TFM.</summary>
public sealed record WebsiteVerificationTargetIdentity(string TargetId,string PackageName,string Version,string TargetFramework,string ApplicationKind);

public sealed record WebsiteVerificationGovernanceRule(string ScenarioId,string RequiredPolicy,string? MinimumSafeVersion,string Mode,string ExpectedOutcome,bool ExpectedIncident,string MutationOperation,string RollbackOperation,string ExcludedMode,string ExclusionReason);

/// <summary>The governance portion of an immutable full-run plan, including its declared operations.</summary>
public sealed record WebsiteVerificationGovernancePlanItem(string ScenarioId,string? TargetId,string Mode,string ExpectedOutcome,string? PackageName,string? Version,string? TargetFramework,string? ApplicationKind,string? RequiredPolicy=null,string? MinimumSafeVersion=null,string? MutationOperation=null,string? RollbackOperation=null);

/// <summary>
/// Shared by the Lab compiler and API. Adding a scenario requires an explicit rule;
/// scenario prefixes never imply a policy, execution lane, or rollback operation.
/// </summary>
public static class WebsiteVerificationGovernanceContract
{
    public const string ContractVersion="15";
    // Revision identifies the approved governance semantics, independently of the
    // website verification protocol. A revision is never reused for changed bytes.
    // Runtime property prevents a consumer assembly from inlining a revision from
    // a different Protocol build than the one supplying validation and hash bytes.
    public static string ManifestRevision { get; }="1";
    public const string WebsiteSafe="WebsiteSafeRealService";
    public const string ControlledLocal="LocalFaultProxyControlledServer";
    public const string PackageVersion="0.1.0-beta.1";

    public static IReadOnlyList<WebsiteVerificationTargetIdentity> Targets { get; }=Array.AsReadOnly(new[]
    {
        new WebsiteVerificationTargetIdentity("net48-console","Errorly.Sdk",PackageVersion,"net462","Console"),
        new WebsiteVerificationTargetIdentity("net48-wpf","Errorly.Wpf",PackageVersion,"net462","WPF"),
        new WebsiteVerificationTargetIdentity("net48-winforms","Errorly.WinForms",PackageVersion,"net462","WinForms"),
        new WebsiteVerificationTargetIdentity("net6-console","Errorly.Sdk",PackageVersion,"net6.0","Console"),
        new WebsiteVerificationTargetIdentity("net6-webapi","Errorly.AspNetCore",PackageVersion,"net6.0","ASP.NET Core"),
        new WebsiteVerificationTargetIdentity("net6-worker","Errorly.Extensions.Logging",PackageVersion,"net6.0","Worker Service"),
        new WebsiteVerificationTargetIdentity("net10-console","Errorly.Sdk",PackageVersion,"net10.0","Console"),
        new WebsiteVerificationTargetIdentity("net10-webapi","Errorly.AspNetCore",PackageVersion,"net10.0","ASP.NET Core"),
        new WebsiteVerificationTargetIdentity("net10-worker","Errorly.Extensions.Logging",PackageVersion,"net10.0","Worker Service")
    });

    public static IReadOnlyList<WebsiteVerificationGovernanceRule> Rules { get; }=Array.AsReadOnly(new[]
    {
        new WebsiteVerificationGovernanceRule("governance.supported","Supported",null,WebsiteSafe,"WebsiteOccurrence",true,"SetApplicationGovernanceOverride","RemoveSuiteApplicationGovernanceOverride",ControlledLocal,"VerifyAuthorizedApplicationProjection"),
        new WebsiteVerificationGovernanceRule("governance.deprecated","Deprecated",null,WebsiteSafe,"WebsiteOccurrence",true,"SetApplicationGovernanceOverride","RemoveSuiteApplicationGovernanceOverride",ControlledLocal,"VerifyAuthorizedApplicationProjection"),
        new WebsiteVerificationGovernanceRule("governance.minimum-safe","Deprecated","999.0.0",WebsiteSafe,"WebsiteOccurrence",true,"SetApplicationGovernanceOverride","RemoveSuiteApplicationGovernanceOverride",ControlledLocal,"VerifyAuthorizedApplicationProjection"),
        new WebsiteVerificationGovernanceRule("governance.blocked","Blocked",null,ControlledLocal,"LocalTerminalRejection",false,"ConfigureControlledGovernancePolicy","ResetControlledGovernanceAndDisposeFixture",WebsiteSafe,"RequiresControlledTerminalPolicy"),
        new WebsiteVerificationGovernanceRule("governance.terminal-quarantine","Blocked",null,ControlledLocal,"LocalQuarantine",false,"ConfigureControlledGovernancePolicy","ResetControlledGovernanceAndDisposeFixture",WebsiteSafe,"RequiresControlledTerminalPolicy"),
        new WebsiteVerificationGovernanceRule("governance.no-retry-storm","Blocked",null,ControlledLocal,"LocalTerminalRejection",false,"ConfigureControlledGovernancePolicy","ResetControlledGovernanceAndDisposeFixture",WebsiteSafe,"RequiresControlledTerminalPolicy"),
        new WebsiteVerificationGovernanceRule("governance.cached-block-restart","Blocked",null,ControlledLocal,"LocalTerminalRejection",false,"SeedBlockedCacheRestartWithPolicyStoreFailure","ResetControlledGovernanceAndDisposeFixture",WebsiteSafe,"RequiresControlledCacheAndPolicyStore"),
        new WebsiteVerificationGovernanceRule("governance.store-failure-known-blocked","Blocked",null,ControlledLocal,"LocalTerminalRejection",false,"SeedBlockedCacheRestartWithPolicyStoreFailure","ResetControlledGovernanceAndDisposeFixture",WebsiteSafe,"RequiresControlledCacheAndPolicyStore"),
        new WebsiteVerificationGovernanceRule("governance.cache-binding","Blocked",null,ControlledLocal,"LocalPass",false,"SeedBlockedCacheRotateKeyWithPolicyStoreFailure","ResetControlledGovernanceAndDisposeFixture",WebsiteSafe,"RequiresControlledCacheAndPolicyStore"),
        new WebsiteVerificationGovernanceRule("governance.cache-expiry","Blocked",null,ControlledLocal,"LocalPass",false,"SeedBlockedCacheExpireThenSetSupported","ResetControlledGovernanceAndDisposeFixture",WebsiteSafe,"RequiresControlledCacheAndPolicyStore"),
        new WebsiteVerificationGovernanceRule("governance.legacy-fail-open","UnknownLegacy",null,ControlledLocal,"LocalPass",false,"RotateControlledKeyAndFailPolicyStore","ResetControlledGovernanceAndDisposeFixture",WebsiteSafe,"RequiresControlledLegacyPolicyFailure")
    });

    public static IReadOnlyList<WebsiteVerificationGovernancePlanItem> Entries { get; }=Array.AsReadOnly(ExpandEntries(Targets,Rules));

    // Canonical ordering is ordinal and independent of catalog enumeration order and culture.
    public static string CanonicalManifest { get; }=CanonicalizeManifest(Targets,Rules);
    public static string ManifestHash { get; }=RequireApprovedManifestHash();

    public static WebsiteVerificationGovernanceRule? FindRule(string? scenarioId)=>Rules.FirstOrDefault(value=>value.ScenarioId==scenarioId);
    public static WebsiteVerificationTargetIdentity? FindTarget(string? targetId)=>Targets.FirstOrDefault(value=>value.TargetId==targetId);

    public static string? ValidateManifest(string? version,string? hash)
    {
        if(version!=ManifestRevision)return "PreflightGovernanceManifestVersionMismatch";
        return string.Equals(hash,ManifestHash,StringComparison.Ordinal)?null:"PreflightGovernanceManifestHashMismatch";
    }

    /// <summary>Binds the exact ordered child plan and its governance contract into the lease.</summary>
    public static string CalculatePlanHash(IEnumerable<WebsiteVerificationGovernancePlanItem> plan,string? manifestVersion,string? manifestHash)
    {
        var lines=new List<string>{"Errorly.FullWebsiteVerification.Plan|"+ContractVersion,"governance|"+(manifestVersion??"-")+"|"+(manifestHash??"-")};
        lines.AddRange(plan.Select(value=>string.Join("|",value.Mode,value.ScenarioId,value.TargetId??"-",value.ExpectedOutcome,value.PackageName??"-",value.Version??"-",value.TargetFramework??"-",value.ApplicationKind??"-",value.RequiredPolicy??"-",value.MinimumSafeVersion??"-",value.MutationOperation??"-",value.RollbackOperation??"-")));
        return Hash(string.Join("\n",lines));
    }

    public static string? ValidatePlan(IEnumerable<WebsiteVerificationGovernancePlanItem> plan)
    {
        var supplied=plan.ToArray();
        foreach(var expected in Entries.OrderBy(value=>value.ScenarioId,StringComparer.Ordinal).ThenBy(value=>value.TargetId,StringComparer.Ordinal))
        {
            var candidates=supplied.Where(value=>value.ScenarioId==expected.ScenarioId&&value.TargetId==expected.TargetId).ToArray();
            if(candidates.Length==0)return Detail("PreflightGovernancePlanIncomplete",expected);
            if(candidates.Length!=1)return Detail("PreflightGovernancePlanDuplicate",expected);
            var actual=candidates[0];
            if(actual.PackageName!=expected.PackageName||actual.Version!=expected.Version||actual.TargetFramework!=expected.TargetFramework||actual.ApplicationKind!=expected.ApplicationKind)return Detail("PreflightGovernanceIdentityMismatch",expected);
            if(actual.Mode!=expected.Mode)return Detail("PreflightGovernanceLaneMismatch",expected);
            if(actual.RequiredPolicy!=expected.RequiredPolicy||actual.MinimumSafeVersion!=expected.MinimumSafeVersion)return Detail("PreflightGovernancePolicyMismatch",expected);
            if(actual.ExpectedOutcome!=expected.ExpectedOutcome)return Detail("PreflightGovernanceOutcomeMismatch",expected);
            if(actual.MutationOperation!=expected.MutationOperation)return Detail("PreflightGovernanceMutationMismatch",expected);
            if(actual.RollbackOperation!=expected.RollbackOperation)return Detail("PreflightGovernanceRollbackMismatch",expected);
        }
        // Prefix detection only rejects unknown entries; it never derives a required mapping.
        foreach(var actual in supplied)
        {
            if(FindRule(actual.ScenarioId) is not null)
            {
                if(FindTarget(actual.TargetId) is null)return "PreflightGovernanceUnexpectedTarget";
            }
            else if(actual.ScenarioId?.StartsWith("governance.",StringComparison.Ordinal)==true||actual.RequiredPolicy is not null||actual.MinimumSafeVersion is not null||actual.MutationOperation is not null||actual.RollbackOperation is not null)return "PreflightGovernanceUnexpectedEntry";
        }
        return null;
    }

    public static bool IsSafeDiagnostic(string? value)
    {
        if(value is "PreflightGovernanceManifestVersionMismatch" or "PreflightGovernanceManifestHashMismatch" or "PreflightGovernanceUnexpectedTarget" or "PreflightGovernanceUnexpectedEntry")return true;
        if(value is null)return false;
        var parts=value.Split('/');
        if(parts.Length!=4)return false;
        if(parts[0] is not("PreflightGovernancePlanIncomplete" or "PreflightGovernancePlanDuplicate" or "PreflightGovernanceIdentityMismatch" or "PreflightGovernanceLaneMismatch" or "PreflightGovernancePolicyMismatch" or "PreflightGovernanceOutcomeMismatch" or "PreflightGovernanceMutationMismatch" or "PreflightGovernanceRollbackMismatch"))return false;
        var rule=FindRule(parts[1]);return rule is not null&&FindTarget(parts[2]) is not null&&parts[3]==rule.RequiredPolicy;
    }

    static string Detail(string code,WebsiteVerificationGovernancePlanItem expected)=>code+"/"+expected.ScenarioId+"/"+expected.TargetId+"/"+expected.RequiredPolicy;
    /// <summary>
    /// Canonical semantic content: ordinal, case-sensitive identifiers, LF separators,
    /// and no trailing newline. SHA-256 consumes its UTF-8 bytes without a BOM.
    /// Inputs may be in any order. Tuples are expanded here from these exact inputs.
    /// No file paths, timestamps, culture-dependent formatting or build data participate.
    /// The format header is protocol 15; approval revision is a separate pinned mapping.
    /// </summary>
    public static string CanonicalizeManifest(IEnumerable<WebsiteVerificationTargetIdentity> targets,IEnumerable<WebsiteVerificationGovernanceRule> rules)
    {
        var targetArray=targets.ToArray();var ruleArray=rules.ToArray();
        if(targetArray.Select(value=>value.TargetId).Distinct(StringComparer.Ordinal).Count()!=targetArray.Length||ruleArray.Select(value=>value.ScenarioId).Distinct(StringComparer.Ordinal).Count()!=ruleArray.Length)throw new ArgumentException("GovernanceManifestDuplicateIdentifier");
        var lines=new List<string>{"Errorly.FullWebsiteVerification.Governance|"+ContractVersion};
        lines.AddRange(targetArray.OrderBy(value=>value.TargetId,StringComparer.Ordinal).Select(value=>"target|"+CanonicalFields(value.TargetId,value.PackageName,value.Version,value.TargetFramework,value.ApplicationKind)));
        lines.AddRange(ruleArray.OrderBy(value=>value.ScenarioId,StringComparer.Ordinal).Select(value=>"rule|"+CanonicalFields(value.ScenarioId,value.RequiredPolicy,value.MinimumSafeVersion??"-",value.Mode,value.ExpectedOutcome,value.ExpectedIncident?"1":"0",value.MutationOperation,value.RollbackOperation,value.ExcludedMode,value.ExclusionReason)));
        lines.AddRange(ExpandEntries(targetArray,ruleArray).OrderBy(value=>value.ScenarioId,StringComparer.Ordinal).ThenBy(value=>value.TargetId,StringComparer.Ordinal).Select(value=>"tuple|"+CanonicalFields(value.ScenarioId,value.TargetId!,value.Mode,value.ExpectedOutcome,value.PackageName!,value.Version!,value.TargetFramework!,value.ApplicationKind!,value.RequiredPolicy!,value.MinimumSafeVersion??"-",value.MutationOperation!,value.RollbackOperation!)));
        return string.Join("\n",lines);
    }

    public static string CalculateManifestHash(IEnumerable<WebsiteVerificationTargetIdentity> targets,IEnumerable<WebsiteVerificationGovernanceRule> rules)=>Hash(CanonicalizeManifest(targets,rules));

    /// <summary>Rejects semantic changes unless an explicit new revision has an approved hash.</summary>
    public static string? ValidateManifestRevision(string? revision,IEnumerable<WebsiteVerificationTargetIdentity> targets,IEnumerable<WebsiteVerificationGovernanceRule> rules)
    {
        var approved=ApprovedManifestHash(revision);
        if(approved is null)return "GovernanceManifestRevisionUnknown";
        return string.Equals(approved,CalculateManifestHash(targets,rules),StringComparison.Ordinal)?null:"GovernanceManifestRevisionContentMismatch";
    }

    // Append a new revision and its reviewed canonical hash when semantics change.
    // Keep existing revision/hash pairs immutable; do not replace revision 1's hash.
    static string? ApprovedManifestHash(string? revision)=>revision switch
    {
        "1"=>"F86FA92E353AC46054B2C065C112C122DEE54FB2EF493749A0301F46D24D72BB",
        _=>null
    };

    static string RequireApprovedManifestHash()
    {
        var rejection=ValidateManifestRevision(ManifestRevision,Targets,Rules);
        if(rejection is not null)throw new InvalidOperationException(rejection);
        return Hash(CanonicalManifest);
    }

    static WebsiteVerificationGovernancePlanItem[] ExpandEntries(IEnumerable<WebsiteVerificationTargetIdentity> targets,IEnumerable<WebsiteVerificationGovernanceRule> rules)=>rules.SelectMany(rule=>targets.Select(target=>new WebsiteVerificationGovernancePlanItem(rule.ScenarioId,target.TargetId,rule.Mode,rule.ExpectedOutcome,target.PackageName,target.Version,target.TargetFramework,target.ApplicationKind,rule.RequiredPolicy,rule.MinimumSafeVersion,rule.MutationOperation,rule.RollbackOperation))).ToArray();

    static string CanonicalFields(params string[] values)
    {
        if(values.Any(value=>string.IsNullOrEmpty(value)||value.IndexOfAny(new[]{'|','\r','\n'})>=0))throw new ArgumentException("GovernanceManifestCanonicalFieldInvalid");
        return string.Join("|",values);
    }
    static string Hash(string value)
    {
        using var sha=SHA256.Create();return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(value))).Replace("-",string.Empty);
    }
}
