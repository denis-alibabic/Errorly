using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace Errorly.SdkLab.Contracts;

public sealed class SdkLabExternalReceiptAssessment
{
    public bool Accepted { get; }
    public bool Retryable { get; }
    public string DiagnosticCode { get; }
    public string? RejectionCode { get; }
    public int? HttpStatusCode { get; }
    public string? HttpStatusFamily { get; }
    public SdkLabExternalReceiptAssessment(bool accepted,bool retryable,string diagnosticCode,string? rejectionCode=null,int? httpStatusCode=null){Accepted=accepted;Retryable=retryable;DiagnosticCode=diagnosticCode;RejectionCode=rejectionCode;HttpStatusCode=httpStatusCode;HttpStatusFamily=httpStatusCode is { } status?$"{status/100}xx":null;}
}

public static class SdkLabSafeRejectionCodes
{
    public const string InvalidOrRevokedKey="InvalidOrRevokedKey";
    public const string KeyApplicationMismatch="KeyApplicationMismatch";
    public const string UnsupportedServerProtocol="UnsupportedServerProtocol";
    public const string SdkIdentityRejected="SdkIdentityRejected";
    public const string PayloadValidationRejected="PayloadValidationRejected";
    public const string RateLimited="RateLimited";
    public const string EndpointUnavailable="EndpointUnavailable";
    public const string UnknownSafeRejection="UnknownSafeRejection";
    public static string FromResponse(int statusCode,byte[] body)=>statusCode switch
    {
        401=>InvalidOrRevokedKey,
        404 or 405 or 415=>UnsupportedServerProtocol,
        426=>SdkIdentityRejected,
        422=>HasExactCode(body,"sdk_policy_invalid")?SdkIdentityRejected:PayloadValidationRejected,
        400 or 409 or 413=>PayloadValidationRejected,
        429=>RateLimited,
        408 or 502 or 503 or 504=>EndpointUnavailable,
        >=500 and <=599=>EndpointUnavailable,
        _=>UnknownSafeRejection
    };
    static bool HasExactCode(byte[] body,string expected)
    {
        if(body.Length is <=0 or >65536)return false;
        try{using var stream=new MemoryStream(body,false);var value=(SafeCodeReceipt)new DataContractJsonSerializer(typeof(SafeCodeReceipt)).ReadObject(stream);return string.Equals(value.Code,expected,StringComparison.Ordinal);}
        catch(Exception){return false;}
    }
    public static bool IsKnown(string? value)=>value is InvalidOrRevokedKey or KeyApplicationMismatch or UnsupportedServerProtocol or SdkIdentityRejected or PayloadValidationRejected or RateLimited or EndpointUnavailable or UnknownSafeRejection;
    [DataContract]sealed class SafeCodeReceipt{[DataMember(Name="code")]public string? Code{get;set;}}
}

public static class SdkLabExternalReceipt
{
    public static SdkLabExternalReceiptAssessment Assess(int statusCode,byte[] body,Guid expectedIncidentId,Guid? expectedApplicationId)
    {
        if(statusCode is <200 or >299){var code=SdkLabSafeRejectionCodes.FromResponse(statusCode,body);return new(false,statusCode is 408 or 429 or >=500,code,code,statusCode);}
        if(body.Length is <=0 or >65536||expectedIncidentId==Guid.Empty)return new(false,false,SdkLabSafeRejectionCodes.UnsupportedServerProtocol,SdkLabSafeRejectionCodes.UnsupportedServerProtocol,statusCode);
        try
        {
            Receipt receipt;using(var stream=new MemoryStream(body,false))receipt=(Receipt)new DataContractJsonSerializer(typeof(Receipt)).ReadObject(stream);
            var validStatus=receipt.Status=="stored"||receipt.Status=="already_exists";
            var validIncident=Guid.TryParse(receipt.IncidentId,out var incidentId)&&incidentId==expectedIncidentId;
            var hasApplication=Guid.TryParse(receipt.ApplicationId,out var applicationId);
            var validApplication=!expectedApplicationId.HasValue||(hasApplication&&applicationId==expectedApplicationId.Value);
            if(validStatus&&validIncident&&validApplication)return new(true,false,string.Empty,null,statusCode);
            var code=validStatus&&validIncident&&expectedApplicationId.HasValue&&hasApplication&&!validApplication?SdkLabSafeRejectionCodes.KeyApplicationMismatch:validStatus&&!validIncident?SdkLabSafeRejectionCodes.UnknownSafeRejection:SdkLabSafeRejectionCodes.UnsupportedServerProtocol;
            return new(false,false,code,code,statusCode);
        }
        catch(Exception){return new(false,false,SdkLabSafeRejectionCodes.UnsupportedServerProtocol,SdkLabSafeRejectionCodes.UnsupportedServerProtocol,statusCode);}
    }

    [DataContract]
    sealed class Receipt
    {
        [DataMember(Name="status")]public string? Status { get; set; }
        [DataMember(Name="incidentId")]public string? IncidentId { get; set; }
        [DataMember(Name="applicationId")]public string? ApplicationId { get; set; }
    }
}
