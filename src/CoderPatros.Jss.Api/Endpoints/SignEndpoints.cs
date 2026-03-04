using CoderPatros.Jss.Api.Models;
using CoderPatros.Jss.Keys;
using CoderPatros.Jss.Models;

namespace CoderPatros.Jss.Api.Endpoints;

public static class SignEndpoints
{
    public static void MapSignEndpoints(this WebApplication app)
    {
        app.MapPost("/api/sign", HandleSign);
        app.MapPost("/api/signatures/countersign", HandleCountersign);
    }

    private static IResult HandleSign(SignRequest request)
    {
        try
        {
            var service = new JssSignatureService();
            using var signingKey = PemKeyHelper.ImportPrivateKeyPem(request.PrivateKeyPem, request.Algorithm);

            // ITU-T X.590 clause 6.2.1: at least one key identification property MUST be populated.
            // Always embed the public key derived from the signing key.
            var publicKeyPemBody = PemKeyHelper.ExportPublicKeyPemBody(signingKey, request.Algorithm);

            var options = new SignatureOptions
            {
                Algorithm = request.Algorithm,
                HashAlgorithm = request.HashAlgorithm,
                Key = signingKey,
                PublicKey = publicKeyPemBody
            };

            var signed = service.Sign(request.Document, options);
            return Results.Ok(new SignResponse { Document = signed });
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }

    private static IResult HandleCountersign(CountersignRequest request)
    {
        try
        {
            var service = new JssSignatureService();
            using var signingKey = PemKeyHelper.ImportPrivateKeyPem(request.PrivateKeyPem, request.Algorithm);

            var options = new CountersignOptions
            {
                Algorithm = request.Algorithm,
                HashAlgorithm = request.HashAlgorithm,
                Key = signingKey,
                SignatureIndex = request.SignatureIndex
            };

            if (request.EmbedPublicKey)
            {
                var publicKeyPemBody = PemKeyHelper.ExportPublicKeyPemBody(signingKey, request.Algorithm);
                if (publicKeyPemBody is not null)
                    options = options with { PublicKey = publicKeyPemBody };
            }

            var result = service.Countersign(request.Document, options);
            return Results.Ok(new SignResponse { Document = result });
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }
}
