using System.Text.Json.Nodes;
using CoderPatros.Jss.Api.Models;
using CoderPatros.Jss.Keys;
using CoderPatros.Jss.Models;

namespace CoderPatros.Jss.Api.Endpoints;

public static class VerifyEndpoints
{
    public static void MapVerifyEndpoints(this WebApplication app)
    {
        app.MapPost("/api/verify", HandleVerify);
        app.MapPost("/api/signatures/verify-all", HandleVerifyAll);
    }

    private static IResult HandleVerify(VerifyRequest request)
    {
        try
        {
            var service = new JssSignatureService();
            var options = BuildVerificationOptions(request);

            using (options.Key)
            {
                var result = service.Verify(request.Document, options);
                return Results.Ok(new VerifyResponse { IsValid = result.IsValid, Error = result.Error });
            }
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }

    private static IResult HandleVerifyAll(VerifyRequest request)
    {
        try
        {
            var service = new JssSignatureService();
            var options = BuildVerificationOptions(request);

            using (options.Key)
            {
                var result = service.VerifyAll(request.Document, options);
                return Results.Ok(new VerifyResponse { IsValid = result.IsValid, Error = result.Error });
            }
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }

    private static VerificationOptions BuildVerificationOptions(VerifyRequest request)
    {
        VerificationKey? verificationKey = null;
        if (request.PublicKeyPem is not null)
        {
            // Determine algorithm from the document if not provided
            var algorithm = request.Algorithm;
            if (algorithm is null && request.Document["signatures"] is JsonArray sigArr && sigArr.Count > 0)
                algorithm = sigArr[sigArr.Count - 1]!.AsObject()["algorithm"]?.GetValue<string>();
            algorithm ??= "ES256";

            verificationKey = PemKeyHelper.ImportPublicKeyPem(request.PublicKeyPem, algorithm);
        }

        IReadOnlySet<string>? acceptedAlgorithmsSet = null;
        if (request.AcceptedAlgorithms is { Count: > 0 })
            acceptedAlgorithmsSet = new HashSet<string>(request.AcceptedAlgorithms, StringComparer.Ordinal);

        return new VerificationOptions
        {
            Key = verificationKey,
            AllowEmbeddedPublicKey = request.AllowEmbeddedKey,
            AcceptedAlgorithms = acceptedAlgorithmsSet
        };
    }
}
