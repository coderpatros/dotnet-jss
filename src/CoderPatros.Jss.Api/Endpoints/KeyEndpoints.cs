using CoderPatros.Jss.Api.Models;
using CoderPatros.Jss.Keys;

namespace CoderPatros.Jss.Api.Endpoints;

public static class KeyEndpoints
{
    private static readonly string[] ValidAlgorithms =
    [
        "ES256", "ES384", "ES512",
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512",
        "Ed25519", "Ed448"
    ];

    public static void MapKeyEndpoints(this WebApplication app)
    {
        app.MapPost("/api/keys/generate", HandleGenerateKey);
    }

    private static IResult HandleGenerateKey(GenerateKeyRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Algorithm))
            return Results.BadRequest(new ErrorResponse { Error = "Algorithm is required." });

        if (!ValidAlgorithms.Contains(request.Algorithm))
            return Results.BadRequest(new ErrorResponse { Error = $"Unsupported algorithm: {request.Algorithm}. Valid algorithms: {string.Join(", ", ValidAlgorithms)}" });

        try
        {
            var (signingKey, _, publicKeyPemBody) = PemKeyHelper.GenerateKeyPair(request.Algorithm);
            var privateKeyPem = PemKeyHelper.ExportPrivateKeyPem(signingKey, request.Algorithm);
            var publicKeyPem = PemKeyHelper.ExportPublicKeyPem(publicKeyPemBody);
            signingKey.Dispose();

            return Results.Ok(new GenerateKeyResponse
            {
                PrivateKeyPem = privateKeyPem,
                PublicKeyPem = publicKeyPem,
                PublicKeyPemBody = publicKeyPemBody
            });
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new ErrorResponse { Error = ex.Message });
        }
    }
}
