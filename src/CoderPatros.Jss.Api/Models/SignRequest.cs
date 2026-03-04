using System.Text.Json.Nodes;

namespace CoderPatros.Jss.Api.Models;

public sealed record SignRequest
{
    public required JsonObject Document { get; init; }
    public required string Algorithm { get; init; }
    public required string HashAlgorithm { get; init; }
    public required string PrivateKeyPem { get; init; }
    public bool EmbedPublicKey { get; init; }
}
