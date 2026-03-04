using System.Text.Json.Nodes;

namespace CoderPatros.Jss.Api.Models;

public sealed record VerifyRequest
{
    public required JsonObject Document { get; init; }
    public string? PublicKeyPem { get; init; }
    public string? Algorithm { get; init; }
    public bool AllowEmbeddedKey { get; init; }
    public IReadOnlyList<string>? AcceptedAlgorithms { get; init; }
}
