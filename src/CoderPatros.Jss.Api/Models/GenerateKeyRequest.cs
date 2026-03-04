namespace CoderPatros.Jss.Api.Models;

public sealed record GenerateKeyRequest
{
    public required string Algorithm { get; init; }
}
