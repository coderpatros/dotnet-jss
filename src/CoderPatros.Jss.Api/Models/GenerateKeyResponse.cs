namespace CoderPatros.Jss.Api.Models;

public sealed record GenerateKeyResponse
{
    public string? PrivateKeyPem { get; init; }
    public string? PublicKeyPem { get; init; }
    public string? PublicKeyPemBody { get; init; }
}
