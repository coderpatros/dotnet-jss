namespace CoderPatros.Jss.Api.Models;

public sealed record ErrorResponse
{
    public required string Error { get; init; }
}
