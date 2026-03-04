using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoderPatros.Jss.Keys;
using FluentAssertions;

namespace CoderPatros.Jss.Tests.Integration;

public class CertificateHelperTests
{
    [Fact]
    public void ComputeThumbprint_ReturnsBase64Url_NotHex()
    {
        // Create a self-signed certificate
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        var thumbprint = CertificateHelper.ComputeThumbprint(cert);

        // base64url characters: A-Z, a-z, 0-9, -, _
        // hex characters: 0-9, a-f
        // A SHA-256 hash is 32 bytes → base64url is 43 chars (no padding)
        // hex would be 64 chars
        thumbprint.Length.Should().Be(43, "base64url of 32 bytes should be 43 characters (no padding)");
        thumbprint.Should().MatchRegex("^[A-Za-z0-9_-]+$", "should only contain base64url characters");
    }

    [Fact]
    public void ComputeThumbprint_FromBase64Der_ReturnsBase64Url()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=Test", ecdsa, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));

        var base64Der = Convert.ToBase64String(cert.RawData);
        var thumbprint = CertificateHelper.ComputeThumbprint(base64Der);

        thumbprint.Length.Should().Be(43);
        thumbprint.Should().MatchRegex("^[A-Za-z0-9_-]+$");

        // Should match the X509Certificate2 overload
        var thumbprint2 = CertificateHelper.ComputeThumbprint(cert);
        thumbprint.Should().Be(thumbprint2);
    }
}
