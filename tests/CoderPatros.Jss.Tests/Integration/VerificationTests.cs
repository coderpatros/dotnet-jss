using System.Text.Json.Nodes;
using CoderPatros.Jss.Models;
using CoderPatros.Jss.Tests.TestFixtures;
using FluentAssertions;

namespace CoderPatros.Jss.Tests.Integration;

public class VerificationTests
{
    private readonly JssSignatureService _service = new();

    [Fact]
    public void Verify_AcceptedAlgorithms_RejectsUnlisted()
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["test"] = "algorithm restriction" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        // Verify with a set that does NOT include ES256
        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification,
            AcceptedAlgorithms = new HashSet<string> { "RS256", "Ed25519" }
        });
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void Verify_AcceptedAlgorithms_AcceptsListed()
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["test"] = "algorithm accepted" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification,
            AcceptedAlgorithms = new HashSet<string> { "ES256", "RS256" }
        });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Verify_EmbeddedKey_WhenNotAllowed_Fails()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["test"] = "embedded not allowed" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        // Verify without allowing embedded key and without providing explicit key
        var act = () => _service.Verify(signed, new VerificationOptions
        {
            AllowEmbeddedPublicKey = false
        });
        act.Should().Throw<JssException>();
    }

    [Fact]
    public void Verify_ModifiedSignatureValue_ReturnsFalse()
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["test"] = "modified value" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        // Tamper with the signature value
        var sigObj = signed["signatures"]!.AsArray()[0]!.AsObject();
        sigObj["value"] = "AAAA_invalid_signature_AAAA";

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification
        });
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void VerifyAll_WithOneInvalidSignature_ReturnsFalse()
    {
        var (signing1, _, pemBody1) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (signing2, _, pemBody2) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES384);

        var doc = new JsonObject { ["test"] = "verify-all invalid" };

        var signed1 = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing1,
            PublicKey = pemBody1
        });

        var signed2 = _service.Sign(signed1, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES384,
            HashAlgorithm = JssHashAlgorithm.Sha384,
            Key = signing2,
            PublicKey = pemBody2
        });

        // Tamper with the first signature's value
        var signatures = signed2["signatures"]!.AsArray();
        signatures[0]!.AsObject()["value"] = "AAAA_invalid_AAAA";

        var result = _service.VerifyAll(signed2, new VerificationOptions
        {
            AllowEmbeddedPublicKey = true
        });
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void Verify_SignaturesArrayMissing_Throws()
    {
        var (_, verification, _) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["test"] = "no signatures" };

        var act = () => _service.Verify(doc, new VerificationOptions
        {
            Key = verification
        });
        act.Should().Throw<JssException>();
    }

    [Fact]
    public void Sign_WithNoKeyIdentificationProperty_Throws()
    {
        var (signing, _, _) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["test"] = "no key id" };

        var act = () => _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing
        });
        act.Should().Throw<JssException>()
            .WithMessage("*key identification*");
    }

    [Fact]
    public void Sign_WithThumbprintOnly_Succeeds()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["test"] = "thumbprint only" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            Thumbprint = "dummythumbprint"
        });

        signed["signatures"].Should().NotBeNull();
        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_WithCertUrlOnly_Succeeds()
    {
        var (signing, verification, _) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["test"] = "cert_url only" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            CertUrl = "https://example.com/cert"
        });

        signed["signatures"].Should().NotBeNull();
        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }
}
