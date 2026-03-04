using System.Text.Json.Nodes;
using CoderPatros.Jss.Models;
using CoderPatros.Jss.Tests.TestFixtures;
using FluentAssertions;

namespace CoderPatros.Jss.Tests.Integration;

public class MultiSignatureTests
{
    private readonly JssSignatureService _service = new();

    [Fact]
    public void TwoSignatures_BothVerify()
    {
        var (signing1, verification1, pemBody1) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (signing2, verification2, pemBody2) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES384);

        var doc = new JsonObject { ["message"] = "multi-sig test" };

        // First signature
        var signed1 = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing1,
            PublicKey = pemBody1
        });

        // Second signature
        var signed2 = _service.Sign(signed1, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES384,
            HashAlgorithm = JssHashAlgorithm.Sha384,
            Key = signing2,
            PublicKey = pemBody2
        });

        var signatures = signed2["signatures"]!.AsArray();
        signatures.Count.Should().Be(2);

        // Verify all
        var result = _service.VerifyAll(signed2, new VerificationOptions
        {
            AllowEmbeddedPublicKey = true
        });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void MultiSig_VerifySpecificSignature()
    {
        var (signing1, _, pemBody1) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (signing2, _, pemBody2) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES384);

        var doc = new JsonObject { ["data"] = "test" };

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

        // Verify first signature
        var result0 = _service.Verify(signed2, new VerificationOptions
        {
            AllowEmbeddedPublicKey = true
        }, signatureIndex: 0);
        result0.IsValid.Should().BeTrue();

        // Verify second signature
        var result1 = _service.Verify(signed2, new VerificationOptions
        {
            AllowEmbeddedPublicKey = true
        }, signatureIndex: 1);
        result1.IsValid.Should().BeTrue();
    }

    [Fact]
    public void MultiSig_ExistingSignaturesAtStart_NewAtEnd()
    {
        var (signing1, _, pemBody1) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (signing2, _, pemBody2) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES384);

        var doc = new JsonObject { ["order"] = "test" };

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

        var signatures = signed2["signatures"]!.AsArray();
        // First signature (index 0) should be ES256 (existing)
        signatures[0]!.AsObject()["algorithm"]!.GetValue<string>().Should().Be("ES256");
        // Second signature (index 1) should be ES384 (new)
        signatures[1]!.AsObject()["algorithm"]!.GetValue<string>().Should().Be("ES384");
    }
}
