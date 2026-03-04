using System.Text.Json.Nodes;
using CoderPatros.Jss.Models;
using CoderPatros.Jss.Tests.TestFixtures;
using FluentAssertions;

namespace CoderPatros.Jss.Tests.Integration;

public class CountersignatureTests
{
    private readonly JssSignatureService _service = new();

    [Fact]
    public void Countersign_CreatesNestedSignature()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (countersigning, _, counterPemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES384);

        var doc = new JsonObject { ["message"] = "countersign test" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.ES384,
            HashAlgorithm = JssHashAlgorithm.Sha384,
            Key = countersigning,
            PublicKey = counterPemBody,
            SignatureIndex = 0
        });

        // The target signature should now have a nested "signature" property
        var signatures = countersigned["signatures"]!.AsArray();
        signatures.Count.Should().Be(1);

        var targetSig = signatures[0]!.AsObject();
        targetSig["signature"].Should().NotBeNull();

        var nestedSig = targetSig["signature"]!.AsObject();
        nestedSig["algorithm"]!.GetValue<string>().Should().Be("ES384");
        nestedSig["hash_algorithm"]!.GetValue<string>().Should().Be("sha-384");
        nestedSig["value"].Should().NotBeNull();
    }

    [Fact]
    public void Countersign_Ed25519_RoundTrip()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEdDsaKeySet("Ed25519");
        var (countersigning, _, counterPemBody) = KeyFixtures.CreateEdDsaKeySet("Ed25519");

        var doc = new JsonObject { ["data"] = "countersign ed25519" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.Ed25519,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.Ed25519,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = countersigning,
            PublicKey = counterPemBody,
            SignatureIndex = 0
        });

        // The main signature should still verify
        var result = _service.Verify(countersigned, new VerificationOptions
        {
            AllowEmbeddedPublicKey = true
        }, signatureIndex: 0);
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void VerifyCountersignature_ValidCountersig_ReturnsTrue()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (countersigning, counterVerification, counterPemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES384);

        var doc = new JsonObject { ["message"] = "verify countersig test" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.ES384,
            HashAlgorithm = JssHashAlgorithm.Sha384,
            Key = countersigning,
            PublicKey = counterPemBody,
            SignatureIndex = 0
        });

        var result = _service.VerifyCountersignature(countersigned, new VerificationOptions
        {
            Key = counterVerification
        }, signatureIndex: 0);
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void VerifyCountersignature_WithEmbeddedKey_ReturnsTrue()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (countersigning, _, counterPemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES384);

        var doc = new JsonObject { ["message"] = "verify countersig embedded key" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.ES384,
            HashAlgorithm = JssHashAlgorithm.Sha384,
            Key = countersigning,
            PublicKey = counterPemBody,
            SignatureIndex = 0
        });

        var result = _service.VerifyCountersignature(countersigned, new VerificationOptions
        {
            AllowEmbeddedPublicKey = true
        }, signatureIndex: 0);
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void VerifyCountersignature_WrongKey_ReturnsFalse()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (countersigning, _, counterPemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES384);
        var (_, wrongVerification, _) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES384);

        var doc = new JsonObject { ["message"] = "wrong key countersig" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.ES384,
            HashAlgorithm = JssHashAlgorithm.Sha384,
            Key = countersigning,
            PublicKey = counterPemBody,
            SignatureIndex = 0
        });

        var result = _service.VerifyCountersignature(countersigned, new VerificationOptions
        {
            Key = wrongVerification
        }, signatureIndex: 0);
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void VerifyCountersignature_NoCountersig_Throws()
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["message"] = "no countersig" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var act = () => _service.VerifyCountersignature(signed, new VerificationOptions
        {
            Key = verification
        }, signatureIndex: 0);
        act.Should().Throw<JssException>()
            .WithMessage("*no countersignature*");
    }

    [Fact]
    public void VerifyCountersignature_Ed25519_RoundTrip()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEdDsaKeySet("Ed25519");
        var (countersigning, counterVerification, counterPemBody) = KeyFixtures.CreateEdDsaKeySet("Ed25519");

        var doc = new JsonObject { ["data"] = "ed25519 countersig verify" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.Ed25519,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.Ed25519,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = countersigning,
            PublicKey = counterPemBody,
            SignatureIndex = 0
        });

        // Verify main sig still works
        var mainResult = _service.Verify(countersigned, new VerificationOptions
        {
            AllowEmbeddedPublicKey = true
        }, signatureIndex: 0);
        mainResult.IsValid.Should().BeTrue();

        // Verify countersig
        var counterResult = _service.VerifyCountersignature(countersigned, new VerificationOptions
        {
            Key = counterVerification
        }, signatureIndex: 0);
        counterResult.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Countersign_DoesNotMutateInput()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);

        var doc = new JsonObject { ["message"] = "immutability test" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var originalJson = signed.ToJsonString();

        var (countersigning, _, counterPemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = countersigning,
            PublicKey = counterPemBody,
            SignatureIndex = 0
        });

        signed.ToJsonString().Should().Be(originalJson);
    }
}
