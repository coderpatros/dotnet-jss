using System.Text.Json.Nodes;
using CoderPatros.Jss.Keys;
using CoderPatros.Jss.Models;
using CoderPatros.Jss.Tests.TestFixtures;
using FluentAssertions;

namespace CoderPatros.Jss.Tests.Integration;

public class SingleSignatureTests
{
    private readonly JssSignatureService _service = new();

    private static JsonObject CreateTestDocument() =>
        new()
        {
            ["now"] = "2025-01-01T00:00:00Z",
            ["escapeMe"] = "\u0001\u001e",
            ["numbers"] = new JsonArray(1e0, 4.5, 6)
        };

    [Theory]
    [InlineData(JssAlgorithm.ES256)]
    [InlineData(JssAlgorithm.ES384)]
    [InlineData(JssAlgorithm.ES512)]
    public void EcdsaSignAndVerify_WithEmbeddedPublicKey(string algorithm)
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(algorithm);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        signed["signatures"].Should().NotBeNull();
        var result = _service.Verify(signed, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JssAlgorithm.RS256)]
    [InlineData(JssAlgorithm.RS384)]
    [InlineData(JssAlgorithm.RS512)]
    public void RsaPkcs1SignAndVerify_WithExplicitKey(string algorithm)
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification
        });
        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JssAlgorithm.PS256)]
    [InlineData(JssAlgorithm.PS384)]
    [InlineData(JssAlgorithm.PS512)]
    public void RsaPssSignAndVerify(string algorithm)
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification
        });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Ed25519SignAndVerify_WithEmbeddedPublicKey()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEdDsaKeySet("Ed25519");
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.Ed25519,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var result = _service.Verify(signed, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Ed448SignAndVerify_WithEmbeddedPublicKey()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEdDsaKeySet("Ed448");
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.Ed448,
            HashAlgorithm = JssHashAlgorithm.Sha512,
            Key = signing,
            PublicKey = pemBody
        });

        var result = _service.Verify(signed, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Sign_DoesNotMutateInput()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = CreateTestDocument();
        var originalJson = doc.ToJsonString();

        _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        doc.ToJsonString().Should().Be(originalJson);
    }

    [Fact]
    public void Verify_WrongKey_ReturnsFalse()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (_, wrongVerification, _) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = wrongVerification
        });
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void Verify_TamperedDocument_ReturnsFalse()
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        // Tamper with the document
        signed["now"] = "2025-12-31T23:59:59Z";

        var result = _service.Verify(signed, new VerificationOptions
        {
            Key = verification
        });
        result.IsValid.Should().BeFalse();
    }

    [Fact]
    public void SignAndVerify_ViaJsonString()
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var json = """{"message":"hello"}""";

        var signedJson = _service.Sign(json, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var result = _service.Verify(signedJson, new VerificationOptions
        {
            Key = verification
        });
        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JssAlgorithm.ES256)]
    [InlineData(JssAlgorithm.ES384)]
    [InlineData(JssAlgorithm.ES512)]
    public void EcdsaSignAndVerify_ImplicitKey(string algorithm)
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateEcdsaKeySet(algorithm);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var sigObj = signed["signatures"]!.AsArray()[0]!.AsObject();
        sigObj["public_key"].Should().NotBeNull();
        sigObj["algorithm"]!.GetValue<string>().Should().Be(algorithm);
        sigObj["value"].Should().NotBeNull();

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JssAlgorithm.RS256)]
    [InlineData(JssAlgorithm.RS384)]
    [InlineData(JssAlgorithm.RS512)]
    public void RsaPkcs1SignAndVerify_WithEmbeddedPublicKey(string algorithm)
    {
        var (signing, _, pemBody) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var sigObj = signed["signatures"]!.AsArray()[0]!.AsObject();
        sigObj["public_key"].Should().NotBeNull();

        // Verify using only the embedded public key (no explicit key)
        var result = _service.Verify(signed, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData(JssAlgorithm.PS256)]
    [InlineData(JssAlgorithm.PS384)]
    [InlineData(JssAlgorithm.PS512)]
    public void RsaPssSignAndVerify_WithEmbeddedPublicKey(string algorithm)
    {
        var (signing, _, pemBody) = KeyFixtures.CreateRsaKeySet();
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        // Verify using only the embedded public key
        var result = _service.Verify(signed, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeTrue();
    }

    [Theory]
    [InlineData("Ed25519", JssAlgorithm.Ed25519)]
    [InlineData("Ed448", JssAlgorithm.Ed448)]
    public void EdDsaSignAndVerify_WithExplicitKey(string curve, string algorithm)
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateEdDsaKeySet(curve);
        var doc = CreateTestDocument();

        var hashAlg = curve == "Ed448" ? JssHashAlgorithm.Sha512 : JssHashAlgorithm.Sha256;
        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = algorithm,
            HashAlgorithm = hashAlg,
            Key = signing,
            PublicKey = pemBody
        });

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// Verification should fail when no key is available.
    /// </summary>
    [Fact]
    public void Verify_NoKeyAvailable_ReturnsFalse()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        // Attempt verification without any key
        var act = () => _service.Verify(signed, new VerificationOptions());
        act.Should().Throw<JssException>();
    }

    /// <summary>
    /// Different hash algorithms should be supported.
    /// </summary>
    [Theory]
    [InlineData(JssHashAlgorithm.Sha256)]
    [InlineData(JssHashAlgorithm.Sha384)]
    [InlineData(JssHashAlgorithm.Sha512)]
    public void SignAndVerify_DifferentHashAlgorithms(string hashAlgorithm)
    {
        var (signing, verification, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = CreateTestDocument();

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = hashAlgorithm,
            Key = signing,
            PublicKey = pemBody
        });

        var sigObj = signed["signatures"]!.AsArray()[0]!.AsObject();
        sigObj["hash_algorithm"]!.GetValue<string>().Should().Be(hashAlgorithm);

        var result = _service.Verify(signed, new VerificationOptions { Key = verification });
        result.IsValid.Should().BeTrue();
    }
}
