using System.Text.Json.Nodes;
using CoderPatros.Jss.Models;
using CoderPatros.Jss.Tests.TestFixtures;
using FluentAssertions;

namespace CoderPatros.Jss.Tests.Integration;

/// <summary>
/// Tests for ITU-T X.590 compliance fixes:
/// - Issue 1: Countersigner key identification validation
/// - Issue 2: Metadata key collision with reserved properties
/// - Issue 3: Existing countersignature detection
/// </summary>
public class ComplianceValidationTests
{
    private readonly JssSignatureService _service = new();

    // --- Issue 1: Countersigner key identification validation ---

    [Fact]
    public void Countersign_WithNoKeyIdentification_Throws()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (countersigning, _, _) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);

        var doc = new JsonObject { ["message"] = "test" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var act = () => _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = countersigning,
            SignatureIndex = 0
            // No key identification properties set
        });

        act.Should().Throw<JssException>()
            .WithMessage("*key identification*");
    }

    [Fact]
    public void Countersign_WithPublicKey_Succeeds()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (countersigning, _, counterPemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);

        var doc = new JsonObject { ["message"] = "test" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = countersigning,
            PublicKey = counterPemBody,
            SignatureIndex = 0
        });

        countersigned["signatures"]!.AsArray()[0]!.AsObject()["signature"].Should().NotBeNull();
    }

    [Fact]
    public void Countersign_WithThumbprintOnly_Succeeds()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (countersigning, _, _) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);

        var doc = new JsonObject { ["message"] = "test" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = countersigning,
            Thumbprint = "some-thumbprint",
            SignatureIndex = 0
        });

        countersigned["signatures"]!.AsArray()[0]!.AsObject()["signature"].Should().NotBeNull();
    }

    // --- Issue 2: Metadata key collision ---

    [Theory]
    [InlineData("algorithm")]
    [InlineData("hash_algorithm")]
    [InlineData("value")]
    [InlineData("signature")]
    [InlineData("public_key")]
    [InlineData("public_cert_chain")]
    [InlineData("cert_url")]
    [InlineData("thumbprint")]
    public void Sign_WithReservedMetadataKey_Throws(string reservedKey)
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["message"] = "test" };

        var metadata = new Dictionary<string, JsonNode?>
        {
            [reservedKey] = JsonValue.Create("malicious-value")
        };

        var act = () => _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody,
            Metadata = metadata
        });

        act.Should().Throw<JssException>()
            .WithMessage($"*'{reservedKey}'*reserved*");
    }

    [Fact]
    public void Sign_WithNonReservedMetadataKey_Succeeds()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var doc = new JsonObject { ["message"] = "test" };

        var metadata = new Dictionary<string, JsonNode?>
        {
            ["custom_field"] = JsonValue.Create("custom-value")
        };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody,
            Metadata = metadata
        });

        var sig = signed["signatures"]!.AsArray()[0]!.AsObject();
        sig["custom_field"]!.GetValue<string>().Should().Be("custom-value");
    }

    // --- Issue 3: Existing countersignature detection ---

    [Fact]
    public void Countersign_AlreadyCountersigned_Throws()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (countersigning1, _, counterPemBody1) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);
        var (countersigning2, _, counterPemBody2) = KeyFixtures.CreateEcdsaKeySet(JssAlgorithm.ES256);

        var doc = new JsonObject { ["message"] = "test" };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = signing,
            PublicKey = pemBody
        });

        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = countersigning1,
            PublicKey = counterPemBody1,
            SignatureIndex = 0
        });

        var act = () => _service.Countersign(countersigned, new CountersignOptions
        {
            Algorithm = JssAlgorithm.ES256,
            HashAlgorithm = JssHashAlgorithm.Sha256,
            Key = countersigning2,
            PublicKey = counterPemBody2,
            SignatureIndex = 0
        });

        act.Should().Throw<JssException>()
            .WithMessage("*already has a countersignature*");
    }
}
