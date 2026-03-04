using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using CoderPatros.Jss.Canonicalization;
using CoderPatros.Jss.Models;
using CoderPatros.Jss.Tests.TestFixtures;
using FluentAssertions;

namespace CoderPatros.Jss.Tests.Integration;

/// <summary>
/// Tests against the exact values from ITU-T X.590 spec examples.
/// </summary>
public class SpecTestVectorTests
{
    private readonly JssSignatureService _service = new();

    /// <summary>
    /// Spec clause 7.1.4 — canonical form of the document with signature object (without value).
    /// </summary>
    [Fact]
    public void CanonicalForm_MatchesSpec()
    {
        var doc = new JsonObject
        {
            ["statement"] = "Hello signed world!",
            ["otherProperties"] = new JsonArray("home", "food"),
            ["signatures"] = new JsonArray(
                new JsonObject
                {
                    ["algorithm"] = "Ed25519",
                    ["hash_algorithm"] = "sha-256",
                    ["public_key"] = SpecReferenceKeys.Ed25519PublicKeyPemBody
                }
            )
        };

        var canonical = JsonCanonicalizer.Canonicalize(doc);

        const string expected =
            """{"otherProperties":["home","food"],"signatures":[{"algorithm":"Ed25519","hash_algorithm":"sha-256","public_key":"MCowBQYDK2VwAyEAubMonBfU9pvIbj5RCiWQLD45Jvu6mKr+kQXjvjW8ZkU"}],"statement":"Hello signed world!"}""";

        canonical.Should().Be(expected);
    }

    /// <summary>
    /// Spec clause 7.1.5 — SHA-256 hash of the canonical form.
    /// </summary>
    [Fact]
    public void HashOfCanonicalForm_MatchesSpec()
    {
        var doc = new JsonObject
        {
            ["statement"] = "Hello signed world!",
            ["otherProperties"] = new JsonArray("home", "food"),
            ["signatures"] = new JsonArray(
                new JsonObject
                {
                    ["algorithm"] = "Ed25519",
                    ["hash_algorithm"] = "sha-256",
                    ["public_key"] = SpecReferenceKeys.Ed25519PublicKeyPemBody
                }
            )
        };

        var canonical = JsonCanonicalizer.Canonicalize(doc);
        var canonicalBytes = Encoding.UTF8.GetBytes(canonical);
        var hash = SHA256.HashData(canonicalBytes);
        var hashHex = Convert.ToHexString(hash).ToLowerInvariant();

        hashHex.Should().Be("e005ae762a01723f3b58fa8edb2b2cc3b126ca087077189072cfd9a27e6079d5");
    }

    /// <summary>
    /// Sign the spec example document with the spec Appendix II key and verify the result.
    /// NOTE: The spec's published signature values (clauses 7.1.6, 7.2.6) do not verify against
    /// the Appendix II public key (confirmed via openssl), so we test sign+verify round-trips
    /// with the spec key instead of exact value matching.
    /// </summary>
    [Fact]
    public void SignWithSpecKey_RoundTrip()
    {
        using var signingKey = SpecReferenceKeys.GetEd25519SigningKey();

        var doc = new JsonObject
        {
            ["statement"] = "Hello signed world!",
            ["otherProperties"] = new JsonArray("home", "food")
        };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = "Ed25519",
            HashAlgorithm = "sha-256",
            Key = signingKey,
            PublicKey = SpecReferenceKeys.Ed25519PublicKeyPemBody
        });

        var signatures = signed["signatures"]!.AsArray();
        signatures.Count.Should().Be(1);
        signatures[0]!.AsObject()["value"].Should().NotBeNull();

        var result = _service.Verify(signed, new VerificationOptions
        {
            AllowEmbeddedPublicKey = true
        });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// Countersign the spec example document with the spec key and verify the result.
    /// </summary>
    [Fact]
    public void CountersignWithSpecKey_RoundTrip()
    {
        using var signingKey = SpecReferenceKeys.GetEd25519SigningKey();

        var doc = new JsonObject
        {
            ["statement"] = "Hello signed world!",
            ["otherProperties"] = new JsonArray("home", "food")
        };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = "Ed25519",
            HashAlgorithm = "sha-256",
            Key = signingKey,
            PublicKey = SpecReferenceKeys.Ed25519PublicKeyPemBody
        });

        using var counterKey = SpecReferenceKeys.GetEd25519SigningKey();
        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = "Ed25519",
            HashAlgorithm = "sha-256",
            Key = counterKey,
            PublicKey = SpecReferenceKeys.Ed25519PublicKeyPemBody,
            SignatureIndex = 0
        });

        var nestedSig = countersigned["signatures"]![0]!.AsObject()["signature"]!.AsObject();
        nestedSig["value"].Should().NotBeNull();

        // Main signature should still verify after countersigning
        var result = _service.Verify(countersigned, new VerificationOptions
        {
            AllowEmbeddedPublicKey = true
        }, signatureIndex: 0);
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// Ed25519 sign and verify round-trip produces valid output.
    /// </summary>
    [Fact]
    public void Ed25519SignAndVerify_RoundTrip()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEdDsaKeySet("Ed25519");

        var doc = new JsonObject
        {
            ["statement"] = "Hello signed world!",
            ["otherProperties"] = new JsonArray("home", "food")
        };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = "Ed25519",
            HashAlgorithm = "sha-256",
            Key = signing,
            PublicKey = pemBody
        });

        var signatures = signed["signatures"]!.AsArray();
        signatures.Count.Should().Be(1);
        signatures[0]!.AsObject()["value"].Should().NotBeNull();

        var result = _service.Verify(signed, new VerificationOptions { AllowEmbeddedPublicKey = true });
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// Ed25519 countersign round-trip produces valid output.
    /// </summary>
    [Fact]
    public void Ed25519CountersignAndVerify_RoundTrip()
    {
        var (signing, _, pemBody) = KeyFixtures.CreateEdDsaKeySet("Ed25519");
        var (countersigning, _, counterPemBody) = KeyFixtures.CreateEdDsaKeySet("Ed25519");

        var doc = new JsonObject
        {
            ["statement"] = "Hello signed world!",
            ["otherProperties"] = new JsonArray("home", "food")
        };

        var signed = _service.Sign(doc, new SignatureOptions
        {
            Algorithm = "Ed25519",
            HashAlgorithm = "sha-256",
            Key = signing,
            PublicKey = pemBody
        });

        var countersigned = _service.Countersign(signed, new CountersignOptions
        {
            Algorithm = "Ed25519",
            HashAlgorithm = "sha-256",
            Key = countersigning,
            PublicKey = counterPemBody,
            SignatureIndex = 0
        });

        var signatures = countersigned["signatures"]!.AsArray();
        var nestedSig = signatures[0]!.AsObject()["signature"]!.AsObject();
        nestedSig["value"].Should().NotBeNull();

        // Main signature should still verify
        var result = _service.Verify(countersigned, new VerificationOptions
        {
            AllowEmbeddedPublicKey = true
        }, signatureIndex: 0);
        result.IsValid.Should().BeTrue();
    }
}
