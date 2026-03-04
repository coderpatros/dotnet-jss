using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;

namespace CoderPatros.Jss.Api.Tests;

public class ApiIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public ApiIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("RS256")]
    [InlineData("Ed25519")]
    public async Task GenerateKey_ReturnsKeyPair(string algorithm)
    {
        var response = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm });
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var body = await response.Content.ReadFromJsonAsync<JsonObject>();
        body!["privateKeyPem"].Should().NotBeNull();
        body["publicKeyPem"].Should().NotBeNull();
        body["publicKeyPemBody"].Should().NotBeNull();
    }

    [Fact]
    public async Task GenerateKey_InvalidAlgorithm_Returns400()
    {
        var response = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "INVALID" });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("RS256")]
    [InlineData("PS256")]
    [InlineData("Ed25519")]
    public async Task SignAndVerify_RoundTrips(string algorithm)
    {
        // Generate key
        var genResponse = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm });
        var keys = await genResponse.Content.ReadFromJsonAsync<JsonObject>();
        var privateKeyPem = keys!["privateKeyPem"]!.GetValue<string>();
        var publicKeyPem = keys["publicKeyPem"]!.GetValue<string>();

        // Sign
        var document = JsonNode.Parse("""{"hello":"world"}""")!.AsObject();
        var signResponse = await _client.PostAsJsonAsync("/api/sign", new
        {
            document,
            algorithm,
            hashAlgorithm = "sha-256",
            privateKeyPem
        });
        signResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var signResult = await signResponse.Content.ReadFromJsonAsync<JsonObject>();
        var signedDoc = signResult!["document"]!.AsObject();

        // Verify
        var verifyResponse = await _client.PostAsJsonAsync("/api/verify", new
        {
            document = signedDoc,
            publicKeyPem,
            algorithm
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeTrue();
    }

    [Fact]
    public async Task Sign_WithEmbeddedPublicKey_CanVerifyWithEmbeddedKey()
    {
        var genResponse = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys = await genResponse.Content.ReadFromJsonAsync<JsonObject>();
        var privateKeyPem = keys!["privateKeyPem"]!.GetValue<string>();

        var document = JsonNode.Parse("""{"hello":"world"}""")!.AsObject();
        var signResponse = await _client.PostAsJsonAsync("/api/sign", new
        {
            document,
            algorithm = "ES256",
            hashAlgorithm = "sha-256",
            privateKeyPem,
            embedPublicKey = true
        });
        signResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var signResult = await signResponse.Content.ReadFromJsonAsync<JsonObject>();
        var signedDoc = signResult!["document"]!.AsObject();

        var verifyResponse = await _client.PostAsJsonAsync("/api/verify", new
        {
            document = signedDoc,
            allowEmbeddedKey = true
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeTrue();
    }

    [Fact]
    public async Task Verify_InvalidSignature_ReturnsInvalid()
    {
        // Generate two different key pairs
        var gen1 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys1 = await gen1.Content.ReadFromJsonAsync<JsonObject>();
        var privateKeyPem1 = keys1!["privateKeyPem"]!.GetValue<string>();

        var gen2 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys2 = await gen2.Content.ReadFromJsonAsync<JsonObject>();
        var publicKeyPem2 = keys2!["publicKeyPem"]!.GetValue<string>();

        // Sign with key1
        var document = JsonNode.Parse("""{"hello":"world"}""")!.AsObject();
        var signResponse = await _client.PostAsJsonAsync("/api/sign", new
        {
            document,
            algorithm = "ES256",
            hashAlgorithm = "sha-256",
            privateKeyPem = privateKeyPem1
        });
        var signResult = await signResponse.Content.ReadFromJsonAsync<JsonObject>();
        var signedDoc = signResult!["document"]!.AsObject();

        // Verify with key2 (wrong key)
        var verifyResponse = await _client.PostAsJsonAsync("/api/verify", new
        {
            document = signedDoc,
            publicKeyPem = publicKeyPem2,
            algorithm = "ES256"
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeFalse();
    }

    [Fact]
    public async Task VerifyAll_RoundTrips()
    {
        var gen1 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys1 = await gen1.Content.ReadFromJsonAsync<JsonObject>();
        var privPem1 = keys1!["privateKeyPem"]!.GetValue<string>();

        var gen2 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES384" });
        var keys2 = await gen2.Content.ReadFromJsonAsync<JsonObject>();
        var privPem2 = keys2!["privateKeyPem"]!.GetValue<string>();

        var document = JsonNode.Parse("""{"multi":"sig"}""")!.AsObject();

        // First signature
        var sign1 = await _client.PostAsJsonAsync("/api/sign", new
        {
            document,
            algorithm = "ES256",
            hashAlgorithm = "sha-256",
            privateKeyPem = privPem1,
            embedPublicKey = true
        });
        var res1 = await sign1.Content.ReadFromJsonAsync<JsonObject>();
        var docWith1 = res1!["document"]!.AsObject();

        // Second signature
        var sign2 = await _client.PostAsJsonAsync("/api/sign", new
        {
            document = docWith1,
            algorithm = "ES384",
            hashAlgorithm = "sha-384",
            privateKeyPem = privPem2,
            embedPublicKey = true
        });
        var res2 = await sign2.Content.ReadFromJsonAsync<JsonObject>();
        var docWith2 = res2!["document"]!.AsObject();

        // Verify all
        var verifyResponse = await _client.PostAsJsonAsync("/api/signatures/verify-all", new
        {
            document = docWith2,
            allowEmbeddedKey = true
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeTrue();
    }

    [Fact]
    public async Task Countersign_RoundTrips()
    {
        var gen1 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys1 = await gen1.Content.ReadFromJsonAsync<JsonObject>();
        var privPem1 = keys1!["privateKeyPem"]!.GetValue<string>();
        var pubPem1 = keys1["publicKeyPem"]!.GetValue<string>();

        var gen2 = await _client.PostAsJsonAsync("/api/keys/generate", new { algorithm = "ES256" });
        var keys2 = await gen2.Content.ReadFromJsonAsync<JsonObject>();
        var privPem2 = keys2!["privateKeyPem"]!.GetValue<string>();

        var document = JsonNode.Parse("""{"counter":"test"}""")!.AsObject();

        // Sign
        var sign = await _client.PostAsJsonAsync("/api/sign", new
        {
            document,
            algorithm = "ES256",
            hashAlgorithm = "sha-256",
            privateKeyPem = privPem1,
            embedPublicKey = true
        });
        var signRes = await sign.Content.ReadFromJsonAsync<JsonObject>();
        var signedDoc = signRes!["document"]!.AsObject();

        // Countersign
        var csign = await _client.PostAsJsonAsync("/api/signatures/countersign", new
        {
            document = signedDoc,
            algorithm = "ES256",
            hashAlgorithm = "sha-256",
            privateKeyPem = privPem2,
            signatureIndex = 0,
            embedPublicKey = true
        });
        csign.StatusCode.Should().Be(HttpStatusCode.OK);
        var csignRes = await csign.Content.ReadFromJsonAsync<JsonObject>();
        var csignedDoc = csignRes!["document"]!.AsObject();

        // Verify original signature still works
        var verifyResponse = await _client.PostAsJsonAsync("/api/verify", new
        {
            document = csignedDoc,
            publicKeyPem = pubPem1,
            algorithm = "ES256"
        });
        verifyResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var verifyResult = await verifyResponse.Content.ReadFromJsonAsync<JsonObject>();
        verifyResult!["isValid"]!.GetValue<bool>().Should().BeTrue();
    }
}
