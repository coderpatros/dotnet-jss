using Bunit;
using CoderPatros.Jss.Web.Pages;
using CoderPatros.Jss.Web.Components;
using FluentAssertions;

namespace CoderPatros.Jss.Web.Tests;

public class PageTests : TestContext
{
    [Fact]
    public void HomePage_RendersTitle()
    {
        var cut = RenderComponent<Home>();
        cut.Find("h1").TextContent.Should().Contain("JSON Signature Scheme");
    }

    [Fact]
    public void HomePage_ShowsPrivacyNote()
    {
        var cut = RenderComponent<Home>();
        cut.Find(".privacy-note").TextContent.Should().Contain("never leave your machine");
    }

    [Fact]
    public void HomePage_ShowsAlgorithmList()
    {
        var cut = RenderComponent<Home>();
        var markup = cut.Markup;
        markup.Should().Contain("ES256");
        markup.Should().Contain("RS256");
        markup.Should().Contain("Ed25519");
    }

    [Fact]
    public void HomePage_DoesNotShowHmac()
    {
        var cut = RenderComponent<Home>();
        var markup = cut.Markup;
        markup.Should().NotContain("HMAC");
        markup.Should().NotContain("HS256");
    }

    [Fact]
    public void GenerateKeyPage_RendersTitle()
    {
        var cut = RenderComponent<GenerateKey>();
        cut.Find("h1").TextContent.Should().Contain("Generate Key");
    }

    [Fact]
    public void GenerateKeyPage_HasAlgorithmSelector()
    {
        var cut = RenderComponent<GenerateKey>();
        cut.Find("select").Should().NotBeNull();
    }

    [Fact]
    public void GenerateKeyPage_HasGenerateButton()
    {
        var cut = RenderComponent<GenerateKey>();
        var button = cut.Find("button.primary");
        button.TextContent.Should().Contain("Generate Key");
    }

    [Fact]
    public void SignPage_RendersTitle()
    {
        var cut = RenderComponent<Sign>();
        cut.Find("h1").TextContent.Should().Contain("Sign a JSON Document");
    }

    [Fact]
    public void SignPage_HasSignButton()
    {
        var cut = RenderComponent<Sign>();
        var button = cut.Find("button.primary");
        button.TextContent.Should().Contain("Sign");
    }

    [Fact]
    public void SignPage_HasHashAlgorithmSelector()
    {
        var cut = RenderComponent<Sign>();
        var selects = cut.FindAll("select");
        selects.Count.Should().BeGreaterThanOrEqualTo(2); // Algorithm + Hash Algorithm
    }

    [Fact]
    public void VerifyPage_RendersTitle()
    {
        var cut = RenderComponent<Verify>();
        cut.Find("h1").TextContent.Should().Contain("Verify a Signed JSON Document");
    }

    [Fact]
    public void VerifyPage_HasVerifyButton()
    {
        var cut = RenderComponent<Verify>();
        var button = cut.Find("button.primary");
        button.TextContent.Should().Contain("Verify");
    }

    [Fact]
    public void AlgorithmSelector_RendersAllAlgorithms()
    {
        var cut = RenderComponent<AlgorithmSelector>();
        var options = cut.FindAll("option");

        // 11 algorithms + 1 placeholder (no HMAC)
        options.Count.Should().Be(12);
    }

    [Fact]
    public void AlgorithmSelector_DoesNotIncludeHmac()
    {
        var cut = RenderComponent<AlgorithmSelector>();
        cut.Markup.Should().NotContain("HS256");
        cut.Markup.Should().NotContain("HMAC");
    }

    [Fact]
    public void HashAlgorithmSelector_RendersAllOptions()
    {
        var cut = RenderComponent<HashAlgorithmSelector>();
        var options = cut.FindAll("option");
        options.Count.Should().Be(3); // sha-256, sha-384, sha-512
    }

    [Fact]
    public void ResultDisplay_WhenNotVisible_RendersNothing()
    {
        var cut = RenderComponent<ResultDisplay>(parameters => parameters
            .Add(p => p.IsVisible, false)
            .Add(p => p.IsValid, true));
        cut.Markup.Trim().Should().BeEmpty();
    }

    [Fact]
    public void ResultDisplay_WhenValid_ShowsGreen()
    {
        var cut = RenderComponent<ResultDisplay>(parameters => parameters
            .Add(p => p.IsVisible, true)
            .Add(p => p.IsValid, true));
        cut.Find(".result-valid").Should().NotBeNull();
        cut.Find(".result-valid").TextContent.Should().Contain("Valid");
    }

    [Fact]
    public void ResultDisplay_WhenInvalid_ShowsRed()
    {
        var cut = RenderComponent<ResultDisplay>(parameters => parameters
            .Add(p => p.IsVisible, true)
            .Add(p => p.IsValid, false)
            .Add(p => p.Message, "Signature mismatch"));
        cut.Find(".result-invalid").Should().NotBeNull();
        cut.Find(".result-invalid").TextContent.Should().Contain("Invalid");
        cut.Find(".result-invalid").TextContent.Should().Contain("Signature mismatch");
    }

    [Fact]
    public void KeyDisplay_WhenEmpty_RendersNothing()
    {
        var cut = RenderComponent<KeyDisplay>(parameters => parameters
            .Add(p => p.Value, ""));
        cut.Markup.Trim().Should().BeEmpty();
    }

    [Fact]
    public void KeyDisplay_WhenHasValue_ShowsContent()
    {
        var cut = RenderComponent<KeyDisplay>(parameters => parameters
            .Add(p => p.Value, "-----BEGIN PUBLIC KEY-----\nMFkwEw...")
            .Add(p => p.Label, "Test Key"));
        cut.Find(".key-display").TextContent.Should().Contain("BEGIN PUBLIC KEY");
        cut.Find("label").TextContent.Should().Contain("Test Key");
    }
}
