using System.Diagnostics;
using System.Text.Json.Nodes;
using FluentAssertions;

namespace CoderPatros.Jss.Cli.Tests;

public class CliIntegrationTests : IDisposable
{
    private readonly string _tempDir;
    private static readonly string ProjectPath = Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "CoderPatros.Jss.Cli", "CoderPatros.Jss.Cli.csproj"));

    public CliIntegrationTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"jss-cli-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, recursive: true);
    }

    private static (int ExitCode, string StdOut, string StdErr) RunCli(string args, int timeoutMs = 60000)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"run --project \"{ProjectPath}\" -- {args}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi)!;
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit(timeoutMs);

        return (process.ExitCode, stdout.Trim(), stderr.Trim());
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("Ed25519")]
    public void GenerateKey_CreatesExpectedFiles(string algorithm)
    {
        var (exitCode, _, _) = RunCli($"generate-key -a {algorithm} -o \"{_tempDir}\"");

        exitCode.Should().Be(0);

        var privateFile = Path.Combine(_tempDir, $"{algorithm}-private.pem");
        var publicFile = Path.Combine(_tempDir, $"{algorithm}-public.pem");
        File.Exists(privateFile).Should().BeTrue();
        File.Exists(publicFile).Should().BeTrue();
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("Ed25519")]
    public void SignAndVerify_RoundTrip(string algorithm)
    {
        // Generate key
        RunCli($"generate-key -a {algorithm} -o \"{_tempDir}\"");

        // Prepare input JSON
        var inputFile = Path.Combine(_tempDir, "input.json");
        File.WriteAllText(inputFile, """{"test":"data"}""");

        // Sign
        var keyForSign = Path.Combine(_tempDir, $"{algorithm}-private.pem");
        var signedFile = Path.Combine(_tempDir, "signed.json");

        var (signExit, signedOutput, _) = RunCli(
            $"sign -a {algorithm} -h sha-256 -k \"{keyForSign}\" -i \"{inputFile}\"");
        signExit.Should().Be(0);
        File.WriteAllText(signedFile, signedOutput);

        // Verify
        var keyForVerify = Path.Combine(_tempDir, $"{algorithm}-public.pem");

        var (verifyExit, verifyOutput, _) = RunCli(
            $"verify -k \"{keyForVerify}\" -i \"{signedFile}\"");
        verifyExit.Should().Be(0);
        verifyOutput.Should().Contain("Valid");
    }

    [Fact]
    public void SignWithEmbeddedPublicKey_VerifyWithoutExplicitKey()
    {
        var algorithm = "ES256";

        RunCli($"generate-key -a {algorithm} -o \"{_tempDir}\"");

        var inputFile = Path.Combine(_tempDir, "input.json");
        File.WriteAllText(inputFile, """{"test":"embedded"}""");

        var keyForSign = Path.Combine(_tempDir, $"{algorithm}-private.pem");
        var (signExit, signedOutput, _) = RunCli(
            $"sign -a {algorithm} -h sha-256 -k \"{keyForSign}\" --embed-public-key -i \"{inputFile}\"");
        signExit.Should().Be(0);

        var signedFile = Path.Combine(_tempDir, "signed.json");
        File.WriteAllText(signedFile, signedOutput);

        // Verify with --allow-embedded-key (uses embedded public key)
        var (verifyExit, verifyOutput, _) = RunCli($"verify --allow-embedded-key -i \"{signedFile}\"");
        verifyExit.Should().Be(0);
        verifyOutput.Should().Contain("Valid");
    }

    [Fact]
    public void Verify_TamperedDocument_ReturnsInvalid()
    {
        var algorithm = "ES256";

        RunCli($"generate-key -a {algorithm} -o \"{_tempDir}\"");

        var inputFile = Path.Combine(_tempDir, "input.json");
        File.WriteAllText(inputFile, """{"test":"original"}""");

        var keyForSign = Path.Combine(_tempDir, $"{algorithm}-private.pem");
        var (signExit, signedOutput, _) = RunCli(
            $"sign -a {algorithm} -h sha-256 -k \"{keyForSign}\" -i \"{inputFile}\"");
        signExit.Should().Be(0);

        // Tamper with the signed document
        var doc = JsonNode.Parse(signedOutput)!.AsObject();
        doc["test"] = "tampered";
        var tamperedFile = Path.Combine(_tempDir, "tampered.json");
        File.WriteAllText(tamperedFile, doc.ToJsonString());

        var keyForVerify = Path.Combine(_tempDir, $"{algorithm}-public.pem");
        var (verifyExit, verifyOutput, _) = RunCli(
            $"verify -k \"{keyForVerify}\" -i \"{tamperedFile}\"");
        verifyExit.Should().Be(1);
        verifyOutput.Should().Contain("Invalid");
    }
}
