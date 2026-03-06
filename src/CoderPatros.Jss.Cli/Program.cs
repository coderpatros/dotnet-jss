// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.CommandLine;
using System.Text.Json.Nodes;
using CoderPatros.Jss;
using CoderPatros.Jss.Cli;
using CoderPatros.Jss.Keys;
using CoderPatros.Jss.Models;

var validAlgorithms = new[]
{
    "ES256", "ES384", "ES512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "Ed25519", "Ed448"
};

var validHashAlgorithms = new[] { "sha-256", "sha-384", "sha-512" };

// --- generate-key command ---

var genAlgorithmOption = new Option<string>("--algorithm", "-a")
{
    Description = "Algorithm identifier: " + string.Join(", ", validAlgorithms),
    Required = true
};

var genOutputOption = new Option<DirectoryInfo?>("--output", "-o")
{
    Description = "Output directory for key files (defaults to current directory)"
};

var genForceOption = new Option<bool>("--force", "-f")
{
    Description = "Overwrite existing key files"
};

var genRsaKeySizeOption = new Option<int>("--rsa-key-size")
{
    Description = "RSA key size in bits (default: 2048, minimum: 2048)",
    DefaultValueFactory = _ => 2048
};

var generateKeyCommand = new Command("generate-key", "Generate a cryptographic key pair");
generateKeyCommand.Options.Add(genAlgorithmOption);
generateKeyCommand.Options.Add(genOutputOption);
generateKeyCommand.Options.Add(genForceOption);
generateKeyCommand.Options.Add(genRsaKeySizeOption);

generateKeyCommand.SetAction(parseResult =>
{
    var algorithm = parseResult.GetValue(genAlgorithmOption)!;
    var outputDir = parseResult.GetValue(genOutputOption)
        ?? new DirectoryInfo(Directory.GetCurrentDirectory());
    var force = parseResult.GetValue(genForceOption);
    var rsaKeySize = parseResult.GetValue(genRsaKeySizeOption);

    if (!validAlgorithms.Contains(algorithm))
    {
        Console.Error.WriteLine($"Unsupported algorithm: {algorithm}");
        Console.Error.WriteLine($"Valid algorithms: {string.Join(", ", validAlgorithms)}");
        return 1;
    }

    if (!outputDir.Exists)
        outputDir.Create();

    var privatePath = Path.Combine(outputDir.FullName, $"{algorithm}-private.pem");
    var publicPath = Path.Combine(outputDir.FullName, $"{algorithm}-public.pem");
    if (!force && (File.Exists(privatePath) || File.Exists(publicPath)))
    {
        if (File.Exists(privatePath))
            Console.Error.WriteLine($"Key file already exists: {privatePath}");
        if (File.Exists(publicPath))
            Console.Error.WriteLine($"Key file already exists: {publicPath}");
        Console.Error.WriteLine("Use --force to overwrite existing key files.");
        return 1;
    }

    var (signingKey, _, publicKeyPemBody) = PemKeyHelper.GenerateKeyPair(algorithm, rsaKeySize);
    var privatePem = PemKeyHelper.ExportPrivateKeyPem(signingKey, algorithm);
    var publicPem = PemKeyHelper.ExportPublicKeyPem(publicKeyPemBody);

    PemKeyFileHelper.WriteSecretFile(privatePath, privatePem, force);
    File.WriteAllText(publicPath, publicPem);
    Console.WriteLine($"Private key written to {privatePath}");
    Console.WriteLine($"Public key written to {publicPath}");

    signingKey.Dispose();
    return 0;
});

// --- sign command ---

var signKeyOption = new Option<FileInfo>("--key", "-k")
{
    Description = "Path to private PEM key file",
    Required = true
};

var signAlgorithmOption = new Option<string>("--algorithm", "-a")
{
    Description = "Signing algorithm identifier",
    Required = true
};

var signHashAlgorithmOption = new Option<string>("--hash-algorithm", "-h")
{
    Description = "Hash algorithm (default: sha-256)",
    DefaultValueFactory = _ => "sha-256"
};

var embedPublicKeyOption = new Option<bool>("--embed-public-key")
{
    Description = "Embed public key in signature"
};

var signInputOption = new Option<FileInfo?>("--input", "-i")
{
    Description = "Path to JSON file (defaults to stdin)"
};

var signCommand = new Command("sign", "Sign a JSON document");
signCommand.Options.Add(signKeyOption);
signCommand.Options.Add(signAlgorithmOption);
signCommand.Options.Add(signHashAlgorithmOption);
signCommand.Options.Add(embedPublicKeyOption);
signCommand.Options.Add(signInputOption);

signCommand.SetAction(parseResult =>
{
    var keyFile = parseResult.GetValue(signKeyOption)!;
    var algorithm = parseResult.GetValue(signAlgorithmOption)!;
    var hashAlgorithm = parseResult.GetValue(signHashAlgorithmOption)!;
    var embedPublicKey = parseResult.GetValue(embedPublicKeyOption);
    var inputFile = parseResult.GetValue(signInputOption);

    if (!validAlgorithms.Contains(algorithm))
    {
        Console.Error.WriteLine($"Unsupported algorithm: {algorithm}");
        return 1;
    }

    if (!validHashAlgorithms.Contains(hashAlgorithm))
    {
        Console.Error.WriteLine($"Unsupported hash algorithm: {hashAlgorithm}");
        return 1;
    }

    if (!keyFile.Exists)
    {
        Console.Error.WriteLine($"Key file not found: {keyFile.FullName}");
        return 1;
    }

    var pem = File.ReadAllText(keyFile.FullName);
    using var signingKey = PemKeyHelper.ImportPrivateKeyPem(pem, algorithm);

    string jsonInput;
    if (inputFile is not null)
    {
        if (!inputFile.Exists)
        {
            Console.Error.WriteLine($"Input file not found: {inputFile.FullName}");
            return 1;
        }
        jsonInput = File.ReadAllText(inputFile.FullName);
    }
    else
    {
        jsonInput = Console.In.ReadToEnd();
    }

    // ITU-T X.590 clause 6.2.1: at least one key identification property MUST be populated.
    // Always embed the public key derived from the signing key.
    var publicKeyPemBody = PemKeyHelper.ExportPublicKeyPemBody(signingKey, algorithm);
    if (publicKeyPemBody is null)
    {
        Console.Error.WriteLine("Cannot extract public key from key file.");
        return 1;
    }

    var options = new SignatureOptions
    {
        Algorithm = algorithm,
        HashAlgorithm = hashAlgorithm,
        Key = signingKey,
        PublicKey = publicKeyPemBody
    };

    var service = new JssSignatureService();
    var signedJson = service.Sign(jsonInput, options);
    Console.WriteLine(signedJson);
    return 0;
});

// --- verify command ---

var verifyKeyOption = new Option<FileInfo?>("--key", "-k")
{
    Description = "Path to public PEM key file"
};

var verifyAlgorithmOption = new Option<string?>("--algorithm", "-a")
{
    Description = "Algorithm hint for key parsing (required with --key for EdDSA keys)"
};

var allowEmbeddedKeyOption = new Option<bool>("--allow-embedded-key")
{
    Description = "Allow verification using the public key embedded in the signature"
};

var acceptedAlgorithmsOption = new Option<string?>("--accepted-algorithms")
{
    Description = "Comma-separated list of accepted algorithm identifiers"
};

var verifyInputOption = new Option<FileInfo?>("--input", "-i")
{
    Description = "Path to signed JSON file (defaults to stdin)"
};

var verifyCommand = new Command("verify", "Verify a signed JSON document");
verifyCommand.Options.Add(verifyKeyOption);
verifyCommand.Options.Add(verifyAlgorithmOption);
verifyCommand.Options.Add(allowEmbeddedKeyOption);
verifyCommand.Options.Add(acceptedAlgorithmsOption);
verifyCommand.Options.Add(verifyInputOption);

verifyCommand.SetAction(parseResult =>
{
    var keyFile = parseResult.GetValue(verifyKeyOption);
    var algorithmHint = parseResult.GetValue(verifyAlgorithmOption);
    var allowEmbeddedKey = parseResult.GetValue(allowEmbeddedKeyOption);
    var acceptedAlgorithmsValue = parseResult.GetValue(acceptedAlgorithmsOption);
    var inputFile = parseResult.GetValue(verifyInputOption);

    string jsonInput;
    if (inputFile is not null)
    {
        if (!inputFile.Exists)
        {
            Console.Error.WriteLine($"Input file not found: {inputFile.FullName}");
            return 1;
        }
        jsonInput = File.ReadAllText(inputFile.FullName);
    }
    else
    {
        jsonInput = Console.In.ReadToEnd();
    }

    IReadOnlySet<string>? acceptedAlgorithms = null;
    if (acceptedAlgorithmsValue is not null)
    {
        var parsed = acceptedAlgorithmsValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        acceptedAlgorithms = new HashSet<string>(parsed, StringComparer.Ordinal);
    }

    VerificationKey? verificationKey = null;
    if (keyFile is not null)
    {
        if (!keyFile.Exists)
        {
            Console.Error.WriteLine($"Key file not found: {keyFile.FullName}");
            return 1;
        }
        var pem = File.ReadAllText(keyFile.FullName);

        // Determine algorithm from the document if not provided
        var alg = algorithmHint;
        if (alg is null)
        {
            var doc = JsonNode.Parse(jsonInput)?.AsObject();
            if (doc?["signatures"] is JsonArray sigArr && sigArr.Count > 0)
                alg = sigArr[sigArr.Count - 1]!.AsObject()["algorithm"]?.GetValue<string>();
        }

        alg ??= "ES256"; // fallback
        verificationKey = PemKeyHelper.ImportPublicKeyPem(pem, alg);
    }

    using (verificationKey)
    {
        var verificationOptions = new VerificationOptions
        {
            AllowEmbeddedPublicKey = allowEmbeddedKey,
            AcceptedAlgorithms = acceptedAlgorithms,
            Key = verificationKey
        };

        var doc = JsonNode.Parse(jsonInput)?.AsObject();
        if (doc is null)
        {
            Console.WriteLine("Invalid: Input is not a valid JSON object.");
            return 1;
        }

        var service = new JssSignatureService();
        var result = service.Verify(doc, verificationOptions);

        if (result.IsValid)
        {
            Console.WriteLine("Valid");
            return 0;
        }
        else
        {
            Console.WriteLine($"Invalid: {result.Error}");
            return 1;
        }
    }
});

// --- countersign command ---

var csKeyOption = new Option<FileInfo>("--key", "-k")
{
    Description = "Path to private PEM key file",
    Required = true
};

var csAlgorithmOption = new Option<string>("--algorithm", "-a")
{
    Description = "Signing algorithm identifier",
    Required = true
};

var csHashAlgorithmOption = new Option<string>("--hash-algorithm", "-h")
{
    Description = "Hash algorithm (default: sha-256)",
    DefaultValueFactory = _ => "sha-256"
};

var csIndexOption = new Option<int>("--signature-index", "-s")
{
    Description = "Index of signature to countersign (default: 0)",
    DefaultValueFactory = _ => 0
};

var csInputOption = new Option<FileInfo?>("--input", "-i")
{
    Description = "Path to signed JSON file (defaults to stdin)"
};

var csEmbedPublicKeyOption = new Option<bool>("--embed-public-key")
{
    Description = "Embed public key in countersignature"
};

var countersignCommand = new Command("countersign", "Countersign a specific signature in a signed document");
countersignCommand.Options.Add(csKeyOption);
countersignCommand.Options.Add(csAlgorithmOption);
countersignCommand.Options.Add(csHashAlgorithmOption);
countersignCommand.Options.Add(csIndexOption);
countersignCommand.Options.Add(csInputOption);
countersignCommand.Options.Add(csEmbedPublicKeyOption);

countersignCommand.SetAction(parseResult =>
{
    var keyFile = parseResult.GetValue(csKeyOption)!;
    var algorithm = parseResult.GetValue(csAlgorithmOption)!;
    var hashAlgorithm = parseResult.GetValue(csHashAlgorithmOption)!;
    var signatureIndex = parseResult.GetValue(csIndexOption);
    var inputFile = parseResult.GetValue(csInputOption);
    var embedPublicKey = parseResult.GetValue(csEmbedPublicKeyOption);

    if (!keyFile.Exists)
    {
        Console.Error.WriteLine($"Key file not found: {keyFile.FullName}");
        return 1;
    }

    var pem = File.ReadAllText(keyFile.FullName);
    using var signingKey = PemKeyHelper.ImportPrivateKeyPem(pem, algorithm);

    string jsonInput;
    if (inputFile is not null)
    {
        if (!inputFile.Exists)
        {
            Console.Error.WriteLine($"Input file not found: {inputFile.FullName}");
            return 1;
        }
        jsonInput = File.ReadAllText(inputFile.FullName);
    }
    else
    {
        jsonInput = Console.In.ReadToEnd();
    }

    var doc = JsonNode.Parse(jsonInput)?.AsObject()
        ?? throw new JssException("Input is not a valid JSON object.");

    var csOptions = new CountersignOptions
    {
        Algorithm = algorithm,
        HashAlgorithm = hashAlgorithm,
        Key = signingKey,
        SignatureIndex = signatureIndex
    };

    if (embedPublicKey)
    {
        var publicKeyPemBody = PemKeyHelper.ExportPublicKeyPemBody(signingKey, algorithm);
        csOptions = csOptions with { PublicKey = publicKeyPemBody };
    }

    var service = new JssSignatureService();
    var result = service.Countersign(doc, csOptions);
    Console.WriteLine(result.ToJsonString());
    return 0;
});

// --- Root command ---

const string banner = """

┌──────────────────────────────────────────────────────────────────────────────┐
│                                                                              │
│      ██╗██████╗██████╗    █████╗██╗    ██╗   ████████╗ █████╗  █████╗ ██╗    │
│      ██║██╔═══╝██╔═══╝   ██╔═══╝██║    ██║   ╚══██╔══╝██╔══██╗██╔══██╗██║    │
│      ██║██████╗██████╗   ██║    ██║    ██║      ██║   ██║  ██║██║  ██║██║    │
│ ██   ██║╚═══██║╚═══██║   ██║    ██║    ██║      ██║   ██║  ██║██║  ██║██║    │
│ ╚█████╔╝██████║██████║   ╚█████╗██████╗██║      ██║   ╚█████╔╝╚█████╔╝██████╗│
│  ╚════╝╚══════╝╚═════╝    ╚════╝╚═════╝╚═╝      ╚═╝    ╚════╝  ╚════╝ ╚═════╝│
│                                                                              │
│               JSON Signature Scheme  -  ITU-T X.590 (10/2023)                │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                         -=[ GREETiNGS GO OUT TO ]=-                          │
│                                                                              │
│   cyberphone  ...  IETF  ...  ITU-T  ...  ECMA  ...  OWASP  ...  CycloneDX   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘

""";

var rootCommand = new RootCommand("JSS CLI - JSON Signature Scheme tool (ITU-T X.590)");
rootCommand.Subcommands.Add(generateKeyCommand);
rootCommand.Subcommands.Add(signCommand);
rootCommand.Subcommands.Add(verifyCommand);
rootCommand.Subcommands.Add(countersignCommand);

if (args.Length == 0 || (args.Length == 1 && args[0] is "--help" or "-?" or "-h"))
    Console.WriteLine(banner);

return rootCommand.Parse(args.Length == 0 ? ["--help"] : args).Invoke();
