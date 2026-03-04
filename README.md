# dotnet-jss

A .NET implementation of **JSON Signature Scheme (JSS)** as defined in [ITU-T X.590 (10/2023)](https://www.itu.int/rec/T-REC-X.590).

JSS provides a method for digitally signing JSON objects while keeping them in JSON format. It uses [JSON Canonicalization Scheme (JCS/RFC 8785)](https://datatracker.ietf.org/doc/html/rfc8785) for deterministic serialization and a two-step hash-then-sign process.

## Features

- Sign JSON documents with multiple signature algorithms
- Multiple independent signatures per document
- Countersignatures (nested signatures on existing signatures)
- Embedded public keys (PEM SubjectPublicKeyInfo format)
- X.509 certificate chain support
- Verify signatures with explicit keys or embedded public keys
- Core library, CLI tool, REST API, and Blazor WebAssembly app

## Supported Algorithms

| Family | Algorithms |
|---|---|
| ECDSA | ES256, ES384, ES512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| EdDSA | Ed25519, Ed448 |

Hash algorithms: `sha-256`, `sha-384`, `sha-512`

## Quick Start

### Library

```csharp
using CoderPatros.Jss;
using CoderPatros.Jss.Keys;
using CoderPatros.Jss.Models;
using System.Text.Json.Nodes;

// Generate a key pair
var (signingKey, verificationKey, publicKeyPemBody) = PemKeyHelper.GenerateKeyPair("ES256");

// Sign a document
var service = new JssSignatureService();
var doc = new JsonObject { ["message"] = "Hello, world!" };

var signed = service.Sign(doc, new SignatureOptions
{
    Algorithm = "ES256",
    HashAlgorithm = "sha-256",
    Key = signingKey,
    PublicKey = publicKeyPemBody
});

// Verify
var result = service.Verify(signed, new VerificationOptions
{
    AllowEmbeddedPublicKey = true
});
Console.WriteLine(result.IsValid); // True

signingKey.Dispose();
verificationKey.Dispose();
```

### CLI

```bash
# Generate a key pair
dotnet run --project src/CoderPatros.Jss.Cli -- generate-key -a ES256 -o ./keys

# Sign a document
dotnet run --project src/CoderPatros.Jss.Cli -- sign -a ES256 -h sha-256 -k ./keys/ES256-private.pem -i document.json

# Verify a signed document
dotnet run --project src/CoderPatros.Jss.Cli -- verify -k ./keys/ES256-public.pem -i signed.json

# Countersign
dotnet run --project src/CoderPatros.Jss.Cli -- countersign -a ES256 -h sha-256 -k ./keys/ES256-private.pem -s 0 -i signed.json
```

### REST API

```bash
dotnet run --project src/CoderPatros.Jss.Api
# Visit http://localhost:5000/swagger for API docs
```

Endpoints:
- `POST /api/keys/generate` — Generate a key pair
- `POST /api/sign` — Sign a JSON document
- `POST /api/verify` — Verify a signature
- `POST /api/signatures/verify-all` — Verify all signatures
- `POST /api/signatures/countersign` — Countersign a signature

### Web App

```bash
dotnet run --project src/CoderPatros.Jss.Web
```

All cryptographic operations run entirely in the browser via WebAssembly.

## How JSS Signing Works

1. **Prepare**: Clone the document, remove any existing `signatures` array
2. **Build signature object**: Create a JSON object with `algorithm`, `hash_algorithm`, and optionally `public_key`
3. **Add to document**: Place the signature object as the sole entry in a `signatures` array
4. **Canonicalize**: Apply JCS (RFC 8785) to the entire document
5. **Hash**: Compute the hash using the specified `hash_algorithm`
6. **Sign**: Sign the hash with the private key, base64url-encode the result as `value`
7. **Reassemble**: Place existing signatures at the start of the array, new signature at the end

## Building

```bash
dotnet build
dotnet test
```

## License

Apache-2.0
