# JSON Signature Scheme CLI tool, web tool, API server, and Library for .NET

A .NET implementation of **JSON Signature Scheme (JSS)** as defined in [ITU-T X.590 (10/2023)](https://www.itu.int/rec/T-REC-X.590) — a method for digitally signing JSON objects while keeping them in JSON format.

JSS embeds cryptographic signatures directly within JSON objects, using [JSON Canonicalization Scheme (JCS/RFC 8785)](https://datatracker.ietf.org/doc/html/rfc8785) for deterministic serialization and a two-step hash-then-sign process. Unlike JWS/JWT where signatures are separate from the data, JSS keeps signature and payload together in a single JSON structure.

## Features

- **Single signatures**, **multiple independent signatures**, and **countersignatures** (nested signatures on existing signatures)
- **12 algorithms**: ECDSA (ES256/384/512), RSA PKCS#1 v1.5 (RS256/384/512), RSA-PSS (PS256/384/512), EdDSA (Ed25519/Ed448)
- Embedded public keys (PEM SubjectPublicKeyInfo format)
- X.509 certificate chain support
- Non-mutating — all operations return new documents
- Accepts both `JsonObject` and `string` inputs

## Requirements

- .NET 8.0+

## Projects

| Project | Description | Details |
|---|---|---|
| [CoderPatros.Jss](src/CoderPatros.Jss/README.md) | .NET library for signing and verifying JSON documents | [Library README](src/CoderPatros.Jss/README.md) |
| [CoderPatros.Jss.Cli](src/CoderPatros.Jss.Cli/README.md) | Command-line tool for key generation, signing, and verification | [CLI README](src/CoderPatros.Jss.Cli/README.md) |
| [CoderPatros.Jss.Api](src/CoderPatros.Jss.Api/README.md) | REST API for key generation, signing, and verification | [API README](src/CoderPatros.Jss.Api/README.md) |
| [CoderPatros.Jss.Web](src/CoderPatros.Jss.Web/README.md) | Browser-based tool for key generation, signing, and verification | [Web README](src/CoderPatros.Jss.Web/README.md) |

## Quick start — Library

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

See the [Library README](src/CoderPatros.Jss/README.md) for the full API reference, countersignatures, key management, and more.

## Quick start — CLI

Build from source:

```sh
dotnet build src/CoderPatros.Jss.Cli
```

Generate keys, sign, and verify:

```sh
# Generate an ECDSA key pair
jss-cli generate-key -a ES256

# Sign a document
jss-cli sign -a ES256 -h sha-256 -k ES256-private.pem -i document.json > signed.json

# Verify the signature
jss-cli verify -k ES256-public.pem -i signed.json
# Output: Valid
```

The CLI also supports stdin/stdout piping, countersigning, embedded public keys, and algorithm whitelisting. See the [CLI README](src/CoderPatros.Jss.Cli/README.md) for the full command reference.

## Quick start — API

Run the API server from source:

```sh
dotnet run --project src/CoderPatros.Jss.Api
```

Or with Docker:

```sh
./src/CoderPatros.Jss.Api/docker-run.sh
```

Generate keys, sign, and verify with curl:

```sh
# Generate an ECDSA key pair
curl -s -X POST http://localhost:5000/api/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"ES256"}'

# Sign a document (use privateKeyPem and algorithm from the generate response)
curl -s -X POST http://localhost:5000/api/sign \
  -H "Content-Type: application/json" \
  -d '{"document":{"message":"hello"},"algorithm":"ES256","hashAlgorithm":"sha-256","privateKeyPem":"..."}'

# Verify the signature
curl -s -X POST http://localhost:5000/api/verify \
  -H "Content-Type: application/json" \
  -d '{"document":{...},"allowEmbeddedKey":true}'
# Output: {"isValid":true,"error":null}
```

The API also supports countersigning and verifying all signatures. See the [API README](src/CoderPatros.Jss.Api/README.md) for the full endpoint reference.

## Quick start — Web

Run the web tool locally:

```sh
dotnet run --project src/CoderPatros.Jss.Web
```

Or with Docker:

```sh
./src/CoderPatros.Jss.Web/docker-run.sh
```

Open the app in your browser to generate keys, sign documents, and verify signatures. All cryptographic operations run entirely in the browser — your keys and documents never leave your machine. See the [Web README](src/CoderPatros.Jss.Web/README.md) for more details.

## How JSS signing works

1. A copy of the document is made and any existing `signatures` array is removed
2. A signature object is created with `algorithm`, `hash_algorithm`, and optionally `public_key` — but no `value` yet
3. The signature object is placed as the sole entry in a `signatures` array on the document
4. The entire document is canonicalized using JCS (RFC 8785)
5. The canonical bytes are hashed using the specified `hash_algorithm`
6. The hash is signed with the private key and the base64url-encoded result is set as `value`
7. The original signatures are restored at the start of the array, with the new signature appended at the end

Verification reverses the process: remove `value`, rebuild the document with just that signature, canonicalize, hash, and verify.

## Running tests

```sh
dotnet test
```

## License

Apache-2.0
