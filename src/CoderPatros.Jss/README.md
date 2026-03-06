# CoderPatros.Jss Library

A .NET library for signing and verifying JSON documents using [JSON Signature Scheme (JSS)](https://www.itu.int/rec/T-REC-X.590) as defined in ITU-T X.590 (10/2023), with [JSON Canonicalization Scheme (JCS/RFC 8785)](https://datatracker.ietf.org/doc/html/rfc8785).

## Installation

Requires .NET 8.0 or later.

## Quick start

```csharp
using CoderPatros.Jss;
using CoderPatros.Jss.Keys;
using CoderPatros.Jss.Models;
using System.Text.Json.Nodes;

var service = new JssSignatureService();

// Generate a key pair
var (signingKey, verificationKey, publicKeyPemBody) = PemKeyHelper.GenerateKeyPair("ES256");

// Sign a document
var document = new JsonObject { ["message"] = "hello" };
var signed = service.Sign(document, new SignatureOptions
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

## API reference

### JssSignatureService

The main entry point for all operations. Optionally accepts custom `SignatureAlgorithmRegistry` and `HashAlgorithmRegistry` instances.

```csharp
var service = new JssSignatureService();
// or with custom registries:
var service = new JssSignatureService(signatureRegistry, hashRegistry);
```

#### Signing methods

| Method | Description |
|---|---|
| `Sign(JsonObject, SignatureOptions)` | Sign a document, returns a new `JsonObject` with the signature appended to the `signatures` array |
| `Sign(string, SignatureOptions)` | Sign a JSON string, returns the signed JSON string |
| `Countersign(JsonObject, CountersignOptions)` | Add a countersignature to an existing signature |

All signing methods are non-mutating and return new documents.

#### Verification methods

| Method | Description |
|---|---|
| `Verify(JsonObject, VerificationOptions, int?)` | Verify a specific signature (default: last one) |
| `Verify(string, VerificationOptions, int?)` | Verify a specific signature from a JSON string |
| `VerifyAll(JsonObject, VerificationOptions)` | Verify all signatures in the document |
| `VerifyCountersignature(JsonObject, VerificationOptions, int)` | Verify the countersignature on a specific signature |

All verification methods return a `VerificationResult` with `IsValid` and an optional `Error` message.

### SignatureOptions

Configuration for signing operations.

```csharp
new SignatureOptions
{
    Algorithm = "ES256",                     // Required: signature algorithm identifier
    HashAlgorithm = "sha-256",              // Required: hash algorithm identifier
    Key = signingKey,                        // Required: signing key
    PublicKey = publicKeyPemBody,            // Optional: PEM body of public key to embed
    PublicCertChain = new[] { "..." },       // Optional: X.509 certificate chain
    CertUrl = "https://...",                 // Optional: URL to retrieve certificate
    Thumbprint = "...",                      // Optional: certificate thumbprint
    Metadata = new Dictionary<string, JsonNode?>  // Optional: additional metadata properties
    {
        ["custom"] = "value"
    }
}
```

### CountersignOptions

Configuration for countersigning operations.

```csharp
new CountersignOptions
{
    Algorithm = "ES256",                     // Required: signature algorithm identifier
    HashAlgorithm = "sha-256",              // Required: hash algorithm identifier
    Key = signingKey,                        // Required: signing key
    SignatureIndex = 0,                      // Index of signature to countersign (default: 0)
    PublicKey = publicKeyPemBody,            // Optional: PEM body of public key to embed
    PublicCertChain = new[] { "..." },       // Optional: X.509 certificate chain
    CertUrl = "https://...",                 // Optional: URL to retrieve certificate
    Thumbprint = "...",                      // Optional: certificate thumbprint
}
```

### VerificationOptions

Configuration for verification operations.

```csharp
new VerificationOptions
{
    Key = verificationKey,                   // Optional: explicit verification key
    KeyResolver = sig => ResolveKey(sig),    // Optional: resolve key per signature
    AllowEmbeddedPublicKey = false,          // Optional: allow using embedded public key (default: false)
    AcceptedAlgorithms = new HashSet<string> // Optional: whitelist of accepted algorithms
    {
        "ES256", "ES384"
    }
}
```

When `AllowEmbeddedPublicKey` is `true`, signatures containing an embedded public key can be verified without providing an explicit key. Only enable this when you trust the source of the document, as an attacker can embed any public key in a signature they create.

### VerificationResult

```csharp
var result = service.Verify(signed, options);
if (result.IsValid)
{
    // Signature is valid
}
else
{
    Console.WriteLine(result.Error); // Description of what failed
}
```

## Key management

### Generating key pairs

```csharp
// Generate a key pair for any supported algorithm
var (signingKey, verificationKey, publicKeyPemBody) = PemKeyHelper.GenerateKeyPair("ES256");
```

### Creating keys from .NET types

```csharp
// ECDSA
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var signingKey = SigningKey.FromECDsa(ecdsa);
var verificationKey = VerificationKey.FromECDsa(ecdsa);

// RSA
using var rsa = RSA.Create(2048);
var rsaSigningKey = SigningKey.FromRsa(rsa);
var rsaVerificationKey = VerificationKey.FromRsa(rsa);

// EdDSA (raw key bytes)
var edSigningKey = SigningKey.FromEdDsa(privateKeyBytes, "Ed25519");
var edVerificationKey = VerificationKey.FromEdDsa(publicKeyBytes, "Ed25519");
```

Both `SigningKey` and `VerificationKey` implement `IDisposable`. Always use `using` statements or explicitly dispose keys when finished.

### Embedded public keys

JSS uses PEM body format (base64 SubjectPublicKeyInfo without header/footer lines) for embedded public keys.

```csharp
// Export a public key PEM body from a .NET key
var pemBody = PemKeyHelper.ExportPublicKeyPemBody(ecdsa);

// Embed in signature
var signed = service.Sign(document, new SignatureOptions
{
    Algorithm = "ES256",
    HashAlgorithm = "sha-256",
    Key = signingKey,
    PublicKey = pemBody
});

// Verify using the embedded key
var result = service.Verify(signed, new VerificationOptions
{
    AllowEmbeddedPublicKey = true
});
```

### PEM import/export

```csharp
// Import keys from PEM files
var signingKey = PemKeyHelper.ImportPrivateKeyPem(pemString, "ES256");
var verificationKey = PemKeyHelper.ImportPublicKeyPem(pemString, "ES256");

// Export keys to PEM format
var privatePem = PemKeyHelper.ExportPrivateKeyPem(signingKey, "ES256");
var publicPem = PemKeyHelper.ExportPublicKeyPem(publicKeyPemBody);
```

## Supported algorithms

| Family | Algorithms | Key type |
|---|---|---|
| ECDSA | ES256, ES384, ES512 | ECDsa (P-256, P-384, P-521) |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 | RSA |
| RSA-PSS | PS256, PS384, PS512 | RSA |
| EdDSA | Ed25519, Ed448 | Raw bytes (via BouncyCastle) |

Hash algorithms: `sha-256`, `sha-384`, `sha-512`

## Multiple signatures

Multiple parties can independently sign a document. Each signature is appended to the `signatures` array.

```csharp
var doc = new JsonObject { ["message"] = "hello" };

// First signer
var withSigner1 = service.Sign(doc, new SignatureOptions
{
    Algorithm = "ES256",
    HashAlgorithm = "sha-256",
    Key = signer1Key,
    PublicKey = signer1PublicKeyPemBody
});

// Second signer adds their signature
var withBoth = service.Sign(withSigner1, new SignatureOptions
{
    Algorithm = "RS256",
    HashAlgorithm = "sha-256",
    Key = signer2Key,
    PublicKey = signer2PublicKeyPemBody
});

// Verify all signatures
var result = service.VerifyAll(withBoth, new VerificationOptions
{
    AllowEmbeddedPublicKey = true
});
```

## Countersignatures

A countersignature is a signature on an existing signature, providing a way to endorse or timestamp a signature.

```csharp
// Countersign the first signature (index 0)
var countersigned = service.Countersign(signed, new CountersignOptions
{
    Algorithm = "ES256",
    HashAlgorithm = "sha-256",
    Key = countersignerKey,
    SignatureIndex = 0,
    PublicKey = countersignerPublicKeyPemBody
});

// Verify the countersignature
var result = service.VerifyCountersignature(countersigned, new VerificationOptions
{
    AllowEmbeddedPublicKey = true
});
```

## Algorithm whitelisting

Restrict which algorithms are accepted during verification to prevent algorithm confusion attacks.

```csharp
var result = service.Verify(signed, new VerificationOptions
{
    Key = verificationKey,
    AcceptedAlgorithms = new HashSet<string> { "ES256", "ES384" }
});
```

## How JSS signing works

1. A copy of the document is made and any existing `signatures` array is removed
2. A signature object is created with `algorithm`, `hash_algorithm`, and optionally `public_key` — but no `value` yet
3. The signature object is placed as the sole entry in a `signatures` array on the document
4. The entire document is canonicalized using JCS (RFC 8785)
5. The canonical bytes are hashed using the specified `hash_algorithm`
6. The hash is signed with the private key and the base64url-encoded result is set as `value`
7. The original signatures are restored at the start of the array, with the new signature appended at the end

Verification reverses the process: remove `value`, rebuild the document with just that signature, canonicalize, hash, and verify.

## Exceptions

| Exception | Description |
|---|---|
| `JssException` | Base exception for all JSS operations |

## License

Apache-2.0
