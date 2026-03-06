# JSS Web Tool

A browser-based tool for generating cryptographic keys, signing JSON documents, and verifying signatures using [JSON Signature Scheme (JSS)](https://www.itu.int/rec/T-REC-X.590) as defined in ITU-T X.590 (10/2023).

Built with Blazor WebAssembly — all cryptographic operations run entirely in the browser. Your keys and documents never leave your machine.

## Running

### From source

Requires .NET 8.0 SDK or later.

```sh
dotnet run --project src/CoderPatros.Jss.Web
```

## Pages

### Generate Key

Create cryptographic key pairs for signing and verification.

- Select an algorithm from the dropdown
- Click **Generate Key** to create a new key pair
- Copy keys to clipboard or use them in the Sign and Verify pages
- Private keys are clearly labelled as secret

### Sign

Sign a JSON document with a private key.

- Select the signing algorithm and hash algorithm
- Paste a PEM private key
- Optionally embed the public key in the signature for self-contained verification
- Paste the JSON document to sign
- The signed document is displayed for copying

### Verify

Verify a signed JSON document.

- Paste the signed JSON document
- Paste the public PEM key, or enable **Allow embedded public key** to use the key from the signature
- The result shows **Valid** or **Invalid** with an error message if verification failed

## Supported algorithms

| Family | Algorithms |
|---|---|
| ECDSA | ES256, ES384, ES512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| EdDSA | Ed25519, Ed448 |

Hash algorithms: `sha-256`, `sha-384`, `sha-512`

## Privacy

This is a client-side application. All key generation, signing, and verification happens in the browser via WebAssembly. No data is sent to any server.

## License

Apache-2.0
