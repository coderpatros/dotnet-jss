# JSS CLI

A command-line tool for generating cryptographic keys, signing JSON documents, and verifying signatures using [JSON Signature Scheme (JSS)](https://www.itu.int/rec/T-REC-X.590) as defined in ITU-T X.590 (10/2023).

## Building from source

Requires .NET 8.0 SDK or later.

```sh
dotnet build src/CoderPatros.Jss.Cli
```

## Quick start

```sh
# Generate a key pair
jss-cli generate-key -a ES256

# Sign a document
jss-cli sign -a ES256 -h sha-256 -k ES256-private.pem -i document.json > signed.json

# Verify the signature
jss-cli verify -k ES256-public.pem -i signed.json
```

## Commands

### generate-key

Generate a cryptographic key pair.

```
jss-cli generate-key -a <algorithm> [-o <directory>] [-f]
```

| Option | Description |
|---|---|
| `-a, --algorithm` | **Required.** Algorithm identifier (see [supported algorithms](#supported-algorithms)) |
| `-o, --output` | Output directory for key files. Defaults to the current directory |
| `-f, --force` | Overwrite existing key files |

Two files are created:
- `{algorithm}-private.pem` — private key (created with owner-only permissions on Linux/macOS)
- `{algorithm}-public.pem` — public key

All key files use standard PEM format (PKCS#8 for private keys, SubjectPublicKeyInfo for public keys).

#### Examples

```sh
# ECDSA key pair
jss-cli generate-key -a ES256

# RSA key pair
jss-cli generate-key -a RS256

# EdDSA key pair
jss-cli generate-key -a Ed25519

# Specify output directory
jss-cli generate-key -a ES256 -o ./keys

# Overwrite existing keys
jss-cli generate-key -a ES256 -f
```

#### Generated key sizes

| Algorithm family | Key details |
|---|---|
| ES256 | ECDSA P-256 |
| ES384 | ECDSA P-384 |
| ES512 | ECDSA P-521 |
| RS256, RS384, RS512 | RSA 2048-bit |
| PS256, PS384, PS512 | RSA 2048-bit |
| Ed25519 | Ed25519 curve |
| Ed448 | Ed448 curve |

### sign

Sign a JSON document. Outputs the signed JSON to stdout.

The public key is always embedded in the signature per ITU-T X.590 clause 6.2.1, which requires at least one key identification property to be populated.

```
jss-cli sign -k <key-file> -a <algorithm> [-h <hash-algorithm>] [-i <input-file>]
```

| Option | Description |
|---|---|
| `-k, --key` | **Required.** Path to a private PEM key file |
| `-a, --algorithm` | **Required.** Signature algorithm identifier |
| `-h, --hash-algorithm` | Hash algorithm (default: `sha-256`) |
| `-i, --input` | Path to the JSON file to sign. Reads from stdin if not provided |

#### Examples

```sh
# Sign from a file
jss-cli sign -a ES256 -h sha-256 -k ES256-private.pem -i document.json

# Sign from stdin
echo '{"message":"hello"}' | jss-cli sign -a ES256 -k ES256-private.pem

# Pipe to a file
jss-cli sign -a ES256 -k ES256-private.pem -i document.json > signed.json

# Use SHA-512 hash
jss-cli sign -a ES256 -h sha-512 -k ES256-private.pem -i document.json

# Sign with RSA-PSS
jss-cli sign -a PS256 -k PS256-private.pem -i document.json

# Sign with EdDSA
jss-cli sign -a Ed25519 -k Ed25519-private.pem -i document.json
```

### verify

Verify a signed JSON document. Outputs `Valid` on success or `Invalid: <error>` on failure. Exits with code 0 for valid signatures, 1 for invalid.

```
jss-cli verify [-k <key-file>] [-a <algorithm>] [-i <input-file>] [--allow-embedded-key] [--accepted-algorithms <list>]
```

| Option | Description |
|---|---|
| `-k, --key` | Path to a public PEM key file. Optional if the signature has an embedded public key |
| `-a, --algorithm` | Algorithm hint for key parsing (required with `--key` for EdDSA keys). Auto-detected from the document if not provided |
| `-i, --input` | Path to the signed JSON file. Reads from stdin if not provided |
| `--allow-embedded-key` | Allow verification using the public key embedded in the signature |
| `--accepted-algorithms` | Comma-separated whitelist of accepted algorithm identifiers (e.g. `ES256,ES384`) |

#### Examples

```sh
# Verify with an explicit key
jss-cli verify -k ES256-public.pem -i signed.json

# Verify using the embedded public key
jss-cli verify --allow-embedded-key -i signed.json

# Verify from stdin
cat signed.json | jss-cli verify -k ES256-public.pem

# Restrict to specific algorithms
jss-cli verify -k ES256-public.pem --accepted-algorithms ES256,ES384 -i signed.json

# Verify EdDSA with algorithm hint
jss-cli verify -k Ed25519-public.pem -a Ed25519 -i signed.json
```

#### Exit codes

| Code | Meaning |
|---|---|
| 0 | Signature is valid |
| 1 | Signature is invalid, or an error occurred |

### countersign

Countersign a specific signature in a signed document. Outputs the countersigned JSON to stdout.

```
jss-cli countersign -k <key-file> -a <algorithm> [-h <hash-algorithm>] [-s <index>] [-i <input-file>] [--embed-public-key]
```

| Option | Description |
|---|---|
| `-k, --key` | **Required.** Path to a private PEM key file |
| `-a, --algorithm` | **Required.** Signature algorithm identifier |
| `-h, --hash-algorithm` | Hash algorithm (default: `sha-256`) |
| `-s, --signature-index` | Index of signature to countersign (default: `0`) |
| `-i, --input` | Path to the signed JSON file. Reads from stdin if not provided |
| `--embed-public-key` | Embed the public key in the countersignature |

#### Examples

```sh
# Countersign the first signature
jss-cli countersign -a ES256 -k ES256-private.pem -s 0 -i signed.json

# Countersign with embedded public key
jss-cli countersign -a ES256 -k ES256-private.pem -s 0 --embed-public-key -i signed.json

# Countersign from stdin
cat signed.json | jss-cli countersign -a ES256 -k ES256-private.pem -s 0
```

## Supported algorithms

| Family | Algorithms |
|---|---|
| ECDSA | ES256, ES384, ES512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| EdDSA | Ed25519, Ed448 |

Hash algorithms: `sha-256`, `sha-384`, `sha-512`

## End-to-end examples

### Sign and verify with ECDSA

```sh
jss-cli generate-key -a ES256 -o ./keys
echo '{"order":"abc123","total":99.95}' | jss-cli sign -a ES256 -k ./keys/ES256-private.pem > signed.json
jss-cli verify --allow-embedded-key -i signed.json
# Output: Valid
```

### Sign and verify with explicit key

```sh
jss-cli generate-key -a ES256 -o ./keys
echo '{"status":"approved"}' | jss-cli sign -a ES256 -k ./keys/ES256-private.pem > signed.json
jss-cli verify -k ./keys/ES256-public.pem -i signed.json
# Output: Valid
```

### Pipeline usage

```sh
# Generate, sign, and verify in a single pipeline
jss-cli generate-key -a ES256 -o ./keys
echo '{"data":"test"}' \
  | jss-cli sign -a ES256 -k ./keys/ES256-private.pem \
  | jss-cli verify --allow-embedded-key
# Output: Valid
```

### Algorithm whitelisting

```sh
# Only accept ES256 and ES384 signatures
jss-cli verify -k key.pem --accepted-algorithms ES256,ES384 -i signed.json
```

## Security notes

- Private key files are created with owner-only permissions (mode 0600) on Linux and macOS
- When using `--allow-embedded-key`, be aware that any signer can embed any public key. Only use this when you trust the source of the document
- Use `--accepted-algorithms` to restrict which algorithms you accept, preventing algorithm confusion attacks

## License

Apache-2.0
