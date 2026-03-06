# JSS API

A REST API for generating cryptographic keys, signing JSON documents, and verifying signatures using [JSON Signature Scheme (JSS)](https://www.itu.int/rec/T-REC-X.590) as defined in ITU-T X.590 (10/2023).

## Running

### From source

Requires .NET 8.0 SDK or later.

```sh
dotnet run --project src/CoderPatros.Jss.Api
```

The API starts on `http://localhost:5000` by default. Browse to `http://localhost:5000/swagger` for the interactive Swagger UI.

### With Docker

Build and run using the provided script:

```sh
./src/CoderPatros.Jss.Api/docker-run.sh
```

This builds the Docker image and runs the API on `http://localhost:8080`. Browse to `http://localhost:8080/swagger` for the interactive Swagger UI.

Or build and run manually from the repository root:

```sh
docker build -f src/CoderPatros.Jss.Api/Dockerfile -t coderpatros-jss-api .
docker run --rm -p 8080:8080 coderpatros-jss-api
```

## Endpoints

### POST /api/keys/generate

Generate a cryptographic key pair.

**Request:**

```json
{
  "algorithm": "ES256"
}
```

**Response:**

```json
{
  "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "publicKeyPemBody": "MFkwEwYH..."
}
```

### POST /api/sign

Sign a JSON document. The public key is always embedded in the signature per ITU-T X.590 clause 6.2.1.

**Request:**

```json
{
  "document": { "message": "hello" },
  "algorithm": "ES256",
  "hashAlgorithm": "sha-256",
  "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
}
```

| Field | Required | Description |
|---|---|---|
| `document` | Yes | The JSON object to sign |
| `algorithm` | Yes | Signature algorithm identifier (see [supported algorithms](#supported-algorithms)) |
| `hashAlgorithm` | Yes | Hash algorithm identifier (`sha-256`, `sha-384`, `sha-512`) |
| `privateKeyPem` | Yes | Private key in PEM format |

**Response:**

```json
{
  "document": {
    "message": "hello",
    "signatures": [{ "algorithm": "ES256", "hash_algorithm": "sha-256", "public_key": "...", "value": "..." }]
  }
}
```

### POST /api/verify

Verify a signed JSON document.

**Request:**

```json
{
  "document": { "message": "hello", "signatures": [{ "algorithm": "ES256", "hash_algorithm": "sha-256", "value": "..." }] },
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "allowEmbeddedKey": false,
  "acceptedAlgorithms": ["ES256", "ES384"]
}
```

| Field | Required | Description |
|---|---|---|
| `document` | Yes | The signed JSON object to verify |
| `publicKeyPem` | No | Public key in PEM format. Optional if using an embedded key |
| `algorithm` | No | Algorithm hint for key parsing (auto-detected from document if not provided) |
| `allowEmbeddedKey` | No | Allow verification using the public key embedded in the signature (default: `false`) |
| `acceptedAlgorithms` | No | Whitelist of accepted algorithm identifiers |

**Response:**

```json
{
  "isValid": true,
  "error": null
}
```

### POST /api/signatures/verify-all

Verify all signatures in a document.

**Request and response** follow the same format as [POST /api/verify](#post-apiverify).

### POST /api/signatures/countersign

Countersign a specific signature in a signed document.

**Request:**

```json
{
  "document": { "message": "hello", "signatures": [{ "algorithm": "ES256", "hash_algorithm": "sha-256", "value": "..." }] },
  "algorithm": "ES256",
  "hashAlgorithm": "sha-256",
  "privateKeyPem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "signatureIndex": 0,
  "embedPublicKey": true
}
```

| Field | Required | Description |
|---|---|---|
| `document` | Yes | The signed JSON object |
| `algorithm` | Yes | Signature algorithm identifier |
| `hashAlgorithm` | Yes | Hash algorithm identifier |
| `privateKeyPem` | Yes | Private key in PEM format |
| `signatureIndex` | No | Index of the signature to countersign (default: `0`) |
| `embedPublicKey` | No | Embed the public key in the countersignature (default: `false`) |

**Response:**

```json
{
  "document": { "message": "hello", "signatures": [{ "algorithm": "ES256", "hash_algorithm": "sha-256", "value": "...", "countersignature": { ... } }] }
}
```

## Error handling

When a request fails, the API returns a `400 Bad Request` with an error message:

```json
{
  "error": "Description of what went wrong."
}
```

## Supported algorithms

| Family | Algorithms |
|---|---|
| ECDSA | ES256, ES384, ES512 |
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| EdDSA | Ed25519, Ed448 |

Hash algorithms: `sha-256`, `sha-384`, `sha-512`

## Example: sign and verify with curl

```sh
# Generate a key pair
curl -s -X POST http://localhost:5000/api/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"algorithm":"ES256"}' > keys.json

# Extract keys
PRIVATE_KEY_PEM=$(jq -r '.privateKeyPem' keys.json)

# Sign a document
SIGNED=$(curl -s -X POST http://localhost:5000/api/sign \
  -H "Content-Type: application/json" \
  -d "{\"document\":{\"message\":\"hello\"},\"algorithm\":\"ES256\",\"hashAlgorithm\":\"sha-256\",\"privateKeyPem\":$(jq '.privateKeyPem' keys.json)}")

# Verify the signature using the embedded public key
SIGNED_DOC=$(echo "$SIGNED" | jq '.document')
curl -s -X POST http://localhost:5000/api/verify \
  -H "Content-Type: application/json" \
  -d "{\"document\":$SIGNED_DOC,\"allowEmbeddedKey\":true}"
# Output: {"isValid":true,"error":null}
```

## License

Apache-2.0
