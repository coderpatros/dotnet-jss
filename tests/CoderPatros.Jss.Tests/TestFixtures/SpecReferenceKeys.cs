using CoderPatros.Jss.Keys;

namespace CoderPatros.Jss.Tests.TestFixtures;

/// <summary>
/// Reference keys from ITU-T X.590 Appendix II.
/// </summary>
internal static class SpecReferenceKeys
{
    // Ed25519 public key PEM body from the spec example.
    // SubjectPublicKeyInfo base64 for the spec Ed25519 test key.
    public const string Ed25519PublicKeyPemBody =
        "MCowBQYDK2VwAyEAubMonBfU9pvIbj5RCiWQLD45Jvu6mKr+kQXjvjW8ZkU";

    // Ed25519 private key PEM (PKCS#8) for signing spec test vectors.
    // This is the private counterpart to the above public key.
    // From ITU-T X.590 Appendix II.2.
    public const string Ed25519PrivateKeyPem =
        "-----BEGIN PRIVATE KEY-----\n" +
        "MC4CAQAwBQYDK2VwBCIEIDnZ5bPmXnB3OfU/5fNVfxfr7iRZtqH06AZ3b6c6liTL\n" +
        "-----END PRIVATE KEY-----";

    public static SigningKey GetEd25519SigningKey()
    {
        return PemKeyHelper.ImportPrivateKeyPem(Ed25519PrivateKeyPem, "Ed25519");
    }

    public static VerificationKey GetEd25519VerificationKey()
    {
        return PemKeyHelper.ParsePublicKey(Ed25519PublicKeyPemBody, "Ed25519");
    }
}
