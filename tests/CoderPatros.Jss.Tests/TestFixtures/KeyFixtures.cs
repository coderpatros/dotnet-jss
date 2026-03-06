using CoderPatros.Jss.Keys;
using CoderPatros.Jss.Models;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CoderPatros.Jss.Tests.TestFixtures;

internal static class KeyFixtures
{
    // ECDSA keys
    public static (ECPrivateKeyParameters Private, ECPublicKeyParameters Public) CreateEcdsaKeyPair(string curveName)
    {
        var ecParams = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName(curveName);
        var domainParams = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        return ((ECPrivateKeyParameters)kp.Private, (ECPublicKeyParameters)kp.Public);
    }

    // RSA keys
    public static (RsaPrivateCrtKeyParameters Private, RsaKeyParameters Public) CreateRsa2048()
    {
        var gen = new RsaKeyPairGenerator();
        gen.Init(new RsaKeyGenerationParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(0x10001),
            new SecureRandom(),
            2048,
            256));
        var kp = gen.GenerateKeyPair();
        return ((RsaPrivateCrtKeyParameters)kp.Private, (RsaKeyParameters)kp.Public);
    }

    // EdDSA Ed25519
    public static (byte[] PrivateKey, byte[] PublicKey) CreateEd25519KeyPair()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = gen.GenerateKeyPair();
        var privateKey = ((Ed25519PrivateKeyParameters)keyPair.Private).GetEncoded();
        var publicKey = ((Ed25519PublicKeyParameters)keyPair.Public).GetEncoded();
        return (privateKey, publicKey);
    }

    // EdDSA Ed448
    public static (byte[] PrivateKey, byte[] PublicKey) CreateEd448KeyPair()
    {
        var gen = new Ed448KeyPairGenerator();
        gen.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
        var keyPair = gen.GenerateKeyPair();
        var privateKey = ((Ed448PrivateKeyParameters)keyPair.Private).GetEncoded();
        var publicKey = ((Ed448PublicKeyParameters)keyPair.Public).GetEncoded();
        return (privateKey, publicKey);
    }

    // Helper: create signing/verification key pairs with PEM body
    public static (SigningKey Signing, VerificationKey Verification, string PublicKeyPemBody) CreateEcdsaKeySet(string algorithm)
    {
        var curveName = algorithm switch
        {
            JssAlgorithm.ES256 => "P-256",
            JssAlgorithm.ES384 => "P-384",
            JssAlgorithm.ES512 => "P-521",
            _ => throw new ArgumentException($"Unsupported: {algorithm}")
        };
        var (privateKey, publicKey) = CreateEcdsaKeyPair(curveName);
        var pemBody = PemKeyHelper.ExportPublicKeyPemBody(publicKey);
        return (
            SigningKey.FromECDsa(privateKey),
            VerificationKey.FromECDsa(publicKey),
            pemBody
        );
    }

    public static (SigningKey Signing, VerificationKey Verification, string PublicKeyPemBody) CreateRsaKeySet()
    {
        var (privateKey, publicKey) = CreateRsa2048();
        var pemBody = PemKeyHelper.ExportPublicKeyPemBody(publicKey);
        return (
            SigningKey.FromRsa(privateKey),
            VerificationKey.FromRsa(publicKey),
            pemBody
        );
    }

    public static (SigningKey Signing, VerificationKey Verification, string PublicKeyPemBody) CreateEdDsaKeySet(string curve)
    {
        var (privateKey, publicKey) = curve switch
        {
            "Ed25519" => CreateEd25519KeyPair(),
            "Ed448" => CreateEd448KeyPair(),
            _ => throw new ArgumentException($"Unsupported: {curve}")
        };
        var bcPubKey = curve switch
        {
            "Ed25519" => (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)new Ed25519PublicKeyParameters(publicKey, 0),
            "Ed448" => new Ed448PublicKeyParameters(publicKey, 0),
            _ => throw new ArgumentException($"Unsupported: {curve}")
        };
        var pemBody = PemKeyHelper.ExportPublicKeyPemBody(bcPubKey);
        return (
            SigningKey.FromEdDsa(privateKey, curve),
            VerificationKey.FromEdDsa(publicKey, curve),
            pemBody
        );
    }
}
