using System.Security.Cryptography;
using CoderPatros.Jss.Keys;
using CoderPatros.Jss.Models;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CoderPatros.Jss.Tests.TestFixtures;

internal static class KeyFixtures
{
    // ECDSA keys
    public static ECDsa CreateEcdsaP256() => ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public static ECDsa CreateEcdsaP384() => ECDsa.Create(ECCurve.NamedCurves.nistP384);
    public static ECDsa CreateEcdsaP521() => ECDsa.Create(ECCurve.NamedCurves.nistP521);

    // RSA keys
    public static RSA CreateRsa2048() => RSA.Create(2048);

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
        var ecdsa = algorithm switch
        {
            JssAlgorithm.ES256 => CreateEcdsaP256(),
            JssAlgorithm.ES384 => CreateEcdsaP384(),
            JssAlgorithm.ES512 => CreateEcdsaP521(),
            _ => throw new ArgumentException($"Unsupported: {algorithm}")
        };
        var pemBody = PemKeyHelper.ExportPublicKeyPemBody(ecdsa);
        var ecdsa2 = ECDsa.Create();
        ecdsa2.ImportSubjectPublicKeyInfo(ecdsa.ExportSubjectPublicKeyInfo(), out _);
        return (
            SigningKey.FromECDsa(ecdsa),
            VerificationKey.FromECDsa(ecdsa2),
            pemBody
        );
    }

    public static (SigningKey Signing, VerificationKey Verification, string PublicKeyPemBody) CreateRsaKeySet()
    {
        var rsa = CreateRsa2048();
        var pemBody = PemKeyHelper.ExportPublicKeyPemBody(rsa);
        var rsa2 = RSA.Create();
        rsa2.ImportSubjectPublicKeyInfo(rsa.ExportSubjectPublicKeyInfo(), out _);
        return (
            SigningKey.FromRsa(rsa),
            VerificationKey.FromRsa(rsa2),
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
        var pemBody = PemKeyHelper.ExportEdDsaPublicKeyPemBody(publicKey, curve);
        return (
            SigningKey.FromEdDsa(privateKey, curve),
            VerificationKey.FromEdDsa(publicKey, curve),
            pemBody
        );
    }
}
