// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CoderPatros.Jss.Keys;

/// <summary>
/// Helpers for parsing PEM body (base64 DER SubjectPublicKeyInfo) to BouncyCastle key objects,
/// and for exporting BouncyCastle key objects to PEM body format.
/// JSS uses PEM body without -----BEGIN/END----- lines.
/// </summary>
public static class PemKeyHelper
{
    /// <summary>
    /// Parse a PEM body (base64 SubjectPublicKeyInfo) into a VerificationKey.
    /// The algorithm hint is used to determine the key type.
    /// </summary>
    public static VerificationKey ParsePublicKey(string pemBody, string algorithm)
    {
        // PEM bodies may omit padding — add it if needed
        var padded = pemBody;
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        var der = Convert.FromBase64String(padded);

        var bcKey = PublicKeyFactory.CreateKey(der);

        if (algorithm.StartsWith("ES", StringComparison.Ordinal))
        {
            if (bcKey is not ECPublicKeyParameters ecKey)
                throw new JssException($"Expected ECDSA public key for algorithm {algorithm}.");
            return VerificationKey.FromECDsa(ecKey);
        }

        if (algorithm.StartsWith("RS", StringComparison.Ordinal) ||
            algorithm.StartsWith("PS", StringComparison.Ordinal))
        {
            if (bcKey is not RsaKeyParameters rsaKey)
                throw new JssException($"Expected RSA public key for algorithm {algorithm}.");
            return VerificationKey.FromRsa(rsaKey);
        }

        if (algorithm is "Ed25519" or "Ed448")
        {
            return bcKey switch
            {
                Ed25519PublicKeyParameters ed25519 => VerificationKey.FromEdDsa(ed25519.GetEncoded(), "Ed25519"),
                Ed448PublicKeyParameters ed448 => VerificationKey.FromEdDsa(ed448.GetEncoded(), "Ed448"),
                _ => throw new JssException($"Unexpected public key type for algorithm {algorithm}.")
            };
        }

        throw new JssException($"Cannot parse public key for algorithm: {algorithm}");
    }

    /// <summary>
    /// Export the SubjectPublicKeyInfo of a BouncyCastle public key as a PEM body (base64, no header/footer).
    /// </summary>
    public static string ExportPublicKeyPemBody(AsymmetricKeyParameter publicKey)
    {
        var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
        return Convert.ToBase64String(spki.GetEncoded());
    }

    /// <summary>
    /// Generate a key pair for the given algorithm and return (SigningKey, VerificationKey, PEM body of public key).
    /// </summary>
    public static (SigningKey Signing, VerificationKey Verification, string PublicKeyPemBody) GenerateKeyPair(string algorithm, int rsaKeySize = 2048)
    {
        if (algorithm.StartsWith("ES", StringComparison.Ordinal))
        {
            var curveName = algorithm switch
            {
                "ES256" => "P-256",
                "ES384" => "P-384",
                "ES512" => "P-521",
                _ => throw new JssException($"Unsupported ECDSA algorithm: {algorithm}")
            };
            var ecParams = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName(curveName);
            var domainParams = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());
            var gen = new ECKeyPairGenerator();
            gen.Init(new ECKeyGenerationParameters(domainParams, new SecureRandom()));
            var kp = gen.GenerateKeyPair();
            var privateKey = (ECPrivateKeyParameters)kp.Private;
            var publicKey = (ECPublicKeyParameters)kp.Public;
            var pemBody = ExportPublicKeyPemBody(publicKey);
            return (SigningKey.FromECDsa(privateKey), VerificationKey.FromECDsa(publicKey), pemBody);
        }

        if (algorithm.StartsWith("RS", StringComparison.Ordinal) ||
            algorithm.StartsWith("PS", StringComparison.Ordinal))
        {
            if (rsaKeySize < 2048)
                throw new JssException($"RSA key size {rsaKeySize} bits is below the minimum of 2048 bits.");
            var gen = new RsaKeyPairGenerator();
            gen.Init(new RsaKeyGenerationParameters(
                Org.BouncyCastle.Math.BigInteger.ValueOf(0x10001),
                new SecureRandom(),
                rsaKeySize,
                256));
            var kp = gen.GenerateKeyPair();
            var privateKey = (RsaPrivateCrtKeyParameters)kp.Private;
            var publicKey = (RsaKeyParameters)kp.Public;
            var pemBody = ExportPublicKeyPemBody(publicKey);
            return (SigningKey.FromRsa(privateKey), VerificationKey.FromRsa(publicKey), pemBody);
        }

        if (algorithm is "Ed25519")
        {
            var gen = new Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var kp = gen.GenerateKeyPair();
            var privBytes = ((Ed25519PrivateKeyParameters)kp.Private).GetEncoded();
            var pubBytes = ((Ed25519PublicKeyParameters)kp.Public).GetEncoded();
            var pemBody = ExportPublicKeyPemBody((Ed25519PublicKeyParameters)kp.Public);
            return (SigningKey.FromEdDsa(privBytes, "Ed25519"), VerificationKey.FromEdDsa(pubBytes, "Ed25519"), pemBody);
        }

        if (algorithm is "Ed448")
        {
            var gen = new Ed448KeyPairGenerator();
            gen.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
            var kp = gen.GenerateKeyPair();
            var privBytes = ((Ed448PrivateKeyParameters)kp.Private).GetEncoded();
            var pubBytes = ((Ed448PublicKeyParameters)kp.Public).GetEncoded();
            var pemBody = ExportPublicKeyPemBody((Ed448PublicKeyParameters)kp.Public);
            return (SigningKey.FromEdDsa(privBytes, "Ed448"), VerificationKey.FromEdDsa(pubBytes, "Ed448"), pemBody);
        }

        throw new JssException($"Unsupported algorithm for key generation: {algorithm}");
    }

    /// <summary>
    /// Export the public key PEM body from a SigningKey.
    /// This extracts the public key material and returns it as a base64 SubjectPublicKeyInfo string.
    /// </summary>
    public static string? ExportPublicKeyPemBody(SigningKey key, string algorithm)
    {
        return key.KeyMaterial switch
        {
            ECPrivateKeyParameters ecKey => ExportPublicKeyPemBody(GetEcPublicKey(ecKey)),
            RsaPrivateCrtKeyParameters rsaKey => ExportPublicKeyPemBody(
                new RsaKeyParameters(false, rsaKey.Modulus, rsaKey.PublicExponent)),
            SigningKey.EdDsaKeyMaterial edDsa =>
                ExportPublicKeyPemBody(GetEdDsaPublicKeyParam(edDsa.PrivateKey, edDsa.Curve)),
            _ => null
        };
    }

    private static ECPublicKeyParameters GetEcPublicKey(ECPrivateKeyParameters privateKey)
    {
        var q = privateKey.Parameters.G.Multiply(privateKey.D).Normalize();
        return new ECPublicKeyParameters(q, privateKey.Parameters);
    }

    private static AsymmetricKeyParameter GetEdDsaPublicKeyParam(byte[] privateKey, string curve)
    {
        return curve switch
        {
            "Ed25519" => new Ed25519PrivateKeyParameters(privateKey, 0).GeneratePublicKey(),
            "Ed448" => new Ed448PrivateKeyParameters(privateKey, 0).GeneratePublicKey(),
            _ => throw new JssException($"Unsupported EdDSA curve: {curve}")
        };
    }

    /// <summary>
    /// Export a private key to PEM format (with header/footer lines).
    /// </summary>
    public static string ExportPrivateKeyPem(SigningKey key, string algorithm)
    {
        AsymmetricKeyParameter bcKey = key.KeyMaterial switch
        {
            ECPrivateKeyParameters ecKey => ecKey,
            RsaPrivateCrtKeyParameters rsaKey => rsaKey,
            SigningKey.EdDsaKeyMaterial edDsa => edDsa.Curve switch
            {
                "Ed25519" => new Ed25519PrivateKeyParameters(edDsa.PrivateKey, 0),
                "Ed448" => new Ed448PrivateKeyParameters(edDsa.PrivateKey, 0),
                _ => throw new JssException($"Unsupported EdDSA curve: {edDsa.Curve}")
            },
            _ => throw new JssException("Unsupported key type for PEM export.")
        };

        var info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(bcKey);
        var der = info.GetEncoded();
        var base64 = Convert.ToBase64String(der);
        return $"-----BEGIN PRIVATE KEY-----\n{base64}\n-----END PRIVATE KEY-----";
    }

    /// <summary>
    /// Export a public key to PEM format (with header/footer lines).
    /// </summary>
    public static string ExportPublicKeyPem(string pemBody)
    {
        return $"-----BEGIN PUBLIC KEY-----\n{pemBody}\n-----END PUBLIC KEY-----";
    }

    /// <summary>
    /// Import a private key from PEM format (with header/footer lines).
    /// </summary>
    public static SigningKey ImportPrivateKeyPem(string pem, string algorithm)
    {
        var base64 = ExtractPemBody(pem);
        var der = Convert.FromBase64String(base64);
        var bcKey = PrivateKeyFactory.CreateKey(der);

        if (algorithm.StartsWith("ES", StringComparison.Ordinal))
        {
            if (bcKey is not ECPrivateKeyParameters ecKey)
                throw new JssException($"Expected ECDSA private key for algorithm {algorithm}.");
            return SigningKey.FromECDsa(ecKey);
        }

        if (algorithm.StartsWith("RS", StringComparison.Ordinal) ||
            algorithm.StartsWith("PS", StringComparison.Ordinal))
        {
            if (bcKey is not RsaPrivateCrtKeyParameters rsaKey)
                throw new JssException($"Expected RSA private key for algorithm {algorithm}.");
            return SigningKey.FromRsa(rsaKey);
        }

        if (algorithm is "Ed25519" or "Ed448")
        {
            return bcKey switch
            {
                Ed25519PrivateKeyParameters ed25519 => SigningKey.FromEdDsa(ed25519.GetEncoded(), "Ed25519"),
                Ed448PrivateKeyParameters ed448 => SigningKey.FromEdDsa(ed448.GetEncoded(), "Ed448"),
                _ => throw new JssException($"Unexpected private key type for algorithm {algorithm}.")
            };
        }

        throw new JssException($"Unsupported algorithm for PEM import: {algorithm}");
    }

    /// <summary>
    /// Import a public key from PEM format (with header/footer lines).
    /// </summary>
    public static VerificationKey ImportPublicKeyPem(string pem, string algorithm)
    {
        var base64 = ExtractPemBody(pem);
        return ParsePublicKey(base64, algorithm);
    }

    private static string ExtractPemBody(string pem)
    {
        var lines = pem.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var body = string.Join("", lines.Where(l =>
            !l.StartsWith("-----", StringComparison.Ordinal) &&
            !l.StartsWith("\r", StringComparison.Ordinal)));
        return body.Trim();
    }
}
