// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CoderPatros.Jss.Keys;

/// <summary>
/// Helpers for parsing PEM body (base64 DER SubjectPublicKeyInfo) to .NET key objects,
/// and for exporting .NET key objects to PEM body format.
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

        if (algorithm.StartsWith("ES", StringComparison.Ordinal))
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(der, out _);
            return VerificationKey.FromECDsa(ecdsa);
        }

        if (algorithm.StartsWith("RS", StringComparison.Ordinal) ||
            algorithm.StartsWith("PS", StringComparison.Ordinal))
        {
            var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(der, out _);
            return VerificationKey.FromRsa(rsa);
        }

        if (algorithm is "Ed25519" or "Ed448")
        {
            var bcPublicKey = PublicKeyFactory.CreateKey(der);
            return bcPublicKey switch
            {
                Ed25519PublicKeyParameters ed25519 => VerificationKey.FromEdDsa(ed25519.GetEncoded(), "Ed25519"),
                Ed448PublicKeyParameters ed448 => VerificationKey.FromEdDsa(ed448.GetEncoded(), "Ed448"),
                _ => throw new JssException($"Unexpected public key type for algorithm {algorithm}.")
            };
        }

        throw new JssException($"Cannot parse public key for algorithm: {algorithm}");
    }

    /// <summary>
    /// Export the SubjectPublicKeyInfo of an ECDsa key as a PEM body (base64, no header/footer).
    /// </summary>
    public static string ExportPublicKeyPemBody(ECDsa key)
    {
        var spki = key.ExportSubjectPublicKeyInfo();
        return Convert.ToBase64String(spki);
    }

    /// <summary>
    /// Export the SubjectPublicKeyInfo of an RSA key as a PEM body.
    /// </summary>
    public static string ExportPublicKeyPemBody(RSA key)
    {
        var spki = key.ExportSubjectPublicKeyInfo();
        return Convert.ToBase64String(spki);
    }

    /// <summary>
    /// Export an EdDSA public key as a PEM body (SubjectPublicKeyInfo format).
    /// </summary>
    public static string ExportEdDsaPublicKeyPemBody(byte[] publicKey, string curve)
    {
        Org.BouncyCastle.Crypto.AsymmetricKeyParameter bcKey = curve switch
        {
            "Ed25519" => new Ed25519PublicKeyParameters(publicKey, 0),
            "Ed448" => new Ed448PublicKeyParameters(publicKey, 0),
            _ => throw new JssException($"Unsupported EdDSA curve: {curve}")
        };

        var info = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(bcKey);
        return Convert.ToBase64String(info.GetEncoded());
    }

    /// <summary>
    /// Generate a key pair for the given algorithm and return (SigningKey, PEM body of public key).
    /// </summary>
    public static (SigningKey Signing, VerificationKey Verification, string PublicKeyPemBody) GenerateKeyPair(string algorithm, int rsaKeySize = 2048)
    {
        if (algorithm.StartsWith("ES", StringComparison.Ordinal))
        {
            var curve = algorithm switch
            {
                "ES256" => ECCurve.NamedCurves.nistP256,
                "ES384" => ECCurve.NamedCurves.nistP384,
                "ES512" => ECCurve.NamedCurves.nistP521,
                _ => throw new JssException($"Unsupported ECDSA algorithm: {algorithm}")
            };
            var ecdsa = ECDsa.Create(curve);
            var pemBody = ExportPublicKeyPemBody(ecdsa);
            // Create a second ECDsa for the verification key (same key material)
            var ecdsa2 = ECDsa.Create();
            ecdsa2.ImportSubjectPublicKeyInfo(ecdsa.ExportSubjectPublicKeyInfo(), out _);
            return (SigningKey.FromECDsa(ecdsa), VerificationKey.FromECDsa(ecdsa2), pemBody);
        }

        if (algorithm.StartsWith("RS", StringComparison.Ordinal) ||
            algorithm.StartsWith("PS", StringComparison.Ordinal))
        {
            if (rsaKeySize < 2048)
                throw new JssException($"RSA key size {rsaKeySize} bits is below the minimum of 2048 bits.");
            var rsa = RSA.Create(rsaKeySize);
            var pemBody = ExportPublicKeyPemBody(rsa);
            var rsa2 = RSA.Create();
            rsa2.ImportSubjectPublicKeyInfo(rsa.ExportSubjectPublicKeyInfo(), out _);
            return (SigningKey.FromRsa(rsa), VerificationKey.FromRsa(rsa2), pemBody);
        }

        if (algorithm is "Ed25519")
        {
            var gen = new Org.BouncyCastle.Crypto.Generators.Ed25519KeyPairGenerator();
            gen.Init(new Ed25519KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom()));
            var kp = gen.GenerateKeyPair();
            var privBytes = ((Ed25519PrivateKeyParameters)kp.Private).GetEncoded();
            var pubBytes = ((Ed25519PublicKeyParameters)kp.Public).GetEncoded();
            var pemBody = ExportEdDsaPublicKeyPemBody(pubBytes, "Ed25519");
            return (SigningKey.FromEdDsa(privBytes, "Ed25519"), VerificationKey.FromEdDsa(pubBytes, "Ed25519"), pemBody);
        }

        if (algorithm is "Ed448")
        {
            var gen = new Org.BouncyCastle.Crypto.Generators.Ed448KeyPairGenerator();
            gen.Init(new Ed448KeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom()));
            var kp = gen.GenerateKeyPair();
            var privBytes = ((Ed448PrivateKeyParameters)kp.Private).GetEncoded();
            var pubBytes = ((Ed448PublicKeyParameters)kp.Public).GetEncoded();
            var pemBody = ExportEdDsaPublicKeyPemBody(pubBytes, "Ed448");
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
            ECDsa ecdsa => ExportPublicKeyPemBody(ecdsa),
            RSA rsa => ExportPublicKeyPemBody(rsa),
            SigningKey.EdDsaKeyMaterial edDsa =>
                ExportEdDsaPublicKeyPemBody(GetEdDsaPublicKeyFromPrivate(edDsa.PrivateKey, edDsa.Curve), edDsa.Curve),
            _ => null
        };
    }

    private static byte[] GetEdDsaPublicKeyFromPrivate(byte[] privateKey, string curve)
    {
        return curve switch
        {
            "Ed25519" => new Ed25519PrivateKeyParameters(privateKey, 0).GeneratePublicKey().GetEncoded(),
            "Ed448" => new Ed448PrivateKeyParameters(privateKey, 0).GeneratePublicKey().GetEncoded(),
            _ => throw new JssException($"Unsupported EdDSA curve: {curve}")
        };
    }

    /// <summary>
    /// Export a private key to PEM format (with header/footer lines).
    /// </summary>
    public static string ExportPrivateKeyPem(SigningKey key, string algorithm)
    {
        return key.KeyMaterial switch
        {
            ECDsa ecdsa => ecdsa.ExportPkcs8PrivateKeyPem(),
            RSA rsa => rsa.ExportPkcs8PrivateKeyPem(),
            SigningKey.EdDsaKeyMaterial edDsa => ExportEdDsaPrivateKeyPem(edDsa.PrivateKey, edDsa.Curve),
            _ => throw new JssException("Unsupported key type for PEM export.")
        };
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
        if (algorithm.StartsWith("ES", StringComparison.Ordinal))
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            return SigningKey.FromECDsa(ecdsa);
        }

        if (algorithm.StartsWith("RS", StringComparison.Ordinal) ||
            algorithm.StartsWith("PS", StringComparison.Ordinal))
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            return SigningKey.FromRsa(rsa);
        }

        if (algorithm is "Ed25519" or "Ed448")
        {
            // Extract the base64 body from PEM
            var base64 = ExtractPemBody(pem);
            var der = Convert.FromBase64String(base64);
            var bcKey = PrivateKeyFactory.CreateKey(der);
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

    private static string ExportEdDsaPrivateKeyPem(byte[] privateKey, string curve)
    {
        Org.BouncyCastle.Crypto.AsymmetricKeyParameter bcKey = curve switch
        {
            "Ed25519" => new Ed25519PrivateKeyParameters(privateKey, 0),
            "Ed448" => new Ed448PrivateKeyParameters(privateKey, 0),
            _ => throw new JssException($"Unsupported EdDSA curve: {curve}")
        };

        var info = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(bcKey);
        var der = info.GetEncoded();
        var base64 = Convert.ToBase64String(der);
        return $"-----BEGIN PRIVATE KEY-----\n{base64}\n-----END PRIVATE KEY-----";
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
