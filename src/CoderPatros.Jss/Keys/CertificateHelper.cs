// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoderPatros.Jss.Serialization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CoderPatros.Jss.Keys;

/// <summary>
/// Helpers for X.509 certificate operations used in JSS.
/// </summary>
public static class CertificateHelper
{
    /// <summary>
    /// Parse a base64 DER-encoded certificate.
    /// </summary>
    public static X509Certificate2 ParseCertificate(string base64Der)
    {
        var der = Convert.FromBase64String(base64Der);
        return new X509Certificate2(der);
    }

    /// <summary>
    /// Extract a VerificationKey from the first certificate in a certificate chain.
    /// </summary>
    public static VerificationKey ExtractPublicKey(IReadOnlyList<string> certChain, string algorithm)
    {
        if (certChain.Count == 0)
            throw new JssException("Certificate chain is empty.");

        var cert = ParseCertificate(certChain[0]);

        if (algorithm.StartsWith("ES", StringComparison.Ordinal))
        {
            var ecdsa = cert.GetECDsaPublicKey()
                ?? throw new JssException("Certificate does not contain an ECDSA public key.");
            return VerificationKey.FromECDsa(ecdsa);
        }

        if (algorithm.StartsWith("RS", StringComparison.Ordinal) ||
            algorithm.StartsWith("PS", StringComparison.Ordinal))
        {
            var rsa = cert.GetRSAPublicKey()
                ?? throw new JssException("Certificate does not contain an RSA public key.");
            return VerificationKey.FromRsa(rsa);
        }

        if (algorithm is "Ed25519" or "Ed448")
        {
            var bcKey = PublicKeyFactory.CreateKey(cert.PublicKey.ExportSubjectPublicKeyInfo());
            return bcKey switch
            {
                Ed25519PublicKeyParameters ed25519 => VerificationKey.FromEdDsa(ed25519.GetEncoded(), "Ed25519"),
                Ed448PublicKeyParameters ed448 => VerificationKey.FromEdDsa(ed448.GetEncoded(), "Ed448"),
                _ => throw new JssException($"Certificate does not contain an EdDSA public key for algorithm: {algorithm}")
            };
        }

        throw new JssException($"Cannot extract public key from certificate for algorithm: {algorithm}");
    }

    /// <summary>
    /// Compute the base64url-encoded SHA-256 thumbprint of a certificate,
    /// per ITU-T X.590 clause 6.2.1 (referencing JWK "x5t#S256", RFC 7517 section 4.9).
    /// </summary>
    public static string ComputeThumbprint(X509Certificate2 cert)
    {
        var hash = SHA256.HashData(cert.RawData);
        return Base64UrlEncoding.Encode(hash);
    }

    /// <summary>
    /// Compute the base64url-encoded SHA-256 thumbprint of a base64 DER-encoded certificate.
    /// </summary>
    public static string ComputeThumbprint(string base64Der)
    {
        var cert = ParseCertificate(base64Der);
        return ComputeThumbprint(cert);
    }
}
