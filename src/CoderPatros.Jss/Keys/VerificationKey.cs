// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Parameters;

namespace CoderPatros.Jss.Keys;

/// <summary>
/// Wraps a public key for verification operations.
/// Supports ECDsa, RSA, EdDSA, and X.509 certificates.
/// </summary>
public sealed class VerificationKey : IDisposable
{
    internal object KeyMaterial { get; }
    private int _disposed;

    private VerificationKey(object keyMaterial)
    {
        KeyMaterial = keyMaterial;
    }

    public static VerificationKey FromECDsa(ECPublicKeyParameters key) => new(key);
    public static VerificationKey FromRsa(RsaKeyParameters key) => new(key);
    public static VerificationKey FromEdDsa(byte[] publicKey, string curve) =>
        new(new EdDsaKeyMaterial(publicKey, curve));
    public static VerificationKey FromCertificate(X509Certificate2 cert) =>
        new(new CertificateKeyMaterial(cert));

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;

        switch (KeyMaterial)
        {
            case EdDsaKeyMaterial edDsa:
                CryptographicOperations.ZeroMemory(edDsa.PublicKey);
                break;
            case CertificateKeyMaterial cert:
                cert.Certificate.Dispose();
                break;
        }
    }

    internal sealed record EdDsaKeyMaterial(byte[] PublicKey, string Curve);
    internal sealed record CertificateKeyMaterial(X509Certificate2 Certificate);
}
