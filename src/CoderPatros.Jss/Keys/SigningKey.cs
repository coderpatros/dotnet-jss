// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Security.Cryptography;

namespace CoderPatros.Jss.Keys;

/// <summary>
/// Wraps a private key for signing operations.
/// Implements IDisposable to securely zero key material on disposal.
/// No HMAC support (JSS spec says HS256/384/512 SHOULD NOT be used).
/// </summary>
public sealed class SigningKey : IDisposable
{
    internal object KeyMaterial { get; }
    private int _disposed;

    private SigningKey(object keyMaterial)
    {
        KeyMaterial = keyMaterial;
    }

    public static SigningKey FromECDsa(ECDsa key) => new(key);
    public static SigningKey FromRsa(RSA key) => new(key);
    public static SigningKey FromEdDsa(byte[] privateKey, string curve) =>
        new(new EdDsaKeyMaterial(privateKey, curve));

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0) return;

        switch (KeyMaterial)
        {
            case ECDsa ecdsa:
                ecdsa.Dispose();
                break;
            case RSA rsa:
                rsa.Dispose();
                break;
            case EdDsaKeyMaterial edDsa:
                CryptographicOperations.ZeroMemory(edDsa.PrivateKey);
                break;
        }
    }

    internal sealed record EdDsaKeyMaterial(byte[] PrivateKey, string Curve);
}
