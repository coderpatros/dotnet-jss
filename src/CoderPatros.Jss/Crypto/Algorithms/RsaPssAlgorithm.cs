// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Security.Cryptography;
using CoderPatros.Jss.Keys;

namespace CoderPatros.Jss.Crypto.Algorithms;

/// <summary>
/// RSA-PSS signature algorithm. Uses SignHash/VerifyHash since JSS pre-hashes the data.
/// The hash algorithm name for RSA is inferred from the hash length since JSS separates
/// the hash algorithm from the signing algorithm.
/// </summary>
internal sealed class RsaPssAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private const int MinimumRsaKeySizeBits = 2048;

    public RsaPssAlgorithm(string algorithmId)
    {
        AlgorithmId = algorithmId;
    }

    public byte[] Sign(ReadOnlySpan<byte> hash, SigningKey key)
    {
        if (key.KeyMaterial is not RSA rsa)
            throw new JssException($"Algorithm {AlgorithmId} requires an RSA key.");
        ValidateKeySize(rsa);
        var hashAlgorithmName = InferHashAlgorithm(hash.Length);
        return rsa.SignHash(hash.ToArray(), hashAlgorithmName, RSASignaturePadding.Pss);
    }

    public bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        if (key.KeyMaterial is not RSA rsa)
            throw new JssException("Invalid key type for RSA-PSS verification.");
        ValidateKeySize(rsa);
        var hashAlgorithmName = InferHashAlgorithm(hash.Length);
        return rsa.VerifyHash(hash.ToArray(), signature.ToArray(), hashAlgorithmName, RSASignaturePadding.Pss);
    }

    private static HashAlgorithmName InferHashAlgorithm(int hashLength) => hashLength switch
    {
        32 => HashAlgorithmName.SHA256,
        48 => HashAlgorithmName.SHA384,
        64 => HashAlgorithmName.SHA512,
        _ => throw new JssException($"Unsupported hash length: {hashLength} bytes")
    };

    private static void ValidateKeySize(RSA rsa)
    {
        if (rsa.KeySize < MinimumRsaKeySizeBits)
            throw new JssException($"RSA key size {rsa.KeySize} bits is below the minimum of {MinimumRsaKeySizeBits} bits.");
    }
}
