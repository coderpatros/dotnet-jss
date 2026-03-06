// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using CoderPatros.Jss.Keys;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;

namespace CoderPatros.Jss.Crypto.Algorithms;

/// <summary>
/// RSA PKCS#1 v1.5 signature algorithm using BouncyCastle.
/// Uses RsaDigestSigner with NullDigest since JSS pre-hashes the data.
/// </summary>
internal sealed class RsaPkcs1Algorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private const int MinimumRsaKeySizeBits = 2048;

    public RsaPkcs1Algorithm(string algorithmId)
    {
        AlgorithmId = algorithmId;
    }

    public byte[] Sign(ReadOnlySpan<byte> hash, SigningKey key)
    {
        if (key.KeyMaterial is not RsaPrivateCrtKeyParameters rsaKey)
            throw new JssException($"Algorithm {AlgorithmId} requires an RSA key.");
        ValidateKeySize(rsaKey.Modulus.BitLength);

        var oid = InferHashOid(hash.Length);
        var signer = new RsaDigestSigner(new NullDigest(), oid);
        signer.Init(true, rsaKey);
        var hashArray = hash.ToArray();
        signer.BlockUpdate(hashArray, 0, hashArray.Length);
        return signer.GenerateSignature();
    }

    public bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        if (key.KeyMaterial is not RsaKeyParameters rsaKey)
            throw new JssException("Invalid key type for RSA verification.");
        ValidateKeySize(rsaKey.Modulus.BitLength);

        var oid = InferHashOid(hash.Length);
        var signer = new RsaDigestSigner(new NullDigest(), oid);
        signer.Init(false, rsaKey);
        var hashArray = hash.ToArray();
        signer.BlockUpdate(hashArray, 0, hashArray.Length);
        return signer.VerifySignature(signature.ToArray());
    }

    private static DerObjectIdentifier InferHashOid(int hashLength) => hashLength switch
    {
        32 => NistObjectIdentifiers.IdSha256,
        48 => NistObjectIdentifiers.IdSha384,
        64 => NistObjectIdentifiers.IdSha512,
        _ => throw new JssException($"Unsupported hash length: {hashLength} bytes")
    };

    private static void ValidateKeySize(int keySizeBits)
    {
        if (keySizeBits < MinimumRsaKeySizeBits)
            throw new JssException($"RSA key size {keySizeBits} bits is below the minimum of {MinimumRsaKeySizeBits} bits.");
    }
}
