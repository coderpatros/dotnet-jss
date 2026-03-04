// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Security.Cryptography;
using CoderPatros.Jss.Keys;

namespace CoderPatros.Jss.Crypto.Algorithms;

/// <summary>
/// ECDSA signature algorithm. Uses SignHash/VerifyHash since JSS pre-hashes the data.
/// ECDSA SignHash does not require knowing the hash algorithm name.
/// </summary>
internal sealed class EcdsaAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private readonly string _expectedCurveOid;

    public EcdsaAlgorithm(string algorithmId)
    {
        AlgorithmId = algorithmId;
        _expectedCurveOid = algorithmId switch
        {
            "ES256" => "1.2.840.10045.3.1.7", // P-256
            "ES384" => "1.3.132.0.34",         // P-384
            "ES512" => "1.3.132.0.35",         // P-521
            _ => throw new ArgumentException($"Unknown ECDSA algorithm: {algorithmId}")
        };
    }

    public byte[] Sign(ReadOnlySpan<byte> hash, SigningKey key)
    {
        if (key.KeyMaterial is not ECDsa ecdsa)
            throw new JssException($"Algorithm {AlgorithmId} requires an ECDsa key.");
        ValidateCurve(ecdsa);
        return ecdsa.SignHash(hash.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        if (key.KeyMaterial is not ECDsa ecdsa)
            throw new JssException("Invalid key type for ECDSA verification.");
        ValidateCurve(ecdsa);
        return ecdsa.VerifyHash(hash.ToArray(), signature.ToArray(), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private void ValidateCurve(ECDsa ecdsa)
    {
        var curveOid = ecdsa.ExportParameters(false).Curve.Oid?.Value;
        if (curveOid != _expectedCurveOid)
            throw new JssException($"Algorithm {AlgorithmId} requires curve OID {_expectedCurveOid}, but key uses {curveOid}.");
    }
}
