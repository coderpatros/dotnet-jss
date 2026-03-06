// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using CoderPatros.Jss.Keys;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace CoderPatros.Jss.Crypto.Algorithms;

/// <summary>
/// ECDSA signature algorithm using BouncyCastle.
/// Uses ECDsaSigner with IEEE P1363 encoding since JSS pre-hashes the data.
/// </summary>
internal sealed class EcdsaAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }
    private readonly string _expectedCurveOid;
    private readonly int _fieldSize;

    public EcdsaAlgorithm(string algorithmId)
    {
        AlgorithmId = algorithmId;
        (_expectedCurveOid, _fieldSize) = algorithmId switch
        {
            "ES256" => ("1.2.840.10045.3.1.7", 32),  // P-256
            "ES384" => ("1.3.132.0.34", 48),           // P-384
            "ES512" => ("1.3.132.0.35", 66),           // P-521
            _ => throw new ArgumentException($"Unknown ECDSA algorithm: {algorithmId}")
        };
    }

    public byte[] Sign(ReadOnlySpan<byte> hash, SigningKey key)
    {
        if (key.KeyMaterial is not ECPrivateKeyParameters ecKey)
            throw new JssException($"Algorithm {AlgorithmId} requires an ECDsa key.");
        ValidateCurve(ecKey.Parameters);

        var signer = new ECDsaSigner();
        signer.Init(true, ecKey);
        var components = signer.GenerateSignature(hash.ToArray());
        return EncodeIeeeP1363(components[0], components[1]);
    }

    public bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        if (key.KeyMaterial is not ECPublicKeyParameters ecKey)
            throw new JssException("Invalid key type for ECDSA verification.");
        ValidateCurve(ecKey.Parameters);

        var (r, s) = DecodeIeeeP1363(signature);
        var signer = new ECDsaSigner();
        signer.Init(false, ecKey);
        return signer.VerifySignature(hash.ToArray(), r, s);
    }

    private byte[] EncodeIeeeP1363(BigInteger r, BigInteger s)
    {
        var result = new byte[_fieldSize * 2];
        PadBigInteger(r, result, 0, _fieldSize);
        PadBigInteger(s, result, _fieldSize, _fieldSize);
        return result;
    }

    private static void PadBigInteger(BigInteger value, byte[] dest, int offset, int length)
    {
        var bytes = value.ToByteArrayUnsigned();
        var copyLen = Math.Min(bytes.Length, length);
        Array.Copy(bytes, 0, dest, offset + length - copyLen, copyLen);
    }

    private (BigInteger R, BigInteger S) DecodeIeeeP1363(ReadOnlySpan<byte> signature)
    {
        if (signature.Length != _fieldSize * 2)
            throw new JssException($"Invalid ECDSA signature length for {AlgorithmId}: expected {_fieldSize * 2}, got {signature.Length}.");
        var r = new BigInteger(1, signature[.._fieldSize].ToArray());
        var s = new BigInteger(1, signature[_fieldSize..].ToArray());
        return (r, s);
    }

    private void ValidateCurve(ECDomainParameters parameters)
    {
        // Look up expected curve and compare domain parameters
        var expectedCurve = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByOid(
            new Org.BouncyCastle.Asn1.DerObjectIdentifier(_expectedCurveOid));
        if (expectedCurve == null || !parameters.Curve.Equals(expectedCurve.Curve) || !parameters.G.Equals(expectedCurve.G))
            throw new JssException($"Algorithm {AlgorithmId} requires curve OID {_expectedCurveOid}, but key uses a different curve.");
    }
}
