// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using CoderPatros.Jss.Keys;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace CoderPatros.Jss.Crypto.Algorithms;

/// <summary>
/// RSA-PSS signature algorithm using BouncyCastle.
/// Uses PssSigner with a special digest for content (since JSS pre-hashes)
/// and the appropriate SHA digest for MGF1.
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
        if (key.KeyMaterial is not RsaPrivateCrtKeyParameters rsaKey)
            throw new JssException($"Algorithm {AlgorithmId} requires an RSA key.");
        ValidateKeySize(rsaKey.Modulus.BitLength);

        var signer = CreatePssSigner(hash.Length);
        signer.Init(true, rsaKey);
        var hashArray = hash.ToArray();
        signer.BlockUpdate(hashArray, 0, hashArray.Length);
        return signer.GenerateSignature();
    }

    public bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        if (key.KeyMaterial is not RsaKeyParameters rsaKey)
            throw new JssException("Invalid key type for RSA-PSS verification.");
        ValidateKeySize(rsaKey.Modulus.BitLength);

        var signer = CreatePssSigner(hash.Length);
        signer.Init(false, rsaKey);
        var hashArray = hash.ToArray();
        signer.BlockUpdate(hashArray, 0, hashArray.Length);
        return signer.VerifySignature(signature.ToArray());
    }

    private static PssSigner CreatePssSigner(int hashLength)
    {
        var (realDigest, saltLen) = CreateDigest(hashLength);
        return new PssSigner(new RsaBlindedEngine(), new PreHashDigest(realDigest), realDigest, saltLen);
    }

    private static (IDigest Digest, int SaltLength) CreateDigest(int hashLength) => hashLength switch
    {
        32 => (new Sha256Digest(), 32),
        48 => (new Sha384Digest(), 48),
        64 => (new Sha512Digest(), 64),
        _ => throw new JssException($"Unsupported hash length: {hashLength} bytes")
    };

    private static void ValidateKeySize(int keySizeBits)
    {
        if (keySizeBits < MinimumRsaKeySizeBits)
            throw new JssException($"RSA key size {keySizeBits} bits is below the minimum of {MinimumRsaKeySizeBits} bits.");
    }

    /// <summary>
    /// A digest wrapper for pre-hashed data with PssSigner.
    /// PssSigner reuses the content digest: first DoFinal extracts mHash from user input,
    /// then subsequent calls compute H = Hash(0x00^8 || mHash || salt).
    /// This wrapper passes through on the first DoFinal, then delegates to a real hash.
    /// </summary>
    private sealed class PreHashDigest : IDigest
    {
        private readonly IDigest _realDigest;
        private readonly MemoryStream _buffer = new();
        private bool _firstDoFinalDone;

        public PreHashDigest(IDigest realDigest)
        {
            _realDigest = realDigest;
        }

        public string AlgorithmName => _realDigest.AlgorithmName;
        public int GetDigestSize() => _realDigest.GetDigestSize();
        public int GetByteLength() => _realDigest.GetByteLength();

        public void Update(byte input)
        {
            if (_firstDoFinalDone)
                _realDigest.Update(input);
            else
                _buffer.WriteByte(input);
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            if (_firstDoFinalDone)
                _realDigest.BlockUpdate(input, inOff, inLen);
            else
                _buffer.Write(input, inOff, inLen);
        }

        public int DoFinal(byte[] output, int outOff)
        {
            if (!_firstDoFinalDone)
            {
                _firstDoFinalDone = true;
                var data = _buffer.ToArray();
                _buffer.SetLength(0);
                Array.Copy(data, 0, output, outOff, data.Length);
                return data.Length;
            }
            return _realDigest.DoFinal(output, outOff);
        }

        public void Reset()
        {
            _firstDoFinalDone = false;
            _buffer.SetLength(0);
            _realDigest.Reset();
        }

#if NET6_0_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (_firstDoFinalDone)
                _realDigest.BlockUpdate(input);
            else
                _buffer.Write(input);
        }

        public int DoFinal(Span<byte> output)
        {
            if (!_firstDoFinalDone)
            {
                _firstDoFinalDone = true;
                var data = _buffer.ToArray();
                _buffer.SetLength(0);
                data.CopyTo(output);
                return data.Length;
            }
            return _realDigest.DoFinal(output);
        }
#endif
    }
}
