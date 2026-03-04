// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using CoderPatros.Jss.Keys;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace CoderPatros.Jss.Crypto.Algorithms;

/// <summary>
/// EdDSA signature algorithm using BouncyCastle.
/// In JSS, the hash bytes ARE the message input to EdDSA (Ed25519 internally hashes again).
/// </summary>
internal sealed class EdDsaAlgorithm : ISignatureAlgorithm
{
    public string AlgorithmId { get; }

    public EdDsaAlgorithm(string algorithmId)
    {
        AlgorithmId = algorithmId;
    }

    private static readonly IReadOnlyDictionary<string, int> ExpectedPrivateKeySizes = new Dictionary<string, int>
    {
        ["Ed25519"] = 32,
        ["Ed448"] = 57
    };

    private static readonly IReadOnlyDictionary<string, int> ExpectedPublicKeySizes = new Dictionary<string, int>
    {
        ["Ed25519"] = 32,
        ["Ed448"] = 57
    };

    public byte[] Sign(ReadOnlySpan<byte> hash, SigningKey key)
    {
        if (key.KeyMaterial is not SigningKey.EdDsaKeyMaterial edKey)
            throw new JssException($"Algorithm {AlgorithmId} requires an EdDSA key.");
        if (edKey.Curve != AlgorithmId)
            throw new JssException($"Algorithm {AlgorithmId} requires curve {AlgorithmId}, but key uses {edKey.Curve}.");
        ValidatePrivateKeyLength(edKey.PrivateKey, edKey.Curve);
        var dataArray = hash.ToArray();

        return edKey.Curve switch
        {
            "Ed25519" => SignEd25519(dataArray, edKey.PrivateKey),
            "Ed448" => SignEd448(dataArray, edKey.PrivateKey),
            _ => throw new JssException($"Unsupported EdDSA curve: {edKey.Curve}")
        };
    }

    public bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, VerificationKey key)
    {
        var (publicKeyBytes, curve) = ResolvePublicKey(key);
        if (curve != AlgorithmId)
            throw new JssException($"Algorithm {AlgorithmId} requires curve {AlgorithmId}, but key uses {curve}.");
        ValidatePublicKeyLength(publicKeyBytes, curve);
        var dataArray = hash.ToArray();
        var sigArray = signature.ToArray();

        return curve switch
        {
            "Ed25519" => VerifyEd25519(dataArray, sigArray, publicKeyBytes),
            "Ed448" => VerifyEd448(dataArray, sigArray, publicKeyBytes),
            _ => throw new JssException($"Unsupported EdDSA curve: {curve}")
        };
    }

    private static byte[] SignEd25519(byte[] data, byte[] privateKey)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(privateKey, 0));
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    private static byte[] SignEd448(byte[] data, byte[] privateKey)
    {
        var signer = new Ed448Signer(Array.Empty<byte>());
        signer.Init(true, new Ed448PrivateKeyParameters(privateKey, 0));
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    private static bool VerifyEd25519(byte[] data, byte[] signature, byte[] publicKey)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }

    private static bool VerifyEd448(byte[] data, byte[] signature, byte[] publicKey)
    {
        var verifier = new Ed448Signer(Array.Empty<byte>());
        verifier.Init(false, new Ed448PublicKeyParameters(publicKey, 0));
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }

    private static void ValidatePrivateKeyLength(byte[] privateKey, string curve)
    {
        if (ExpectedPrivateKeySizes.TryGetValue(curve, out var expected) && privateKey.Length != expected)
            throw new JssException($"EdDSA {curve} private key must be {expected} bytes, but got {privateKey.Length} bytes.");
    }

    private static void ValidatePublicKeyLength(byte[] publicKey, string curve)
    {
        if (ExpectedPublicKeySizes.TryGetValue(curve, out var expected) && publicKey.Length != expected)
            throw new JssException($"EdDSA {curve} public key must be {expected} bytes, but got {publicKey.Length} bytes.");
    }

    private static (byte[] PublicKey, string Curve) ResolvePublicKey(VerificationKey key)
    {
        return key.KeyMaterial switch
        {
            VerificationKey.EdDsaKeyMaterial ed => (ed.PublicKey, ed.Curve),
            _ => throw new JssException("Invalid key type for EdDSA verification.")
        };
    }
}
