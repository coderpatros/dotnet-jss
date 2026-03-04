// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using CoderPatros.Jss.Crypto.Algorithms;
using CoderPatros.Jss.Models;

namespace CoderPatros.Jss.Crypto;

/// <summary>
/// Registry of all supported signature algorithms, keyed by algorithm ID.
/// </summary>
public sealed class SignatureAlgorithmRegistry
{
    private readonly Dictionary<string, ISignatureAlgorithm> _algorithms = new(StringComparer.Ordinal);

    public SignatureAlgorithmRegistry()
    {
        // ECDSA (uses SignHash/VerifyHash since JSS explicitly hashes first)
        Register(new EcdsaAlgorithm(JssAlgorithm.ES256));
        Register(new EcdsaAlgorithm(JssAlgorithm.ES384));
        Register(new EcdsaAlgorithm(JssAlgorithm.ES512));

        // RSA PKCS#1 v1.5 (hash algorithm inferred from hash length)
        Register(new RsaPkcs1Algorithm(JssAlgorithm.RS256));
        Register(new RsaPkcs1Algorithm(JssAlgorithm.RS384));
        Register(new RsaPkcs1Algorithm(JssAlgorithm.RS512));

        // RSA-PSS (hash algorithm inferred from hash length)
        Register(new RsaPssAlgorithm(JssAlgorithm.PS256));
        Register(new RsaPssAlgorithm(JssAlgorithm.PS384));
        Register(new RsaPssAlgorithm(JssAlgorithm.PS512));

        // EdDSA (hash bytes are treated as the message)
        Register(new EdDsaAlgorithm(JssAlgorithm.Ed25519));
        Register(new EdDsaAlgorithm(JssAlgorithm.Ed448));
    }

    public void Register(ISignatureAlgorithm algorithm)
    {
        _algorithms[algorithm.AlgorithmId] = algorithm;
    }

    public ISignatureAlgorithm Get(string algorithmId)
    {
        if (!_algorithms.TryGetValue(algorithmId, out var algorithm))
            throw new JssException($"Unsupported algorithm: {algorithmId}");
        return algorithm;
    }
}
