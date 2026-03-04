// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using CoderPatros.Jss.Crypto.Algorithms;
using CoderPatros.Jss.Models;

namespace CoderPatros.Jss.Crypto;

/// <summary>
/// Registry of all supported hash algorithms, keyed by algorithm ID.
/// </summary>
public sealed class HashAlgorithmRegistry
{
    private readonly Dictionary<string, IHashAlgorithm> _algorithms = new(StringComparer.Ordinal);

    public HashAlgorithmRegistry()
    {
        Register(new Sha256HashAlgorithm());
        Register(new Sha384HashAlgorithm());
        Register(new Sha512HashAlgorithm());
    }

    public void Register(IHashAlgorithm algorithm)
    {
        _algorithms[algorithm.AlgorithmId] = algorithm;
    }

    public IHashAlgorithm Get(string algorithmId)
    {
        if (!_algorithms.TryGetValue(algorithmId, out var algorithm))
            throw new JssException($"Unsupported hash algorithm: {algorithmId}");
        return algorithm;
    }
}
