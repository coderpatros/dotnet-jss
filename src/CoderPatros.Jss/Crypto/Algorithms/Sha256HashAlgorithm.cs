// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Security.Cryptography;
using CoderPatros.Jss.Models;

namespace CoderPatros.Jss.Crypto.Algorithms;

internal sealed class Sha256HashAlgorithm : IHashAlgorithm
{
    public string AlgorithmId => JssHashAlgorithm.Sha256;

    public byte[] ComputeHash(ReadOnlySpan<byte> data)
    {
        return SHA256.HashData(data);
    }
}
