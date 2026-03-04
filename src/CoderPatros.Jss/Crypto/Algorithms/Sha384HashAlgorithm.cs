// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Security.Cryptography;
using CoderPatros.Jss.Models;

namespace CoderPatros.Jss.Crypto.Algorithms;

internal sealed class Sha384HashAlgorithm : IHashAlgorithm
{
    public string AlgorithmId => JssHashAlgorithm.Sha384;

    public byte[] ComputeHash(ReadOnlySpan<byte> data)
    {
        return SHA384.HashData(data);
    }
}
