// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Security.Cryptography;
using CoderPatros.Jss.Models;

namespace CoderPatros.Jss.Crypto.Algorithms;

internal sealed class Sha512HashAlgorithm : IHashAlgorithm
{
    public string AlgorithmId => JssHashAlgorithm.Sha512;

    public byte[] ComputeHash(ReadOnlySpan<byte> data)
    {
        return SHA512.HashData(data);
    }
}
