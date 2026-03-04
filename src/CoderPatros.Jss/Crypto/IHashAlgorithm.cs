// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

namespace CoderPatros.Jss.Crypto;

/// <summary>
/// Abstraction for a hash algorithm used in the JSS two-step signing process.
/// </summary>
public interface IHashAlgorithm
{
    string AlgorithmId { get; }
    byte[] ComputeHash(ReadOnlySpan<byte> data);
}
