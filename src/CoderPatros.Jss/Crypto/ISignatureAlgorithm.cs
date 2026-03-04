// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using CoderPatros.Jss.Keys;

namespace CoderPatros.Jss.Crypto;

/// <summary>
/// Abstraction for a cryptographic signature algorithm.
/// In JSS, Sign/Verify operate on pre-hashed data (except EdDSA where the hash IS the message).
/// </summary>
public interface ISignatureAlgorithm
{
    string AlgorithmId { get; }
    byte[] Sign(ReadOnlySpan<byte> hash, SigningKey key);
    bool Verify(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, VerificationKey key);
}
