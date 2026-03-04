// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using CoderPatros.Jss.Keys;

namespace CoderPatros.Jss.Models;

/// <summary>
/// Configuration for a JSS verification operation.
/// </summary>
public sealed record VerificationOptions
{
    /// <summary>Key for verification.</summary>
    public VerificationKey? Key { get; init; }

    /// <summary>
    /// Key resolver for multi-signature verification.
    /// Called with each signature to resolve the appropriate verification key.
    /// </summary>
    public Func<JssSignatureCore, VerificationKey>? KeyResolver { get; init; }

    /// <summary>
    /// When true, allows verification using the public key embedded in the signature.
    /// Defaults to false. Only enable this when you trust the source of the document.
    /// </summary>
    public bool AllowEmbeddedPublicKey { get; init; }

    /// <summary>
    /// Optional set of accepted algorithm identifiers.
    /// When set, signatures using algorithms not in this set will be rejected.
    /// </summary>
    public IReadOnlySet<string>? AcceptedAlgorithms { get; init; }
}
