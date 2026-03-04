// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using CoderPatros.Jss.Keys;

namespace CoderPatros.Jss.Models;

/// <summary>
/// Configuration for a JSS countersigning operation.
/// </summary>
public sealed record CountersignOptions
{
    /// <summary>Hash algorithm identifier (e.g. "sha-256").</summary>
    public required string HashAlgorithm { get; init; }

    /// <summary>Signing algorithm identifier (e.g. "Ed25519").</summary>
    public required string Algorithm { get; init; }

    /// <summary>Private key for countersigning.</summary>
    public required SigningKey Key { get; init; }

    /// <summary>PEM body of the public key to embed (optional).</summary>
    public string? PublicKey { get; init; }

    /// <summary>X.509 certificate chain to embed (optional).</summary>
    public IReadOnlyList<string>? PublicCertChain { get; init; }

    /// <summary>URL to retrieve the certificate (optional).</summary>
    public string? CertUrl { get; init; }

    /// <summary>Certificate thumbprint (optional).</summary>
    public string? Thumbprint { get; init; }

    /// <summary>Index of the signature in the signatures array to countersign (0-based).</summary>
    public int SignatureIndex { get; init; }
}
