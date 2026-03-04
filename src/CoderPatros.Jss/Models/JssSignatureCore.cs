// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Text.Json.Nodes;

namespace CoderPatros.Jss.Models;

/// <summary>
/// Represents a JSS signature object as it appears in the "signatures" JSON array.
/// </summary>
public sealed record JssSignatureCore
{
    /// <summary>Hash algorithm identifier (e.g. "sha-256").</summary>
    public required string HashAlgorithm { get; init; }

    /// <summary>Signing algorithm identifier (e.g. "Ed25519").</summary>
    public required string Algorithm { get; init; }

    /// <summary>PEM body of the public key (base64 DER SubjectPublicKeyInfo, no header/footer).</summary>
    public string? PublicKey { get; init; }

    /// <summary>X.509 certificate chain (base64 DER certificates).</summary>
    public IReadOnlyList<string>? PublicCertChain { get; init; }

    /// <summary>URL to retrieve the certificate.</summary>
    public string? CertUrl { get; init; }

    /// <summary>Base64url-encoded SHA-256 certificate thumbprint (per RFC 7517 x5t#S256).</summary>
    public string? Thumbprint { get; init; }

    /// <summary>Base64url-encoded signature value.</summary>
    public string? Value { get; init; }

    /// <summary>Nested countersignature (optional).</summary>
    public JssSignatureCore? Countersignature { get; init; }

    /// <summary>Additional metadata properties.</summary>
    public IReadOnlyDictionary<string, JsonNode?>? Metadata { get; init; }
}
