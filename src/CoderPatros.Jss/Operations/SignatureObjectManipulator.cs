// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Text.Json.Nodes;
using CoderPatros.Jss.Models;
using CoderPatros.Jss.Serialization;

namespace CoderPatros.Jss.Operations;

/// <summary>
/// JSON-level operations on JSS signature objects within documents.
/// Handles the "signatures" JSON array manipulation.
/// </summary>
internal static class SignatureObjectManipulator
{
    /// <summary>
    /// Extracts all JssSignatureCore objects from a document's "signatures" array.
    /// </summary>
    public static IReadOnlyList<JssSignatureCore> ExtractSignatures(JsonObject document)
    {
        var sigArray = document["signatures"] as JsonArray
            ?? throw new JssException("Document does not contain a 'signatures' property.");

        return sigArray
            .Select(n => JssSignatureCoreSerializer.Deserialize(n!.AsObject()))
            .ToList();
    }

    /// <summary>
    /// Extracts a single JssSignatureCore from the signatures array at the given index.
    /// </summary>
    public static JssSignatureCore ExtractSignatureAt(JsonObject document, int index)
    {
        var signatures = ExtractSignatures(document);
        if (index < 0 || index >= signatures.Count)
            throw new JssException($"Signature index {index} is out of range (0..{signatures.Count - 1}).");
        return signatures[index];
    }
}
