// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Text;
using System.Text.Json.Nodes;
using CoderPatros.Jss.Canonicalization;
using CoderPatros.Jss.Crypto;
using CoderPatros.Jss.Models;
using CoderPatros.Jss.Serialization;

namespace CoderPatros.Jss.Operations;

/// <summary>
/// Orchestrates JSS signing operations per ITU-T X.590 clause 7.1.
/// </summary>
internal sealed class JssSigner
{
    private readonly SignatureAlgorithmRegistry _signatureRegistry;
    private readonly HashAlgorithmRegistry _hashRegistry;

    public JssSigner(SignatureAlgorithmRegistry signatureRegistry, HashAlgorithmRegistry hashRegistry)
    {
        _signatureRegistry = signatureRegistry;
        _hashRegistry = hashRegistry;
    }

    /// <summary>
    /// Signs a document. Never mutates the input.
    /// Clause 7.1: existing signatures go at START, new sig at END.
    /// </summary>
    public JsonObject Sign(JsonObject document, SignatureOptions options)
    {
        // ITU-T X.590 clause 6.2.1: at least one key identification property MUST be populated
        if (options.PublicKey is null &&
            options.PublicCertChain is null &&
            options.CertUrl is null &&
            options.Thumbprint is null)
        {
            throw new JssException(
                "At least one key identification property must be set: PublicKey, PublicCertChain, CertUrl, or Thumbprint (ITU-T X.590 clause 6.2.1).");
        }

        var sigAlgorithm = _signatureRegistry.Get(options.Algorithm);
        var hashAlgorithm = _hashRegistry.Get(options.HashAlgorithm);

        var clone = document.DeepClone().AsObject();

        // Save existing signatures (if any) for reassembly
        JsonArray? existingSignatures = null;
        if (clone["signatures"] is JsonArray existing)
        {
            existingSignatures = existing.DeepClone().AsArray();
            clone.Remove("signatures");
        }

        // Create signature metadata object (without value)
        var sigMetadata = new JssSignatureCore
        {
            HashAlgorithm = options.HashAlgorithm,
            Algorithm = options.Algorithm,
            PublicKey = options.PublicKey,
            PublicCertChain = options.PublicCertChain,
            CertUrl = options.CertUrl,
            Thumbprint = options.Thumbprint,
            Metadata = options.Metadata
        };

        // Add as sole entry in signatures array (clause 7.1.3)
        var sigObj = JssSignatureCoreSerializer.Serialize(sigMetadata);
        clone["signatures"] = new JsonArray(sigObj);

        // JCS canonicalize (clause 7.1.4)
        var canonical = JsonCanonicalizer.Canonicalize(clone);
        var canonicalBytes = Encoding.UTF8.GetBytes(canonical);

        // Hash (clause 7.1.5)
        var hash = hashAlgorithm.ComputeHash(canonicalBytes);

        // Sign hash (clause 7.1.6)
        var signatureBytes = sigAlgorithm.Sign(hash, options.Key);
        var signatureValue = Base64UrlEncoding.Encode(signatureBytes);

        // Reassemble: old sigs at START, new sig (with value) at END (clause 7.1.7)
        var finalSig = sigMetadata with { Value = signatureValue };
        var finalSigObj = JssSignatureCoreSerializer.Serialize(finalSig);

        var result = document.DeepClone().AsObject();
        result.Remove("signatures");

        var finalArray = new JsonArray();
        if (existingSignatures is not null)
        {
            foreach (var existingSig in existingSignatures)
                finalArray.Add(existingSig!.DeepClone());
        }
        finalArray.Add(finalSigObj);

        result["signatures"] = finalArray;
        return result;
    }
}
