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
/// Orchestrates JSS countersigning operations per ITU-T X.590 clause 7.2.
/// </summary>
internal sealed class JssCountersigner
{
    private readonly SignatureAlgorithmRegistry _signatureRegistry;
    private readonly HashAlgorithmRegistry _hashRegistry;

    public JssCountersigner(SignatureAlgorithmRegistry signatureRegistry, HashAlgorithmRegistry hashRegistry)
    {
        _signatureRegistry = signatureRegistry;
        _hashRegistry = hashRegistry;
    }

    /// <summary>
    /// Countersigns a specific signature in the document. Never mutates the input.
    /// Clause 7.2: The target signature IS the signed data. A nested "signature" property is added to it.
    /// </summary>
    public JsonObject Countersign(JsonObject document, CountersignOptions options)
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

        // Extract signatures
        var sigArray = document["signatures"] as JsonArray
            ?? throw new JssException("Document does not contain a 'signatures' property.");

        if (options.SignatureIndex < 0 || options.SignatureIndex >= sigArray.Count)
            throw new JssException($"Signature index {options.SignatureIndex} is out of range.");

        // Check if the target signature already has a countersignature
        var targetSigCheck = (sigArray[options.SignatureIndex]!).AsObject();
        if (targetSigCheck.ContainsKey("signature"))
            throw new JssException("The target signature already has a countersignature. Remove the existing countersignature before adding a new one.");

        var clone = document.DeepClone().AsObject();

        // Get the target signature
        var targetSigNode = (clone["signatures"] as JsonArray)![options.SignatureIndex]!.AsObject();

        // Create countersig metadata (without value)
        var counterSigMetadata = new JssSignatureCore
        {
            HashAlgorithm = options.HashAlgorithm,
            Algorithm = options.Algorithm,
            PublicKey = options.PublicKey,
            PublicCertChain = options.PublicCertChain,
            CertUrl = options.CertUrl,
            Thumbprint = options.Thumbprint
        };

        // Build signing input: clone doc, keep only target sig in array,
        // add countersig object (no value) as "signature" property of target
        var signingDoc = document.DeepClone().AsObject();
        var targetForSigning = (sigArray[options.SignatureIndex]!.DeepClone()).AsObject();

        // Add countersig (without value) as nested "signature" property
        var counterSigObj = JssSignatureCoreSerializer.Serialize(counterSigMetadata);
        targetForSigning["signature"] = counterSigObj;

        // Replace signatures array with just the target
        signingDoc["signatures"] = new JsonArray(targetForSigning);

        // JCS canonicalize (clause 7.2.4)
        var canonical = JsonCanonicalizer.Canonicalize(signingDoc);
        var canonicalBytes = Encoding.UTF8.GetBytes(canonical);

        // Hash (clause 7.2.5)
        var hash = hashAlgorithm.ComputeHash(canonicalBytes);

        // Sign (clause 7.2.6)
        var signatureBytes = sigAlgorithm.Sign(hash, options.Key);
        var signatureValue = Base64UrlEncoding.Encode(signatureBytes);

        // Reassemble: add countersig with value to target
        var finalCounterSig = counterSigMetadata with { Value = signatureValue };
        var finalCounterSigObj = JssSignatureCoreSerializer.Serialize(finalCounterSig);

        // Build final document
        var result = document.DeepClone().AsObject();
        var resultSigArray = (result["signatures"] as JsonArray)!;
        var resultTarget = resultSigArray[options.SignatureIndex]!.AsObject();
        resultTarget["signature"] = finalCounterSigObj;

        return result;
    }
}
