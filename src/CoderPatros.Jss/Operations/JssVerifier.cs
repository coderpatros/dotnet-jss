// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Text;
using System.Text.Json.Nodes;
using CoderPatros.Jss.Canonicalization;
using CoderPatros.Jss.Crypto;
using CoderPatros.Jss.Keys;
using CoderPatros.Jss.Models;
using CoderPatros.Jss.Serialization;

namespace CoderPatros.Jss.Operations;

/// <summary>
/// Orchestrates JSS verification operations per ITU-T X.590 clause 8.1.
/// </summary>
internal sealed class JssVerifier
{
    private readonly SignatureAlgorithmRegistry _signatureRegistry;
    private readonly HashAlgorithmRegistry _hashRegistry;

    public JssVerifier(SignatureAlgorithmRegistry signatureRegistry, HashAlgorithmRegistry hashRegistry)
    {
        _signatureRegistry = signatureRegistry;
        _hashRegistry = hashRegistry;
    }

    /// <summary>
    /// Verifies a single signature at the given index (default: last).
    /// </summary>
    public VerificationResult Verify(JsonObject document, VerificationOptions options, int? signatureIndex = null)
    {
        var signatures = SignatureObjectManipulator.ExtractSignatures(document);
        if (signatures.Count == 0)
            throw new JssException("Document has no signatures.");

        var idx = signatureIndex ?? (signatures.Count - 1);
        if (idx < 0 || idx >= signatures.Count)
            throw new JssException($"Signature index {idx} is out of range.");

        var sig = signatures[idx];

        var algorithmCheck = CheckAcceptedAlgorithm(sig.Algorithm, options);
        if (algorithmCheck is not null)
            return algorithmCheck;

        var key = ResolveKey(sig, options);

        try
        {
            return VerifySingleSignature(document, sig, idx, key);
        }
        catch (Exception ex)
        {
            return VerificationResult.Failure($"Verification error: {ex.Message}");
        }
    }

    /// <summary>
    /// Verifies all signatures in the document.
    /// </summary>
    public VerificationResult VerifyAll(JsonObject document, VerificationOptions options)
    {
        var signatures = SignatureObjectManipulator.ExtractSignatures(document);
        if (signatures.Count == 0)
            return VerificationResult.Failure("Document has no signatures.");

        for (int i = 0; i < signatures.Count; i++)
        {
            var sig = signatures[i];

            var algorithmCheck = CheckAcceptedAlgorithm(sig.Algorithm, options);
            if (algorithmCheck is not null)
                return algorithmCheck;

            try
            {
                var key = ResolveKey(sig, options);
                var result = VerifySingleSignature(document, sig, i, key);
                if (!result.IsValid)
                    return VerificationResult.Failure($"Signature {i} verification failed: {result.Error}");
            }
            catch (Exception ex)
            {
                return VerificationResult.Failure($"Signature {i} verification failed: {ex.Message}");
            }
        }

        return VerificationResult.Success();
    }

    private VerificationResult VerifySingleSignature(JsonObject document, JssSignatureCore sig, int index, VerificationKey key)
    {
        if (sig.Value is null)
            return VerificationResult.Failure("Signature has no value.");

        var sigAlgorithm = _signatureRegistry.Get(sig.Algorithm);
        var hashAlgorithm = _hashRegistry.Get(sig.HashAlgorithm);

        // Clause 8.1: Extract target sig, save and remove its "value".
        // Keep only target sig in array (remove others).
        // Also strip the countersignature — it was added after the original signing.
        var clone = document.DeepClone().AsObject();

        // Build the signature object without "value" and without nested countersignature
        var sigWithoutValue = sig with { Value = null, Countersignature = null };
        var sigObj = JssSignatureCoreSerializer.Serialize(sigWithoutValue);

        // Replace signatures array with just this signature (without value)
        clone["signatures"] = new JsonArray(sigObj);

        // JCS canonicalize
        var canonical = JsonCanonicalizer.Canonicalize(clone);
        var canonicalBytes = Encoding.UTF8.GetBytes(canonical);

        // Hash
        var hash = hashAlgorithm.ComputeHash(canonicalBytes);

        // Verify
        var signatureBytes = Base64UrlEncoding.Decode(sig.Value);
        var isValid = sigAlgorithm.Verify(hash, signatureBytes, key);

        return isValid ? VerificationResult.Success() : VerificationResult.Failure("Signature is invalid.");
    }

    /// <summary>
    /// Verifies the countersignature on a specific signature.
    /// Reconstructs the signing input per clause 7.2: document with only the target signature
    /// (including countersig metadata without value), then canonicalizes, hashes, and verifies.
    /// </summary>
    public VerificationResult VerifyCountersignature(JsonObject document, VerificationOptions options, int signatureIndex = 0)
    {
        var signatures = SignatureObjectManipulator.ExtractSignatures(document);
        if (signatures.Count == 0)
            throw new JssException("Document has no signatures.");

        if (signatureIndex < 0 || signatureIndex >= signatures.Count)
            throw new JssException($"Signature index {signatureIndex} is out of range.");

        var targetSig = signatures[signatureIndex];
        var counterSig = targetSig.Countersignature
            ?? throw new JssException($"Signature at index {signatureIndex} has no countersignature.");

        var algorithmCheck = CheckAcceptedAlgorithm(counterSig.Algorithm, options);
        if (algorithmCheck is not null)
            return algorithmCheck;

        if (counterSig.Value is null)
            return VerificationResult.Failure("Countersignature has no value.");

        var key = ResolveKey(counterSig, options);

        try
        {
            var sigAlgorithm = _signatureRegistry.Get(counterSig.Algorithm);
            var hashAlgorithm = _hashRegistry.Get(counterSig.HashAlgorithm);

            // Reconstruct signing input per clause 7.2:
            // The document with only the target signature in the array,
            // and the countersig metadata (without value) nested as "signature" property.
            var clone = document.DeepClone().AsObject();

            // Build target sig as it appeared during countersigning:
            // full target sig (with value) + countersig metadata (without value)
            var targetSigNode = (clone["signatures"] as JsonArray)![signatureIndex]!.DeepClone().AsObject();

            // Replace the nested "signature" with one that has no value
            var counterSigWithoutValue = counterSig with { Value = null };
            var counterSigObj = JssSignatureCoreSerializer.Serialize(counterSigWithoutValue);
            targetSigNode["signature"] = counterSigObj;

            // Replace signatures array with just this target
            clone["signatures"] = new JsonArray(targetSigNode);

            // JCS canonicalize
            var canonical = Canonicalization.JsonCanonicalizer.Canonicalize(clone);
            var canonicalBytes = Encoding.UTF8.GetBytes(canonical);

            // Hash
            var hash = hashAlgorithm.ComputeHash(canonicalBytes);

            // Verify
            var signatureBytes = Base64UrlEncoding.Decode(counterSig.Value);
            var isValid = sigAlgorithm.Verify(hash, signatureBytes, key);

            return isValid
                ? VerificationResult.Success()
                : VerificationResult.Failure("Countersignature is invalid.");
        }
        catch (Exception ex)
        {
            return VerificationResult.Failure($"Countersignature verification error: {ex.Message}");
        }
    }

    private static VerificationResult? CheckAcceptedAlgorithm(string algorithm, VerificationOptions options)
    {
        if (options.AcceptedAlgorithms is not null && !options.AcceptedAlgorithms.Contains(algorithm))
            return VerificationResult.Failure($"Algorithm '{algorithm}' is not in the accepted algorithms list.");
        return null;
    }

    private static VerificationKey ResolveKey(JssSignatureCore sig, VerificationOptions options)
    {
        if (options.KeyResolver is not null)
            return options.KeyResolver(sig);

        if (options.Key is not null)
            return options.Key;

        if (options.AllowEmbeddedPublicKey && sig.PublicKey is not null)
            return PemKeyHelper.ParsePublicKey(sig.PublicKey, sig.Algorithm);

        if (options.AllowEmbeddedPublicKey && sig.PublicCertChain is not null)
            return CertificateHelper.ExtractPublicKey(sig.PublicCertChain, sig.Algorithm);

        throw new JssException("No verification key available. Provide a key, key resolver, or enable AllowEmbeddedPublicKey.");
    }
}
