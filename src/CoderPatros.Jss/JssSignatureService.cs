// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Text.Json.Nodes;
using CoderPatros.Jss.Crypto;
using CoderPatros.Jss.Models;
using CoderPatros.Jss.Operations;

namespace CoderPatros.Jss;

/// <summary>
/// Public facade for JSS signing, countersigning, and verification operations.
/// </summary>
public sealed class JssSignatureService
{
    private readonly JssSigner _signer;
    private readonly JssCountersigner _countersigner;
    private readonly JssVerifier _verifier;

    public JssSignatureService()
        : this(new SignatureAlgorithmRegistry(), new HashAlgorithmRegistry())
    {
    }

    public JssSignatureService(SignatureAlgorithmRegistry signatureRegistry, HashAlgorithmRegistry hashRegistry)
    {
        _signer = new JssSigner(signatureRegistry, hashRegistry);
        _countersigner = new JssCountersigner(signatureRegistry, hashRegistry);
        _verifier = new JssVerifier(signatureRegistry, hashRegistry);
    }

    /// <summary>
    /// Signs a JSON document. Returns a new document with the signature added to the "signatures" array.
    /// </summary>
    public JsonObject Sign(JsonObject document, SignatureOptions options)
    {
        return _signer.Sign(document, options);
    }

    /// <summary>
    /// Signs a JSON string. Returns the signed JSON string.
    /// </summary>
    public string Sign(string json, SignatureOptions options)
    {
        var doc = JsonNode.Parse(json)?.AsObject()
            ?? throw new JssException("Input is not a valid JSON object.");
        var signed = _signer.Sign(doc, options);
        return signed.ToJsonString();
    }

    /// <summary>
    /// Countersigns a specific signature in the document.
    /// Returns a new document with the countersignature added.
    /// </summary>
    public JsonObject Countersign(JsonObject document, CountersignOptions options)
    {
        return _countersigner.Countersign(document, options);
    }

    /// <summary>
    /// Verifies a specific signature (default: last one) in the document.
    /// </summary>
    public VerificationResult Verify(JsonObject document, VerificationOptions options, int? signatureIndex = null)
    {
        return _verifier.Verify(document, options, signatureIndex);
    }

    /// <summary>
    /// Verifies a specific signature in the document from JSON string.
    /// </summary>
    public VerificationResult Verify(string json, VerificationOptions options, int? signatureIndex = null)
    {
        var doc = JsonNode.Parse(json)?.AsObject()
            ?? throw new JssException("Input is not a valid JSON object.");
        return _verifier.Verify(doc, options, signatureIndex);
    }

    /// <summary>
    /// Verifies all signatures in the document.
    /// </summary>
    public VerificationResult VerifyAll(JsonObject document, VerificationOptions options)
    {
        return _verifier.VerifyAll(document, options);
    }

    /// <summary>
    /// Verifies the countersignature on a specific signature in the document.
    /// </summary>
    public VerificationResult VerifyCountersignature(JsonObject document, VerificationOptions options, int signatureIndex = 0)
    {
        return _verifier.VerifyCountersignature(document, options, signatureIndex);
    }
}
