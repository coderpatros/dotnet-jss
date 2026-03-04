// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Text.Json.Nodes;
using CoderPatros.Jss.Models;

namespace CoderPatros.Jss.Serialization;

/// <summary>
/// Serializes/deserializes JssSignatureCore to/from JsonObject.
/// Uses JSS property names: hash_algorithm, algorithm, public_key, public_cert_chain, cert_url, thumbprint, value, signature.
/// </summary>
internal static class JssSignatureCoreSerializer
{
    private static readonly HashSet<string> KnownProperties = new(StringComparer.Ordinal)
    {
        "hash_algorithm", "algorithm", "public_key", "public_cert_chain",
        "cert_url", "thumbprint", "value", "signature"
    };

    public static JsonObject Serialize(JssSignatureCore sig)
    {
        var obj = new JsonObject
        {
            ["algorithm"] = sig.Algorithm,
            ["hash_algorithm"] = sig.HashAlgorithm
        };

        if (sig.PublicKey is not null)
            obj["public_key"] = sig.PublicKey;

        if (sig.PublicCertChain is not null)
        {
            var arr = new JsonArray();
            foreach (var cert in sig.PublicCertChain)
                arr.Add(JsonValue.Create(cert));
            obj["public_cert_chain"] = arr;
        }

        if (sig.CertUrl is not null)
            obj["cert_url"] = sig.CertUrl;

        if (sig.Thumbprint is not null)
            obj["thumbprint"] = sig.Thumbprint;

        if (sig.Metadata is not null && sig.Metadata.Count > 0)
        {
            foreach (var (key, value) in sig.Metadata)
            {
                if (KnownProperties.Contains(key))
                    throw new JssException($"Metadata key '{key}' conflicts with a reserved JSS signature property.");
                obj[key] = value?.DeepClone();
            }
        }

        if (sig.Countersignature is not null)
            obj["signature"] = Serialize(sig.Countersignature);

        if (sig.Value is not null)
            obj["value"] = sig.Value;

        return obj;
    }

    public static JssSignatureCore Deserialize(JsonObject obj)
    {
        var algorithm = obj["algorithm"]?.GetValue<string>()
            ?? throw new JssException("Signature object missing 'algorithm' property.");

        var hashAlgorithm = obj["hash_algorithm"]?.GetValue<string>()
            ?? throw new JssException("Signature object missing 'hash_algorithm' property.");

        var publicKey = obj["public_key"]?.GetValue<string>();

        List<string>? publicCertChain = null;
        if (obj["public_cert_chain"] is JsonArray certArr)
            publicCertChain = certArr.Select(n => n!.GetValue<string>()).ToList();

        var certUrl = obj["cert_url"]?.GetValue<string>();
        var thumbprint = obj["thumbprint"]?.GetValue<string>();
        var value = obj["value"]?.GetValue<string>();

        JssSignatureCore? countersignature = null;
        if (obj["signature"] is JsonObject counterSigObj)
            countersignature = Deserialize(counterSigObj);

        // Metadata: any properties not in the known set
        Dictionary<string, JsonNode?>? metadata = null;
        foreach (var prop in obj)
        {
            if (!KnownProperties.Contains(prop.Key))
            {
                metadata ??= new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
                metadata[prop.Key] = prop.Value?.DeepClone();
            }
        }

        return new JssSignatureCore
        {
            HashAlgorithm = hashAlgorithm,
            Algorithm = algorithm,
            PublicKey = publicKey,
            PublicCertChain = publicCertChain,
            CertUrl = certUrl,
            Thumbprint = thumbprint,
            Value = value,
            Countersignature = countersignature,
            Metadata = metadata
        };
    }
}
