// This file is part of CoderPatros.JSS Library for .NET
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CoderPatros.Jss.Canonicalization;

/// <summary>
/// RFC 8785 JSON Canonicalization Scheme (JCS).
/// Produces deterministic JSON by sorting object keys and using ES6 number formatting.
/// </summary>
public static class JsonCanonicalizer
{
    public static string Canonicalize(string json)
    {
        var node = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow
        });

        return Canonicalize(node);
    }

    public static string Canonicalize(JsonNode? node)
    {
        var sb = new StringBuilder();
        WriteCanonical(node, sb);
        return sb.ToString();
    }

    private static void WriteCanonical(JsonNode? node, StringBuilder sb)
    {
        switch (node)
        {
            case null:
                sb.Append("null");
                break;

            case JsonObject obj:
                WriteObject(obj, sb);
                break;

            case JsonArray arr:
                WriteArray(arr, sb);
                break;

            case JsonValue val:
                WriteValue(val, sb);
                break;
        }
    }

    private static void WriteObject(JsonObject obj, StringBuilder sb)
    {
        sb.Append('{');

        // RFC 8785: Sort by UTF-16 code unit order (StringComparer.Ordinal)
        var sortedProperties = obj
            .OrderBy(p => p.Key, StringComparer.Ordinal)
            .ToList();

        for (int i = 0; i < sortedProperties.Count; i++)
        {
            if (i > 0) sb.Append(',');
            WriteString(sortedProperties[i].Key, sb);
            sb.Append(':');
            WriteCanonical(sortedProperties[i].Value, sb);
        }

        sb.Append('}');
    }

    private static void WriteArray(JsonArray arr, StringBuilder sb)
    {
        sb.Append('[');

        for (int i = 0; i < arr.Count; i++)
        {
            if (i > 0) sb.Append(',');
            WriteCanonical(arr[i], sb);
        }

        sb.Append(']');
    }

    private static void WriteValue(JsonValue val, StringBuilder sb)
    {
        // JsonValue may wrap a JsonElement (parsed JSON) or a native CLR type (programmatic)
        if (val.TryGetValue<JsonElement>(out var element))
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.String:
                    WriteString(element.GetString()!, sb);
                    return;
                case JsonValueKind.Number:
                    sb.Append(ES6NumberSerializer.Serialize(element.GetDouble()));
                    return;
                case JsonValueKind.True:
                    sb.Append("true");
                    return;
                case JsonValueKind.False:
                    sb.Append("false");
                    return;
                case JsonValueKind.Null:
                    sb.Append("null");
                    return;
            }
        }

        // Handle native CLR types from programmatic JsonNode construction
        if (val.TryGetValue<string>(out var s))
        {
            WriteString(s, sb);
        }
        else if (val.TryGetValue<bool>(out var b))
        {
            sb.Append(b ? "true" : "false");
        }
        else if (val.TryGetValue<double>(out var d))
        {
            sb.Append(ES6NumberSerializer.Serialize(d));
        }
        else if (val.TryGetValue<long>(out var l))
        {
            sb.Append(ES6NumberSerializer.Serialize(l));
        }
        else if (val.TryGetValue<int>(out var i))
        {
            sb.Append(ES6NumberSerializer.Serialize(i));
        }
        else
        {
            // Fallback: serialize via System.Text.Json and re-parse
            var json = val.ToJsonString();
            sb.Append(json);
        }
    }

    private static void WriteString(string value, StringBuilder sb)
    {
        sb.Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20)
                    {
                        sb.Append($"\\u{(int)c:x4}");
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        sb.Append('"');
    }
}
