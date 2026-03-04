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

namespace CoderPatros.Jss.Serialization;

/// <summary>
/// RFC 4648 base64url encoding without padding.
/// </summary>
public static class Base64UrlEncoding
{
    public static string Encode(ReadOnlySpan<byte> data)
    {
        var base64 = Convert.ToBase64String(data);
        return base64
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    public static byte[] Decode(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            throw new JssException("Base64url input must not be null or empty.");

        // Validate that input contains only valid base64url characters
        foreach (var c in encoded)
        {
            if (!IsValidBase64UrlChar(c))
                throw new JssException($"Invalid character '{c}' in base64url input.");
        }

        var base64 = encoded
            .Replace('-', '+')
            .Replace('_', '/');

        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
            case 1: throw new JssException("Invalid base64url input length.");
        }

        return Convert.FromBase64String(base64);
    }

    private static bool IsValidBase64UrlChar(char c)
    {
        return c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
    }
}
