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

using System.Globalization;

namespace CoderPatros.Jss.Canonicalization;

/// <summary>
/// ECMA-262 7.1.12.1 Number::toString algorithm for JCS (RFC 8785).
/// Converts IEEE 754 double values to their canonical ES6 string representation.
/// </summary>
internal static class ES6NumberSerializer
{
    public static string Serialize(double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value))
            throw new ArgumentException("NaN and Infinity are not valid JSON numbers.");

        if (value == 0.0)
            return "0";

        if (value < 0)
            return "-" + Serialize(-value);

        // Use R format to get round-trip precision
        var str = value.ToString("R", CultureInfo.InvariantCulture);

        // If it already contains 'E', it's in scientific notation from .NET.
        // We need to normalize to ES6 format.
        if (str.Contains('E'))
            return FormatScientific(value, str);

        // Check if ES6 would use scientific notation:
        // ES6 uses scientific notation for very large or very small numbers.
        // Specifically when the integer representation needs it.
        return NormalizeDecimal(value, str);
    }

    private static string NormalizeDecimal(double value, string dotnetStr)
    {
        // ES6 spec: If the number has k digits and n is the exponent (value = digits * 10^(n-k)):
        //   - If k <= n <= 21: integer notation
        //   - If 0 < n <= 0 (well, n <= 0) and n > -6: decimal with leading zeros
        //   - Otherwise: scientific notation

        // Parse the digits and exponent
        var (digits, exponent) = GetDigitsAndExponent(value);
        int k = digits.Length;
        int n = exponent; // number of integer digits

        if (k <= n && n <= 21)
        {
            // Integer notation: digits followed by zeros
            return digits + new string('0', n - k);
        }

        if (0 < n && n < k)
        {
            // Decimal within the digits
            return digits[..n] + "." + digits[n..];
        }

        if (-6 < n && n <= 0)
        {
            // 0.000...digits
            return "0." + new string('0', -n) + digits;
        }

        // Scientific notation
        return FormatES6Scientific(digits, n);
    }

    private static string FormatES6Scientific(string digits, int n)
    {
        var mantissa = digits.Length == 1
            ? digits
            : digits[0] + "." + digits[1..];

        var exp = n - 1;
        var expSign = exp >= 0 ? "+" : "-";
        return mantissa + "e" + expSign + Math.Abs(exp);
    }

    private static (string Digits, int Exponent) GetDigitsAndExponent(double value)
    {
        // Use R format to get all significant digits
        var str = value.ToString("R", CultureInfo.InvariantCulture);

        if (str.Contains('E') || str.Contains('e'))
        {
            var parts = str.Split('E', 'e');
            var mantissa = parts[0];
            var exp = int.Parse(parts[1], CultureInfo.InvariantCulture);

            var cleanMantissa = mantissa.Replace(".", "").TrimStart('0');
            if (string.IsNullOrEmpty(cleanMantissa))
                return ("0", 1);

            var dotIndex = mantissa.IndexOf('.');
            int integerDigits = dotIndex >= 0 ? dotIndex : mantissa.Length;

            return (cleanMantissa, integerDigits + exp);
        }

        // Regular decimal number
        var dotIdx = str.IndexOf('.');
        if (dotIdx < 0)
        {
            // Integer - strip trailing zeros for digits, count them for exponent
            var trimmed = str.TrimEnd('0');
            if (string.IsNullOrEmpty(trimmed))
                return ("0", 1);
            return (trimmed, str.Length);
        }

        // Has decimal point
        var intPart = str[..dotIdx];
        var fracPart = str[(dotIdx + 1)..];
        var allDigits = intPart + fracPart;

        // Remove trailing zeros from the combined digits
        allDigits = allDigits.TrimEnd('0');

        if (intPart == "0")
        {
            // 0.00xyz -> digits = "xyz", exponent = -(number of leading zeros in frac)
            var stripped = fracPart.TrimStart('0');
            if (string.IsNullOrEmpty(stripped))
                return ("0", 1);
            var leadingZeros = fracPart.Length - fracPart.TrimStart('0').Length;
            return (stripped.TrimEnd('0'), -leadingZeros);
        }

        // Non-zero integer part
        var cleanDigits = allDigits.TrimStart('0');
        if (string.IsNullOrEmpty(cleanDigits))
            return ("0", 1);
        return (cleanDigits, intPart.Length);
    }

    private static string FormatScientific(double value, string dotnetStr)
    {
        // .NET scientific -> ES6 scientific
        return NormalizeDecimal(value, dotnetStr);
    }
}
