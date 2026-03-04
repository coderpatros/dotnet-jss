// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

namespace CoderPatros.Jss.Models;

/// <summary>
/// JSS signing algorithm identifier constants from ITU-T X.590 Table 1.
/// </summary>
public static class JssAlgorithm
{
    // ECDSA
    public const string ES256 = "ES256";
    public const string ES384 = "ES384";
    public const string ES512 = "ES512";

    // RSA PKCS#1 v1.5
    public const string RS256 = "RS256";
    public const string RS384 = "RS384";
    public const string RS512 = "RS512";

    // RSA-PSS
    public const string PS256 = "PS256";
    public const string PS384 = "PS384";
    public const string PS512 = "PS512";

    // EdDSA
    public const string Ed25519 = "Ed25519";
    public const string Ed448 = "Ed448";

    // XMSS (identifiers from Table 1)
    public const string XMSS_SHA2_10_256 = "XMSS-SHA2_10_256";
    public const string XMSS_SHA2_16_256 = "XMSS-SHA2_16_256";
    public const string XMSS_SHA2_20_256 = "XMSS-SHA2_20_256";

    // LMS (identifiers from Table 1)
    public const string LMS_SHA256_M32_H5 = "LMS_SHA256_M32_H5";
    public const string LMS_SHA256_M32_H10 = "LMS_SHA256_M32_H10";
    public const string LMS_SHA256_M32_H15 = "LMS_SHA256_M32_H15";
    public const string LMS_SHA256_M32_H20 = "LMS_SHA256_M32_H20";
    public const string LMS_SHA256_M32_H25 = "LMS_SHA256_M32_H25";
}
