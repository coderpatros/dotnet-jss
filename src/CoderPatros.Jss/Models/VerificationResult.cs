// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

namespace CoderPatros.Jss.Models;

/// <summary>
/// Outcome of a signature verification operation.
/// </summary>
public sealed record VerificationResult
{
    public required bool IsValid { get; init; }
    public string? Error { get; init; }

    public static VerificationResult Success() => new() { IsValid = true };
    public static VerificationResult Failure(string error) => new() { IsValid = false, Error = error };
}
