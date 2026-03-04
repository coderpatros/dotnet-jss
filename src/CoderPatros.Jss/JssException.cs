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

namespace CoderPatros.Jss;

/// <summary>
/// Base exception for JSS operations.
/// </summary>
public class JssException : Exception
{
    public JssException(string message) : base(message) { }
    public JssException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>
/// Thrown when signature verification fails.
/// </summary>
public sealed class JssVerificationException : JssException
{
    public JssVerificationException(string message) : base(message) { }
}

/// <summary>
/// Thrown when signing fails.
/// </summary>
public sealed class JssSigningException : JssException
{
    public JssSigningException(string message) : base(message) { }
    public JssSigningException(string message, Exception innerException) : base(message, innerException) { }
}
