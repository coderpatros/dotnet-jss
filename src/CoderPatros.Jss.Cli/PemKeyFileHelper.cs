// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

namespace CoderPatros.Jss.Cli;

/// <summary>
/// PEM file I/O helpers with secure file permissions.
/// </summary>
internal static class PemKeyFileHelper
{
    public static void WriteSecretFile(string filePath, string content, bool overwrite = false)
    {
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            if (overwrite && File.Exists(filePath))
                File.Delete(filePath);

            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            };
            using var stream = new FileStream(filePath, options);
            using var writer = new StreamWriter(stream);
            writer.Write(content);
        }
        else
        {
            // Windows: FileStream with CreateNew prevents overwriting.
            // Note: Windows does not support UnixCreateMode; file inherits directory ACLs.
            // For stronger protection, configure directory-level ACLs to restrict access.
            if (overwrite && File.Exists(filePath))
                File.Delete(filePath);
            using var stream = new FileStream(filePath, FileMode.CreateNew, FileAccess.Write);
            using var writer = new StreamWriter(stream);
            writer.Write(content);
        }
    }
}
