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
            File.WriteAllText(filePath, content);
        }
    }
}
