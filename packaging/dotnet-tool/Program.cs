using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;

return Run(args);

static int Run(string[] args)
{
    string nativeExecutablePath = Path.Combine(AppContext.BaseDirectory, "windbg-tool.exe");

    if (!File.Exists(nativeExecutablePath))
    {
        Console.Error.WriteLine("No native windbg-tool executable is available for this runtime identifier in the installed package.");
        return 1;
    }

    var processStartInfo = new ProcessStartInfo(nativeExecutablePath)
    {
        UseShellExecute = false,
    };

    foreach (string argument in args)
    {
        processStartInfo.ArgumentList.Add(argument);
    }

    try
    {
        using Process? process = Process.Start(processStartInfo);
        if (process is null)
        {
            Console.Error.WriteLine("Unable to start the native windbg-tool executable.");
            return 1;
        }

        process.WaitForExit();
        return process.ExitCode;
    }
    catch (Win32Exception ex)
    {
        Console.Error.WriteLine($"Unable to start the native windbg-tool executable: {ex.Message}");
        return 1;
    }
    catch (InvalidOperationException ex)
    {
        Console.Error.WriteLine($"Unable to start the native windbg-tool executable: {ex.Message}");
        return 1;
    }
}
