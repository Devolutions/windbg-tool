using System.Runtime.CompilerServices;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace ManagedBreakpointFixture;

public static class Program
{
    public static int Main(string[] args)
    {
        Console.WriteLine(ManagedTargets.PublicEntry());
        Console.WriteLine(ManagedTargets.InvokePrivateEntry());
        Console.WriteLine(ManagedTargets.Overload("selected"));
        EmitRequestedDebugOutput(args);
        BurnRequestedCpu(args);
        SleepForStartupObservation(args);
        return 0;
    }

    private static void EmitRequestedDebugOutput(string[] args)
    {
        const string outputArgument = "--debug-output";
        var index = Array.IndexOf(args, outputArgument);
        if (index < 0 || index + 1 >= args.Length)
        {
            return;
        }

        var text = args[index + 1];
        if (text.Length > 256)
        {
            throw new ArgumentOutOfRangeException(
                outputArgument,
                "Expected at most 256 UTF-16 characters.");
        }

        OutputDebugString(text);
    }

    private static void SleepForStartupObservation(string[] args)
    {
        const string delayArgument = "--startup-observation-delay-ms";
        var index = Array.IndexOf(args, delayArgument);
        if (index < 0 || index + 1 >= args.Length)
        {
            return;
        }

        if (!int.TryParse(
                args[index + 1],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var delayMilliseconds)
            || delayMilliseconds is < 0 or > 10000)
        {
            throw new ArgumentOutOfRangeException(
                delayArgument,
                "Expected an integer delay from 0 through 10000 milliseconds.");
        }

        Thread.Sleep(delayMilliseconds);
    }

    private static void BurnRequestedCpu(string[] args)
    {
        const string durationArgument = "--cpu-burn-ms";
        var index = Array.IndexOf(args, durationArgument);
        if (index < 0 || index + 1 >= args.Length)
        {
            return;
        }

        if (!int.TryParse(
                args[index + 1],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var durationMilliseconds)
            || durationMilliseconds is < 1 or > 10000)
        {
            throw new ArgumentOutOfRangeException(
                durationArgument,
                "Expected an integer duration from 1 through 10000 milliseconds.");
        }

        var stopwatch = Stopwatch.StartNew();
        ulong accumulator = 0;
        while (stopwatch.ElapsedMilliseconds < durationMilliseconds)
        {
            accumulator = unchecked((accumulator * 6364136223846793005UL) + (ulong)Stopwatch.GetTimestamp());
        }

        GC.KeepAlive(accumulator);
    }

    [DllImport("kernel32.dll", EntryPoint = "OutputDebugStringW", CharSet = CharSet.Unicode)]
    private static extern void OutputDebugString(string text);
}

public static class ManagedTargets
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string PublicEntry() => "public";

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string InvokePrivateEntry() => PrivateEntry();

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static string PrivateEntry() => "private";

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string Overload() => "no-arguments";

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string Overload(string value) => $"string:{value}";
}
