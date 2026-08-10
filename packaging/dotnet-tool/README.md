# Devolutions.WinDbg.Tool

`Devolutions.WinDbg.Tool` installs the `windbg-tool` command as a .NET 10 global
or local tool on Windows.

```powershell
dotnet tool install --global Devolutions.WinDbg.Tool
windbg-tool discover
```

The package contains architecture-specific signed payloads for `win-x64` and
`win-arm64`. The installed .NET SDK/runtime must be version 10 or later.
