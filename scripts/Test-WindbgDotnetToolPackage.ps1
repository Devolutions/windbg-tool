param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$PackageDir = (Join-Path $PSScriptRoot "..\artifacts\nuget"),
    [string]$ToolPath = (Join-Path ([System.IO.Path]::GetTempPath()) "windbg-tool-package-smoke-$PID")
)

$ErrorActionPreference = "Stop"

$packageSource = (Resolve-Path -LiteralPath $PackageDir).Path
$nugetConfig = Join-Path ([System.IO.Path]::GetTempPath()) "windbg-tool-package-smoke-$PID.nuget.config"

if (Test-Path -LiteralPath $ToolPath) {
    Remove-Item -LiteralPath $ToolPath -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $ToolPath | Out-Null

@"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$packageSource" />
  </packageSources>
</configuration>
"@ | Set-Content -LiteralPath $nugetConfig -Encoding utf8

try {
    dotnet tool install Devolutions.WinDbg.Tool `
        --tool-path $ToolPath `
        --configfile $nugetConfig `
        --version $Version

    if ($LASTEXITCODE -ne 0) {
        throw "dotnet tool install failed with exit code $LASTEXITCODE"
    }

    $toolExe = @("windbg-tool", "windbg-tool.exe", "windbg-tool.cmd") |
        ForEach-Object { Join-Path $ToolPath $_ } |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1

    if (-not $toolExe) {
        throw "Installed tool shim not found under: $ToolPath"
    }

    & $toolExe discover | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "windbg-tool discover failed with exit code $LASTEXITCODE"
    }
}
finally {
    Remove-Item -LiteralPath $nugetConfig -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $ToolPath -Recurse -Force -ErrorAction SilentlyContinue
}
