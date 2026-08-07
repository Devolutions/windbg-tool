param(
    [string] $OutDir = "..\target\ttd-runtime",
    [ValidateSet("x64", "x86", "arm64")]
    [string] $Arch = "x64",
    [string] $MsixBundle = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$resolvedOutDir = Resolve-Path -Path $OutDir -ErrorAction SilentlyContinue
if ($null -eq $resolvedOutDir) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
    $resolvedOutDir = Resolve-Path -Path $OutDir
}

$tempDir = Join-Path $resolvedOutDir "TempTtdReplay"
if (Test-Path $tempDir) {
    Remove-Item $tempDir -Recurse -Force
}
New-Item -ItemType Directory -Path $tempDir | Out-Null

$bundleZip = Join-Path $tempDir "ttd.zip"
$replayFiles = @("TTDReplay.dll", "TTDReplayCPU.dll")

try {
    if ($MsixBundle -eq "") {
        Write-Host "Downloading TTD appinstaller metadata from https://aka.ms/ttd/download"
        $appInstaller = Join-Path $tempDir "ttd.appinstaller"
        Invoke-WebRequest "https://aka.ms/ttd/download" -OutFile $appInstaller
        $bundleUri = ([xml](Get-Content $appInstaller)).AppInstaller.MainBundle.Uri
        Write-Host "Downloading TTD bundle from $bundleUri"
        Invoke-WebRequest $bundleUri -OutFile $bundleZip
    }
    else {
        Copy-Item $MsixBundle -Destination $bundleZip
    }

    $bundleDir = Join-Path $tempDir "bundle"
    Expand-Archive -DestinationPath $bundleDir $bundleZip -Force

    $msixName = "TTD-$Arch.msix"
    $msixPath = Join-Path $bundleDir $msixName
    if (!(Test-Path $msixPath)) {
        throw "Could not find $msixName inside the downloaded bundle."
    }

    $msixZip = Join-Path $tempDir "TTD-$Arch.zip"
    Copy-Item $msixPath $msixZip

    $expandedMsix = Join-Path $tempDir "expanded"
    Expand-Archive -DestinationPath $expandedMsix $msixZip -Force

    foreach ($fileName in $replayFiles) {
        $source = Get-ChildItem -Path $expandedMsix -Filter $fileName -Recurse -File | Select-Object -First 1
        if ($null -eq $source) {
            throw "Could not find $fileName in $msixName."
        }
        Copy-Item $source.FullName -Destination (Join-Path $resolvedOutDir $fileName) -Force
    }

    Write-Host "TTD replay runtime copied to $resolvedOutDir"
}
finally {
    if (Test-Path $tempDir) {
        Remove-Item $tempDir -Recurse -Force
    }
}
