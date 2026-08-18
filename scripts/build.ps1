param(
    [switch]$Race
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$minimumGoMajor = 1
$minimumGoMinor = 23

function Test-GoVersion([string]$GoExe) {
    if ([string]::IsNullOrWhiteSpace($GoExe) -or -not (Test-Path -LiteralPath $GoExe)) {
        return $false
    }
    try {
        $text = (& $GoExe version 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -ne 0) { return $false }
        if ($text -notmatch 'go(?<major>\d+)\.(?<minor>\d+)') { return $false }
        $major = [int]$Matches['major']
        $minor = [int]$Matches['minor']
        return ($major -gt $minimumGoMajor) -or ($major -eq $minimumGoMajor -and $minor -ge $minimumGoMinor)
    } catch {
        return $false
    }
}

function Find-SystemGo {
    $cmd = Get-Command go.exe -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        $cmd = Get-Command go -ErrorAction SilentlyContinue
    }
    if ($null -ne $cmd -and (Test-GoVersion $cmd.Source)) {
        return $cmd.Source
    }
    return $null
}

function Install-PortableGo([string]$ProjectRoot) {
    $toolsDir = Join-Path $ProjectRoot '.tools'
    $goDir = Join-Path $toolsDir 'go'
    $goExe = Join-Path $goDir 'bin\go.exe'

    if (Test-GoVersion $goExe) {
        return $goExe
    }

    Write-Host 'Go 1.23+ was not found. Downloading a portable official Go toolchain...' -ForegroundColor Yellow

    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
    $downloadDir = Join-Path $toolsDir 'downloads'
    New-Item -ItemType Directory -Force -Path $downloadDir | Out-Null

    # PowerShell 5.1 on older Windows installations can otherwise negotiate an old TLS version.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {}

    try {
        $releases = Invoke-RestMethod -Uri 'https://go.dev/dl/?mode=json' -Method Get
    } catch {
        throw "Could not query the official Go download API. Install Go 1.23+ manually and reopen the terminal. Original error: $($_.Exception.Message)"
    }

    $release = $releases | Where-Object { $_.stable -eq $true } | Select-Object -First 1
    if ($null -eq $release) {
        throw 'The official Go download API returned no stable release.'
    }

    $archive = $release.files | Where-Object {
        $_.os -eq 'windows' -and $_.arch -eq 'amd64' -and $_.kind -eq 'archive'
    } | Select-Object -First 1
    if ($null -eq $archive) {
        throw "The official Go download API did not list a Windows amd64 archive for $($release.version)."
    }

    $zipPath = Join-Path $downloadDir $archive.filename
    $downloadUrl = 'https://go.dev/dl/' + $archive.filename

    $needDownload = $true
    if (Test-Path -LiteralPath $zipPath) {
        $actual = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -eq ([string]$archive.sha256).ToLowerInvariant()) {
            $needDownload = $false
        } else {
            Remove-Item -LiteralPath $zipPath -Force
        }
    }

    if ($needDownload) {
        Write-Host "Downloading $($archive.filename)..."
        try {
            Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
        } catch {
            Remove-Item -LiteralPath $zipPath -Force -ErrorAction SilentlyContinue
            throw "Could not download $downloadUrl. Install Go 1.23+ manually and reopen the terminal. Original error: $($_.Exception.Message)"
        }
    }

    $actualHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedHash = ([string]$archive.sha256).ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw "Go archive SHA-256 mismatch. Expected $expectedHash, got $actualHash."
    }

    $extractDir = Join-Path $toolsDir ('extract-' + [Guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
        Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force
        $extractedGo = Join-Path $extractDir 'go'
        if (-not (Test-Path -LiteralPath (Join-Path $extractedGo 'bin\go.exe'))) {
            throw 'Downloaded Go archive has an unexpected layout.'
        }
        if (Test-Path -LiteralPath $goDir) {
            Remove-Item -LiteralPath $goDir -Recurse -Force
        }
        Move-Item -LiteralPath $extractedGo -Destination $goDir
    } finally {
        Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-GoVersion $goExe)) {
        throw "Portable Go was extracted, but $goExe is not a usable Go 1.23+ toolchain."
    }
    return $goExe
}

$goExe = Find-SystemGo
if ([string]::IsNullOrWhiteSpace($goExe)) {
    $goExe = Install-PortableGo $root
}

$goVersion = (& $goExe version | Out-String).Trim()
Write-Host "Using: $goVersion"
Write-Host "Go executable: $goExe"

Write-Host 'Running tests...'
& $goExe test ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host 'Running go vet...'
& $goExe vet ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Race) {
    if ($null -eq (Get-Command gcc.exe -ErrorAction SilentlyContinue) -and $null -eq (Get-Command clang.exe -ErrorAction SilentlyContinue)) {
        throw 'The -Race option requires a C compiler on Windows (for example a recent mingw-w64 GCC). Run build.ps1 without -Race for a normal release build.'
    }
    Write-Host 'Running race detector...'
    & $goExe test -race ./...
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host 'Building Windows x64...'
New-Item -ItemType Directory -Force -Path dist | Out-Null

$oldGOOS = $env:GOOS
$oldGOARCH = $env:GOARCH
$oldCGO = $env:CGO_ENABLED
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    & $goExe build -trimpath -ldflags '-s -w' -o dist\SplitWire.exe .\cmd\splitwire
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally {
    $env:GOOS = $oldGOOS
    $env:GOARCH = $oldGOARCH
    $env:CGO_ENABLED = $oldCGO
}

Copy-Item -Force .\splitwire.default.conf .\dist\splitwire.default.conf
Copy-Item -Force .\README_RU.md .\dist\README_RU.md
Copy-Item -Force .\THIRD_PARTY_NOTICES.md .\dist\THIRD_PARTY_NOTICES.md
Copy-Item -Force .\LICENSE .\dist\LICENSE
Copy-Item -Force .\CHANGELOG_1.1.1.md .\dist\CHANGELOG_1.1.1.md
Copy-Item -Force .\TEST_RESULTS.txt .\dist\TEST_RESULTS.txt
Copy-Item -Force .\example.conf .\dist\example.conf
Copy-Item -Force .\example-custom-groups.conf .\dist\example-custom-groups.conf
Copy-Item -Force .\scripts\remove-windivert-driver.ps1 .\dist\remove-windivert-driver.ps1

Write-Host ''
Write-Host "Built portable directory: $root\dist" -ForegroundColor Green
Write-Host "Executable: $root\dist\SplitWire.exe" -ForegroundColor Green