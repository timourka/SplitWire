$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host 'Running tests...'
go test ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
go vet ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
go test -race ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host 'Building Windows x64...'
New-Item -ItemType Directory -Force -Path dist | Out-Null
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'
go build -trimpath -ldflags '-s -w' -o dist\SplitWire.exe .\cmd\splitwire
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Copy-Item -Force .\splitwire.default.conf .\dist\splitwire.default.conf
Copy-Item -Force .\README_RU.md .\dist\README_RU.md
Copy-Item -Force .\THIRD_PARTY_NOTICES.md .\dist\THIRD_PARTY_NOTICES.md
Copy-Item -Force .\LICENSE .\dist\LICENSE
Copy-Item -Force .\CHANGELOG_1.1.1.md .\dist\CHANGELOG_1.1.1.md
Copy-Item -Force .\TEST_RESULTS.txt .\dist\TEST_RESULTS.txt
Copy-Item -Force .\example.conf .\dist\example.conf
Copy-Item -Force .\example-custom-groups.conf .\dist\example-custom-groups.conf
Copy-Item -Force .\scripts\remove-windivert-driver.ps1 .\dist\remove-windivert-driver.ps1

Write-Host "Built portable directory: $root\dist"
