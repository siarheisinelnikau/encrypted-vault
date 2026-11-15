param([switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Set-Location -LiteralPath $repository
$manifestText = Get-Content -LiteralPath (Join-Path $repository 'Cargo.toml') -Raw
$version = [regex]::Match($manifestText, '(?m)^version = "([0-9]+\.[0-9]+\.[0-9]+)"').Groups[1].Value
if (-not $version) { throw 'Package version was not found.' }
if (-not $SkipBuild) {
    & cargo build --locked --release --jobs 2 --target-dir (Join-Path $repository 'target')
    if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
}
$distribution = Join-Path $repository 'dist'
New-Item -ItemType Directory -Force -Path $distribution | Out-Null
$assetName = "EncryptedVault-v$version.exe"
$asset = Join-Path $distribution $assetName
Copy-Item -LiteralPath (Join-Path $repository 'target\release\EncryptedVault.exe') -Destination $asset
$digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $asset).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $distribution "$assetName.sha256"), "$digest  $assetName`n", [Text.UTF8Encoding]::new($false))
foreach ($name in @('LICENSE', 'THIRD-PARTY-NOTICES.txt')) { Copy-Item -LiteralPath (Join-Path $repository $name) -Destination (Join-Path $distribution $name) }
$metadataText = & cargo metadata --offline --locked --format-version 1 --filter-platform x86_64-pc-windows-msvc
if ($LASTEXITCODE -ne 0) { throw 'Dependency license metadata could not be resolved offline.' }
$metadata = $metadataText | ConvertFrom-Json
$licenseRoot = Join-Path $distribution 'licenses'
New-Item -ItemType Directory -Force -Path $licenseRoot | Out-Null
$report = @()
foreach ($package in $metadata.packages) {
    if ($package.name -eq 'encrypted-vault') { continue }
    $directory = Split-Path -Parent $package.manifest_path
    $destination = Join-Path $licenseRoot "$($package.name)-$($package.version)"
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    $notices = Get-ChildItem -LiteralPath $directory -File | Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE|copyright)' }
    foreach ($notice in $notices) { Copy-Item -LiteralPath $notice.FullName -Destination (Join-Path $destination $notice.Name) }
    $report += [pscustomobject]@{ name=$package.name; version=$package.version; license=$package.license; repository=$package.repository; noticeFiles=@($notices.Name) }
}
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $licenseRoot 'dependencies.json') -Encoding utf8NoBOM
Write-Output "Prepared $assetName and SHA-256. Nothing was uploaded or published."
