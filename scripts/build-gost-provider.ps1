$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$sourceDir = Join-Path $root 'tools/gost-engine'
$revision = '509dcb467507149297673e68293be5b01d1aa4a8'
if (!$env:OPENSSL_ROOT_DIR) { throw 'Set OPENSSL_ROOT_DIR to an OpenSSL >=3.4 development installation with matching architecture.' }
function Invoke-Checked([string] $command, [string[]] $arguments) {
    & $command @arguments
    if ($LASTEXITCODE -ne 0) { throw "$command failed with exit code $LASTEXITCODE" }
}
if (!(Test-Path $sourceDir)) {
    Invoke-Checked git @('clone', 'https://github.com/gost-engine/engine.git', $sourceDir)
    Invoke-Checked git @('-C', $sourceDir, 'checkout', '--detach', $revision)
}
$currentRevision = & git -C $sourceDir rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $currentRevision -ne $revision) { throw 'Existing provider checkout differs from the pinned revision; left untouched.' }
Invoke-Checked git @('-C', $sourceDir, 'submodule', 'update', '--init', '--recursive')
Invoke-Checked cmake @('-S', $sourceDir, '-B', "$sourceDir/build", "-DOPENSSL_ROOT_DIR=$env:OPENSSL_ROOT_DIR", "-DOPENSSL_ENGINES_DIR=$sourceDir/build/bin", '-DGOST_BUILD_ENGINE=OFF', '-DGOST_BUILD_PROVIDER=ON', '-DCMAKE_BUILD_TYPE=Release')
Invoke-Checked cmake @('--build', "$sourceDir/build", '--target', 'gost_prov', '--config', 'Release', '--parallel', '4')
Write-Output "Provider built under $sourceDir/build/bin. No system configuration changed."
