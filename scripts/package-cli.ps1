param([Parameter(Mandatory=$true)][ValidateSet('x86_64-pc-windows-msvc','aarch64-pc-windows-msvc')][string]$Target)
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$binary = 'target/release/gost-sign.exe'
$versionLine = & $binary --version
if ($LASTEXITCODE -ne 0) { throw 'Не удалось запустить бинарник' }
$version = $versionLine -replace '^gost-sign ', ''
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Неверная версия бинарника' }
$package = "gost-sign-$version-$Target"
New-Item -ItemType Directory -Force dist | Out-Null
if ((Test-Path "dist/$package") -or (Test-Path "dist/$package.zip")) { throw 'Архив уже существует; выберите пустую папку dist' }
New-Item -ItemType Directory "dist/$package" | Out-Null
Copy-Item $binary "dist/$package/"
Copy-Item README.md "dist/$package/"
Copy-Item docs,licenses,examples "dist/$package/" -Recurse
$revision = $env:BUILD_REVISION
if (-not $revision) { $revision = git rev-parse HEAD; if ($LASTEXITCODE -ne 0) { throw 'Нет Git revision' } }
$dirty = [bool](git status --porcelain)
if ($LASTEXITCODE -ne 0) { throw 'Не удалось определить состояние Git' }
@("version=$version", "target=$Target", "revision=$revision", "source_dirty=$dirty", (rustc --version)) | Set-Content "dist/$package/BUILD-INFO.txt" -Encoding utf8
Compress-Archive -Path "dist/$package" -DestinationPath "dist/$package.zip"
$hash = (Get-FileHash "dist/$package.zip" -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $package.zip" | Set-Content "dist/$package.zip.sha256" -Encoding ascii
Write-Host "Готово: dist/$package.zip"
