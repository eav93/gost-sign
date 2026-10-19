$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if ($env:PACKAGE_PLATFORM -ne 'windows-x86_64') { throw 'Неподдерживаемая платформа' }
$actualVersion = php -n -r 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION;'
if ($LASTEXITCODE -ne 0 -or $actualVersion -ne $env:PHP_VERSION) { throw 'Версия PHP не совпадает' }
$actualThread = php -n -r 'echo PHP_ZTS ? "ts" : "nts";'
if ($LASTEXITCODE -ne 0 -or $actualThread -ne $env:phpts) { throw 'Режим NTS/ZTS не совпадает' }
$extension = Join-Path (Get-Location) 'target/release/gost_sign_php.dll'
php -n -d "extension=$extension" crates/gost-sign-php/tests/smoke.php
if ($LASTEXITCODE -ne 0) { throw 'Smoke-тест не прошёл' }
php -n -d "extension=$extension" crates/gost-sign-php/tests/portable.php target/php-public-test.pfx
if ($LASTEXITCODE -ne 0) { throw 'Тест подписи PFX не прошёл' }
$package = "gost-sign-php$($env:PHP_VERSION)-$($env:PACKAGE_PLATFORM)-$($env:phpts)"
New-Item -ItemType Directory -Force dist | Out-Null
if ((Test-Path "dist/$package") -or (Test-Path "dist/$package.zip")) { throw 'Архив уже существует' }
New-Item -ItemType Directory "dist/$package" | Out-Null
Copy-Item $extension "dist/$package/gost_sign_php.dll"
'extension=gost_sign_php.dll' | Set-Content "dist/$package/gost_sign.ini" -Encoding ascii
Copy-Item README.md "dist/$package/"
Copy-Item docs,licenses,examples "dist/$package/" -Recurse
@((git rev-parse HEAD), (rustc --version), (php -n -i | Select-String '^(PHP API|PHP Extension|Zend Extension|Thread Safety|Debug Build) ')) | Set-Content "dist/$package/BUILD-INFO.txt" -Encoding utf8
Compress-Archive -Path "dist/$package" -DestinationPath "dist/$package.zip"
$hash = (Get-FileHash "dist/$package.zip" -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $package.zip" | Set-Content "dist/$package.zip.sha256" -Encoding ascii
Write-Host "Готово: dist/$package.zip"
