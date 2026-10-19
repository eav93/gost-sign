$ErrorActionPreference = 'Stop'
$opensslRoot = $env:OPENSSL_ROOT_DIR
if (!$opensslRoot) { $opensslRoot = $env:OPENSSL_DIR }
if (!$opensslRoot) { throw 'Set OPENSSL_ROOT_DIR to the same OpenSSL installation used by build-gost-provider.ps1.' }
$previous = $env:OPENSSL_DIR
try {
    $env:OPENSSL_DIR = $opensslRoot
    & cargo @args
    $result = $LASTEXITCODE
} finally { $env:OPENSSL_DIR = $previous }
exit $result
