<?php
$module = getenv('GOST_PROVIDER_MODULE');
$fixtures = getenv('GOST_TEST_IMPORT_DIR');
if (!$module || !$fixtures) { throw new RuntimeException('Set GOST_PROVIDER_MODULE and GOST_TEST_IMPORT_DIR.'); }
$cert = file_get_contents(__DIR__.'/../../gost-sign-cms/tests/fixtures/synthetic-certificate.der');
$encrypted = file_get_contents($fixtures.'/encrypted-pkcs8.der');
$pfx = file_get_contents($fixtures.'/test-identity.pfx');
$content = "protected import test\0\xff\r\n";
$password = "public-test-password\0binary";
function rejected(callable $operation): void {
    try { $operation(); } catch (Exception $e) { return; }
    throw new RuntimeException('Invalid key/password/container was accepted');
}
$cms = gost_sign_cades_sign_encrypted_pkcs8($content, $cert, $encrypted, $password, $module);
if (!gost_sign_cades_verify($content, $cms)) { throw new RuntimeException('Encrypted PKCS8 signing failed'); }
$cms = gost_sign_cades_sign_pkcs12($content, $pfx, 'public-test-pfx', $module, false);
if (!gost_sign_cades_verify($content, $cms)) { throw new RuntimeException('PFX signing failed'); }
$legacyCms = gost_sign_cades_sign_pkcs12($content, $pfx, 'public-test-pfx', $module, true);
if (!gost_sign_cades_verify($content, $legacyCms)) { throw new RuntimeException('Explicit legacy provider path failed'); }
rejected(fn() => gost_sign_cades_sign_encrypted_pkcs8($content, $cert, $encrypted, 'wrong', $module));
rejected(fn() => gost_sign_cades_sign_encrypted_pkcs8($content, $cert, $encrypted, 'public-test-password', $module));
rejected(fn() => gost_sign_cades_sign_encrypted_pkcs8($content, $cert, $encrypted."\0", $password, $module));
rejected(fn() => gost_sign_cades_sign_pkcs12($content, $pfx, 'wrong', $module, false));
rejected(fn() => gost_sign_cades_sign_pkcs12($content, $pfx, "public-test-pfx\0", $module, false));
rejected(fn() => gost_sign_cades_sign_pkcs12($content, $pfx."\0", 'public-test-pfx', $module, false));
echo "PHP protected PKCS8/PFX imports, exact passwords and invalid inputs: OK\n";
