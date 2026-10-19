<?php
$module = getenv('GOST_PROVIDER_MODULE');
if (!$module) { throw new RuntimeException('Set GOST_PROVIDER_MODULE to the built provider.'); }
$cert = file_get_contents(__DIR__.'/../../gost-sign-cms/tests/fixtures/synthetic-certificate.der');
// PUBLIC test scalar d=1. Never use this fixture as a real signing key.
$key = hex2bin('303e020100301706082a85030701010101300b06092a8503070102010101042001').str_repeat("\0", 31);
$data = "PHP native provider test\x00\xff\r\n";
$cms = gost_sign_cades_sign_pkcs8($data, $cert, $key, $module);
if (!gost_sign_cades_verify($data, $cms) || gost_sign_cades_verify($data.'changed', $cms)) {
    throw new RuntimeException('Native signing / independent Rust verification failed');
}
$wrong = $key;
$wrong[32] = "\x02";
$rejected = false;
try { gost_sign_cades_sign_pkcs8($data, $cert, $wrong, $module); }
catch (Exception $e) { $rejected = true; }
if (!$rejected) { throw new RuntimeException('Wrong key accepted'); }
echo "PHP -> OpenSSL GOST signing -> Rust CMS verification: OK\n";
