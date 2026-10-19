<?php
$vectors = json_decode(file_get_contents(__DIR__.'/../../gost-sign-core/tests/public-vectors.json'), true, flags: JSON_THROW_ON_ERROR);
foreach ($vectors as $vector) {
    $message = hex2bin($vector['input_hex']);
    foreach ([256, 512] as $bits) {
        $function = 'gost_sign_hash'.$bits;
        if (!hash_equals($vector['hash'.$bits], $function($message))) {
            throw new RuntimeException('RFC6986 mismatch: '.$vector['name'].' / '.$bits);
        }
    }
}
echo "Rust PHP extension / RFC6986 vectors: OK\n";

function check(bool $value, string $message): void {
    if (!$value) { throw new RuntimeException($message); }
}
function expectFailure(callable $operation): void {
    try { $operation(); } catch (Exception $e) { return; }
    throw new RuntimeException('Expected malformed-input exception');
}
$cert = file_get_contents(__DIR__.'/../../gost-sign-experimental/tests/fixtures/rfc9215-tc26-256-a.der');
check(gost_sign_verify_certificate_tc26_256_a($cert, $cert), 'RFC9215 signature mismatch');
$altered = $cert;
$altered[strlen($altered)-1] = chr(ord($altered[strlen($altered)-1]) ^ 1);
check(!gost_sign_verify_certificate_tc26_256_a($altered, $cert), 'Altered signature accepted');
expectFailure(fn() => gost_sign_verify_certificate_tc26_256_a("\0bad", $cert));
$content = "\xff\0exact\r\n";
$attrs = gost_sign_cades_signed_attributes($content, $cert);
check(ord($attrs[0]) === 0x31, 'Signed attributes must be DER SET');
check($attrs !== gost_sign_cades_signed_attributes($content."\0", $cert), 'Binary content not bound');
$signature = str_repeat("\0", 64);
$cms = gost_sign_cades_assemble($content, $cert, $signature);
check(str_contains($cms, $signature), 'Signature bytes lost');
check(!gost_sign_cades_verify($content, $cms), 'Dummy signature accepted');
expectFailure(fn() => gost_sign_cades_assemble($content, $cert, str_repeat("\0", 63)));
expectFailure(fn() => gost_sign_cades_verify($content, $cms."\0"));
echo "Rust PHP extension / RFC9215 and CMS binary/error handling: OK\n";
