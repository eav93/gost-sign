<?php
// Только одноразовая тестовая фикстура, созданная тестовой утилитой.
$pfx = file_get_contents($argv[1]);
$data = "PHP Rust PFX\x00\xff\r\n";
$certificate = gost_sign_pfx_certificate($pfx, 'test-new-password');
if ($certificate !== file_get_contents(__DIR__.'/../../gost-sign-cms/tests/fixtures/synthetic-certificate.der')) {
    throw new RuntimeException('Не совпадает сертификат PFX');
}
$certificateRejected = false;
try { gost_sign_pfx_certificate($pfx, 'incorrect'); }
catch (Exception $e) { $certificateRejected = true; }
if (!$certificateRejected) { throw new RuntimeException('Сертификат PFX прочитан с неверным паролем'); }
$cms = gost_sign_cades_sign_pfx($data, $pfx, 'test-new-password');
if (!gost_sign_cades_verify($data, $cms) || gost_sign_cades_verify($data.'changed', $cms)) {
    throw new RuntimeException('Ошибка проверки подписи Rust');
}
$rejected = false;
try { gost_sign_cades_sign_pfx($data, $pfx, 'incorrect'); }
catch (Exception $e) { $rejected = true; }
if (!$rejected) { throw new RuntimeException('Принят неверный пароль'); }
echo "PHP → Rust PFX → подпись → проверка: успешно\n";
