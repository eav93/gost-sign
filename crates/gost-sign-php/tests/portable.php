<?php
// Только одноразовая тестовая фикстура, созданная тестовой утилитой.
$pfx = file_get_contents($argv[1]);
$data = "PHP Rust PFX\x00\xff\r\n";
$cms = gost_sign_cades_sign_pfx($data, $pfx, 'test-new-password');
if (!gost_sign_cades_verify($data, $cms) || gost_sign_cades_verify($data.'changed', $cms)) {
    throw new RuntimeException('Ошибка проверки подписи Rust');
}
$rejected = false;
try { gost_sign_cades_sign_pfx($data, $pfx, 'incorrect'); }
catch (Exception $e) { $rejected = true; }
if (!$rejected) { throw new RuntimeException('Принят неверный пароль'); }
echo "PHP → Rust PFX → подпись → проверка: успешно\n";
