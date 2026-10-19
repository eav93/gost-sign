<?php
declare(strict_types=1);

// Пароль предоставляет окружение приложения; он не передаётся аргументом CLI.
// В сервисе вместо getenv можно использовать клиент менеджера секретов.
if ($argc !== 4) {
    fwrite(STDERR, "Использование: php sign.php КЛЮЧ.pfx ДОКУМЕНТ НОВАЯ_ПОДПИСЬ.p7s\n");
    exit(2);
}
try {
    if (!function_exists('gost_sign_cades_sign_pfx')) {
        throw new RuntimeException('Расширение gost_sign_php не загружено');
    }
    $password = getenv('GOST_PFX_PASSWORD');
    if ($password === false || $password === '') {
        throw new RuntimeException('Не задан GOST_PFX_PASSWORD');
    }
    $pfx = file_get_contents($argv[1]);
    $document = file_get_contents($argv[2]);
    if ($pfx === false || $document === false) {
        throw new RuntimeException('Не удалось прочитать PFX или документ');
    }
    $signature = gost_sign_cades_sign_pfx($document, $pfx, $password);
    if (!gost_sign_cades_verify($document, $signature)) {
        throw new RuntimeException('Проверка созданной подписи не прошла');
    }
    $output = fopen($argv[3], 'xb'); // Запрещает перезапись существующего файла.
    if ($output === false) {
        throw new RuntimeException('Не удалось создать файл подписи');
    }
    try {
        $offset = 0;
        while ($offset < strlen($signature)) {
            $written = fwrite($output, substr($signature, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException('Ошибка записи подписи');
            }
            $offset += $written;
        }
    } finally {
        fclose($output);
    }
    echo "Подпись сохранена: {$argv[3]}\n";
} catch (Throwable $error) {
    fwrite(STDERR, "Ошибка: {$error->getMessage()}\n");
    exit(1);
}
