<?php

$pharPath = $argv[1] ?? (dirname(__DIR__) . '/phar/bzip2.phar');
$outDir = $argv[2] ?? (sys_get_temp_dir() . '/phar_bz2_members');

if (!is_dir($outDir)) {
    mkdir($outDir, 0o755, true);
}

$phar = new Phar($pharPath);
$manifest = [];
foreach (new RecursiveIteratorIterator($phar) as $file) {
    $rel = $file->getPathname();
    $rel = substr($rel, strpos($rel, '.phar') + strlen('.phar') + 1);
    $bytes = file_get_contents($file->getPathname());
    $flat = str_replace(['/', '\\'], '__', $rel);
    file_put_contents($outDir . '/' . $flat, $bytes);
    $manifest[$rel] = [
        'len' => strlen($bytes),
        'sha256' => hash('sha256', $bytes),
        'bz2' => $file->isCompressed(Phar::BZ2),
    ];
}

fwrite(STDOUT, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
