<?php

if (!extension_loaded('bz2')) {
    fwrite(STDERR, "bz2 extension not loaded; run with -d extension=php_bz2\n");
    exit(2);
}
if (!Phar::canCompress(Phar::BZ2)) {
    fwrite(STDERR, "Phar cannot BZ2-compress in this build\n");
    exit(2);
}

$srcDir = __DIR__ . '/src';
$outDir = dirname(__DIR__) . '/phar';
$outPath = $outDir . '/bzip2.phar';

if (!is_dir($outDir)) {
    mkdir($outDir, 0o755, true);
}
if (file_exists($outPath)) {
    Phar::unlinkArchive($outPath);
}

$phar = new Phar($outPath);
$phar->buildFromDirectory($srcDir);
$phar->setStub($phar->createDefaultStub('index.php'));
$phar->compressFiles(Phar::BZ2);
$phar->stopBuffering();
unset($phar);

$rebuilt = new Phar($outPath);
$compressed = 0;
$total = 0;
foreach (new RecursiveIteratorIterator($rebuilt) as $file) {
    $total++;
    if ($file->isCompressed(Phar::BZ2)) {
        $compressed++;
    }
}
unset($rebuilt);

fwrite(STDOUT, sprintf("wrote %s (%d bytes), %d/%d members bzip2-compressed\n", $outPath, filesize($outPath), $compressed, $total));
