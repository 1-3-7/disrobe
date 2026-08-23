<?php

function stamp(?DateTimeImmutable $when): string
{
    return (string) ($when?->format('Y-m-d') ?? 'none');
}

function reason(?Throwable $error): string
{
    return (string) ($error?->getMessage() ?? 'none');
}

function inner_reason(?Throwable $error): string
{
    return (string) ($error?->getPrevious()?->getMessage() ?? 'none');
}

function inner_code(?Throwable $error): string
{
    return (string) ($error?->getPrevious()?->getCode() ?? 'none');
}

$when = new DateTimeImmutable('2020-01-02 03:04:05');
$inner = new RuntimeException('inner', 7);
$outer = new RuntimeException('outer', 0, $inner);
$bare = new RuntimeException('bare', 3);

echo stamp($when), "\n";
echo stamp(null), "\n";
echo reason($outer), "\n";
echo reason(null), "\n";
echo inner_reason($outer), "\n";
echo inner_reason($bare), "\n";
echo inner_reason(null), "\n";
echo inner_code($outer), "\n";
echo inner_code($bare), "\n";
