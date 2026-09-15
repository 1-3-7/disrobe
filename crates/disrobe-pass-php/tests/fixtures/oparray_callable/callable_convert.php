<?php

function callable_convert_namespace_contrast(): void
{
    $direct = CallableFixture\lower(...);
    $static = CallableFixture\Factory::date(...);
}

function callable_convert_output(): void
{
    $direct = strtoupper(...);
    $name = 'strrev';
    $dynamic = $name(...);
    $static = DateTimeImmutable::createFromFormat(...);
    $date = new DateTimeImmutable('2024-02-03');
    $method = $date->format(...);
    $instance_method = 'format';
    $dynamic_method = $date->$instance_method(...);
    $class = 'DateTimeImmutable';
    $static_method = 'createFromFormat';
    $dynamic_static = $class::$static_method(...);

    echo $direct('mixed') . ':' . $dynamic('stressed') . ':';
    echo $static('Y-m-d', '2025-04-05')->format('Y') . ':' . $method('m') . ':';
    echo $dynamic_method('d') . ':' . $dynamic_static('Y-m-d', '2025-04-05')->format('m');
}

function nullsafe_callable_convert_candidate(?DateTimeImmutable $date): ?int
{
    return $date?->getTimestamp();
}

callable_convert_output();
