<?php

function read_named_value(string $name, string $value): string
{
    return $$name ?? 'missing';
}

echo read_named_value('value', 'present'), "\n";
echo read_named_value('absent', 'unused'), "\n";
