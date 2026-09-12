<?php

function remove_first(string $removed, string $kept): string
{
    unset($removed);
    return (isset($removed) ? $removed : 'missing') . '|' . $kept;
}

echo remove_first('remove', 'keep'), "\n";
