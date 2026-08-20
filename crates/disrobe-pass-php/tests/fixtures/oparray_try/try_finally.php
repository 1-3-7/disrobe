<?php

function guarded($value)
{
    $trace = "";
    try {
        $trace = $trace . "t";
    } finally {
        $trace = $trace . "f";
    }
    return $trace;
}

function settled($value)
{
    try {
        if ($value < 0) {
            throw new RuntimeException("low");
        }
        return "ok";
    } catch (RuntimeException $error) {
        return "caught";
    } finally {
        echo "closed\n";
    }
}

function layered($value)
{
    try {
        try {
            return "deep";
        } finally {
            echo "inner\n";
        }
    } finally {
        echo "outer\n";
    }
}

function counted($rows)
{
    $total = 0;
    foreach ($rows as $row) {
        try {
            if ($row < 0) {
                continue;
            }
            if ($row > 9) {
                break;
            }
            $total = $total + $row;
        } finally {
            $total = $total + 100;
        }
    }
    return $total;
}

function stepped($limit)
{
    $log = "";
    for ($i = 0; $i < $limit; $i = $i + 1) {
        try {
            if ($i === 2) {
                continue;
            }
            $log = $log . $i;
        } finally {
            $log = $log . ".";
        }
    }
    return $log;
}

function overrides($value)
{
    try {
        throw new RuntimeException("discarded");
    } finally {
        return "from-finally";
    }
}

echo guarded(0), "\n";
echo settled(-1), settled(1), "\n";
echo layered(0), "\n";
echo counted(range(-2, 12)), "\n";
echo stepped(5), "\n";
echo overrides(0), "\n";
