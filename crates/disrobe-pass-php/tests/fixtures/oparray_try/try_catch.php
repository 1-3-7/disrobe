<?php

function classify($value)
{
    try {
        if ($value < 0) {
            throw new InvalidArgumentException("negative");
        }
        return "ok";
    } catch (InvalidArgumentException $error) {
        return "bad";
    }
}

function widen($value)
{
    try {
        if ($value === 1) {
            throw new RuntimeException("one");
        }
        if ($value === 2) {
            throw new LogicException("two");
        }
        return "none";
    } catch (RuntimeException | LogicException $error) {
        return "either";
    } catch (Throwable $other) {
        return "rest";
    }
}

function silent($value)
{
    try {
        throw new RuntimeException("quiet");
    } catch (RuntimeException) {
        return "swallowed";
    }
}

function inner($value)
{
    try {
        try {
            throw new RuntimeException("deep");
        } catch (RuntimeException $error) {
            return "inner";
        }
    } catch (Throwable $other) {
        return "outer";
    }
}

function siblings($value)
{
    $marks = "";
    try {
        $marks = $marks . "a";
    } catch (Throwable $error) {
        $marks = $marks . "b";
    }
    try {
        $marks = $marks . "c";
    } catch (Throwable $error) {
        $marks = $marks . "d";
    }
    return $marks;
}

echo classify(-1), classify(1), "\n";
echo widen(1), widen(2), widen(3), "\n";
echo silent(0), "\n";
echo inner(0), "\n";
echo siblings(0), "\n";
