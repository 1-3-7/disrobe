<?php

const LABEL = "tag";

$box = new stdClass();
$box->n = 3;
$box->n = $box->n + 4;
echo $box->n, "\n";
echo LABEL, "\n";

$err = new RuntimeException("boom", 7);
echo $err->getMessage(), "\n";
echo $err->getCode(), "\n";
echo $err instanceof RuntimeException ? "yes" : "no", "\n";

echo isset($box->n) ? "set" : "unset", "\n";
echo empty($box->missing) ? "empty" : "full", "\n";
echo isset($absent) ? "have" : "none", "\n";

$raw = "12";
$asInt = (int) $raw;
$asFloat = (float) $raw;
$asText = (string) ($asInt + 1);
echo $asInt + 1, "\n";
echo $asFloat + 0.5, "\n";
echo $asText, "\n";
echo ~$asInt, "\n";

$none = null;
echo $none ?? "fallback", "\n";
$pick = $asText ?: "empty";
echo $pick, "\n";
$branch = ($asInt > 5 ? "hi" : "lo") ?: "none";
echo $branch, "\n";

$copy = clone $box;
echo $copy->n, "\n";
echo DateTime::createFromFormat("Y-m-d", "2020-01-02")->format("d"), "\n";
