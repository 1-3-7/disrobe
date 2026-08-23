<?php

class Ledger
{
    public const LABEL = 'ledger';
    public const SCALE = 10;

    public static int $total = 0;
    public static string $tag = 'none';

    public int $value = 0;
    public string $note = '';
    public array $bag = [];

    public static function add(int $by): int
    {
        Ledger::$total += $by;
        Ledger::$total++;
        ++Ledger::$total;
        Ledger::$total--;

        return self::$total;
    }

    public static function retag(string $suffix): string
    {
        Ledger::$tag = $suffix;
        Ledger::$tag .= '!';

        return static::$tag;
    }

    public function bump(int $by): int
    {
        $this->value += $by;
        $this->value *= 2;
        $this->value++;
        ++$this->value;
        $this->value--;
        --$this->value;

        return $this->value;
    }

    public function annotate(string $text): string
    {
        $this->note .= $text;
        $this->note .= self::LABEL;

        return $this->note;
    }

    public function stash(string $key, int $amount): int
    {
        $this->bag[$key] = $amount;
        $this->bag[$key] += self::SCALE;

        return $this->bag[$key];
    }
}

function accumulate(array &$rows, int $by): void
{
    foreach ($rows as &$row) {
        $row += $by;
    }
}

function join_flat(array $rows): string
{
    $out = '';
    foreach ($rows as $row) {
        $out = $out . $row . ',';
    }

    return $out;
}

function build_list(int $seed): array
{
    return [$seed, $seed + 1, $seed + 2];
}

echo Ledger::LABEL, "\n";
echo Ledger::SCALE, "\n";

echo Ledger::add(5), "\n";
echo Ledger::$total, "\n";
echo Ledger::retag('x'), "\n";

$ledger = new Ledger();
echo $ledger->bump(3), "\n";
echo $ledger->value, "\n";
echo $ledger->annotate('note:'), "\n";
echo $ledger->stash('k', 7), "\n";

$rows = build_list(1);
accumulate($rows, 100);
echo join_flat($rows), "\n";
