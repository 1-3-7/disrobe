<?php

enum Suit: string
{
    case Hearts = 'H';
    case Spades = 'S';

    public function color(): string
    {
        return match ($this) {
            self::Hearts => 'red',
            self::Spades => 'black',
        };
    }

    public static function fromChar(string $char): self
    {
        return self::from($char);
    }
}

function describe(Suit $suit): string
{
    return $suit->name . '=' . $suit->value . ' ' . $suit->color();
}

echo describe(Suit::Hearts), "\n";
echo describe(Suit::fromChar('S')), "\n";
echo count(Suit::cases()), "\n";
echo Suit::tryFrom('X') === null ? 'no X' : 'X', "\n";
