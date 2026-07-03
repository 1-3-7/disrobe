<?php

namespace PharBz2;

final class Greeter
{
    public function __construct(private readonly string $subject)
    {
    }

    public function salute(): string
    {
        return 'hello, ' . $this->subject;
    }
}
