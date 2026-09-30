<?php

class AppError extends RuntimeException
{
}

function risky(int $n): int
{
    if ($n < 0) {
        throw new InvalidArgumentException("negative: $n");
    }
    if ($n === 0) {
        throw new AppError('zero', 42);
    }

    return intdiv(100, $n);
}

function guarded(int $n): string
{
    try {
        $v = risky($n);
        $out = "ok $v";
    } catch (InvalidArgumentException $e) {
        $out = 'bad arg: ' . $e->getMessage();
    } catch (AppError | DivisionByZeroError $e) {
        $out = 'app ' . $e->getCode();
    } finally {
        echo "[finally $n] ";
    }

    return $out;
}

function finally_wins(): string
{
    try {
        return 'from try';
    } finally {
        echo "cleanup ";
    }
}

function finally_overrides(): string
{
    try {
        throw new LogicException('lost');
    } finally {
        return 'finally return';
    }
}

function rethrow(int $n): void
{
    try {
        risky($n);
        echo "no throw\n";
    } catch (Exception $e) {
        echo 'caught ', get_class($e), ", rethrowing\n";
        throw $e;
    }
}

function wrap(): void
{
    try {
        risky(-1);
    } catch (InvalidArgumentException $e) {
        throw new AppError('wrapped', 7, $e);
    }
}

function nested(): string
{
    $log = [];
    try {
        try {
            $log[] = 'inner try';
            throw new RuntimeException('inner');
        } catch (RuntimeException $e) {
            $log[] = 'inner catch ' . $e->getMessage();
            throw new LogicException('outer');
        } finally {
            $log[] = 'inner finally';
        }
    } catch (LogicException $e) {
        $log[] = 'outer catch ' . $e->getMessage();
    }

    return implode(' | ', $log);
}

function loop_finally(): int
{
    $count = 0;
    for ($i = 0; $i < 5; $i++) {
        try {
            if ($i === 1) {
                continue;
            }
            if ($i === 3) {
                break;
            }
            $count += 10;
        } finally {
            $count++;
        }
    }

    return $count;
}

function escapes(int $depth): int
{
    if ($depth === 0) {
        throw new UnexpectedValueException('bottom');
    }

    return escapes($depth - 1) + 1;
}

foreach ([4, -2, 0] as $n) {
    echo guarded($n), "\n";
}
echo finally_wins(), "\n";
echo finally_overrides(), "\n";
try {
    rethrow(0);
} catch (AppError $e) {
    echo 'top: ', $e->getMessage(), ' ', $e->getCode(), "\n";
}
rethrow(5);
try {
    wrap();
} catch (AppError $e) {
    echo $e->getMessage(), ' <- ', get_class($e->getPrevious()), ': ', $e->getPrevious()->getMessage(), "\n";
}
echo nested(), "\n";
echo loop_finally(), "\n";
try {
    echo escapes(3), "\n";
} catch (UnexpectedValueException $e) {
    echo 'escaped: ', $e->getMessage(), "\n";
}
try {
    intdiv(1, 0);
} catch (DivisionByZeroError $e) {
    echo 'div: ', $e->getMessage(), "\n";
}
try {
    throw new ErrorException('plain', 3);
} catch (Throwable) {
    echo "caught without variable\n";
}
