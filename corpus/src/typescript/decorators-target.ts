type LogLevel = "trace" | "debug" | "info" | "warn" | "error";

interface Logger {
    log(level: LogLevel, message: string, fields?: Record<string, unknown>): void;
}

class ConsoleLogger implements Logger {
    private readonly prefix: string;

    constructor(prefix: string) {
        this.prefix = prefix;
    }

    log(level: LogLevel, message: string, fields?: Record<string, unknown>): void {
        const payload = fields ? ` ${JSON.stringify(fields)}` : "";
        console.log(`[${this.prefix}] ${level.toUpperCase()} ${message}${payload}`);
    }
}

function traced<This, Args extends unknown[], Return>(
    value: (this: This, ...args: Args) => Return,
    context: ClassMethodDecoratorContext<This, (this: This, ...args: Args) => Return>,
): (this: This, ...args: Args) => Return {
    const name = String(context.name);
    return function (this: This, ...args: Args): Return {
        const logger = new ConsoleLogger("trace");
        logger.log("debug", `enter ${name}`, { args });
        const result = value.apply(this, args);
        logger.log("debug", `exit ${name}`, { result });
        return result;
    };
}

class Calculator<T extends number> {
    private readonly history: Array<readonly [string, T, T, T]> = [];

    @traced
    add(a: T, b: T): T {
        const r = (a + b) as T;
        this.history.push(["add", a, b, r] as const);
        return r;
    }

    @traced
    mul(a: T, b: T): T {
        const r = (a * b) as T;
        this.history.push(["mul", a, b, r] as const);
        return r;
    }

    snapshot(): ReadonlyArray<readonly [string, T, T, T]> {
        return this.history;
    }
}

const calc = new Calculator<number>();
calc.add(2, 3);
calc.mul(4, 5);
console.log(JSON.stringify(calc.snapshot()));
