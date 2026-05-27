type ClassDecorator2 = <T extends new (...args: any[]) => any>(value: T, context: ClassDecoratorContext<T>) => T;

function logged<T extends new (...args: any[]) => any>(value: T, context: ClassDecoratorContext<T>): T {
    context.addInitializer(function () {
        (this as any).constructionAt = Date.now();
    });
    return value;
}

function bound<T extends Function>(value: T, context: ClassMethodDecoratorContext): void {
    context.addInitializer(function () {
        (this as any)[context.name] = (value as Function).bind(this);
    });
}

function trace<T>(value: ClassAccessorDecoratorTarget<unknown, T>, context: ClassAccessorDecoratorContext<unknown, T>): ClassAccessorDecoratorResult<unknown, T> {
    return {
        get() {
            return value.get.call(this);
        },
        set(v: T) {
            value.set.call(this, v);
        },
    };
}

@logged
export class Pinger {
    @trace accessor counter: number = 0;

    @bound
    ping(): number {
        this.counter += 1;
        return this.counter;
    }
}

export const probe = { Pinger };
