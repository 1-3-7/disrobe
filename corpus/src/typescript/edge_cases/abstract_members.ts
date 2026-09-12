export abstract class Shape {
    abstract readonly kind: string;
    abstract area(): number;
    describe(): string {
        return `${this.kind} area=${this.area()}`;
    }
}

export class Circle extends Shape {
    readonly kind = "circle";
    constructor(public radius: number) {
        super();
    }
    area(): number {
        return Math.PI * this.radius * this.radius;
    }
}

export class Square extends Shape {
    readonly kind = "square";
    constructor(public side: number) {
        super();
    }
    area(): number {
        return this.side * this.side;
    }
}

export type ShapeCtor = abstract new (...args: any[]) => Shape;
export function describeAll(shapes: ReadonlyArray<Shape>): string[] {
    return shapes.map((s) => s.describe());
}

export const shapes = describeAll([new Circle(2), new Square(3)]);
