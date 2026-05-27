export type Ctor<T> = new (...args: any[]) => T;
export type AbstractCtor<T> = abstract new (...args: any[]) => T;

export function withTimestamp<TBase extends Ctor<object>>(Base: TBase) {
    return class extends Base {
        readonly createdAt: number = Date.now();
    };
}

export function withTag<Tag extends string>(tag: Tag) {
    return function <TBase extends Ctor<object>>(Base: TBase) {
        return class extends Base {
            readonly tag = tag;
        };
    };
}

class Plain {
    constructor(public name: string) {}
}

const TaggedTimestamped = withTimestamp(withTag("user")(Plain));
export const instance = new TaggedTimestamped("ada");
export const tag: "user" = instance.tag;
