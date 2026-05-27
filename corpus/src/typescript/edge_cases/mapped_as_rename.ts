export type Prefixed<T, P extends string> = {
    [K in keyof T as `${P}${Capitalize<string & K>}`]: T[K];
};

export type StripPrivate<T> = {
    [K in keyof T as K extends `_${string}` ? never : K]: T[K];
};

export type EventHandlers<T extends string> = {
    [K in T as `on${Capitalize<K>}`]: (payload: unknown) => void;
};

declare const widget: Prefixed<{ id: number; name: string }, "widget">;
declare const cleaned: StripPrivate<{ id: number; _secret: string; name: string }>;
declare const handlers: EventHandlers<"click" | "hover" | "submit">;

export const proof = { widget, cleaned, handlers };
