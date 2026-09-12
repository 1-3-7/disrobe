export type UserShape = { id: number; name: string };
export interface OrderShape {
    readonly id: string;
    readonly user: UserShape;
}

export function build(id: number, name: string): UserShape {
    return { id, name };
}

export function order(id: string, user: UserShape): OrderShape {
    return { id, user };
}

export const sample = order("o1", build(1, "ada"));
export type SampleType = typeof sample;
