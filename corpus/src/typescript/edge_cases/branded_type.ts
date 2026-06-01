declare const brand: unique symbol;
export type Brand<T, B extends string> = T & { readonly [brand]: B };

export type UserId = Brand<string, "UserId">;
export type OrderId = Brand<string, "OrderId">;
export type CurrencyAmount = Brand<number, "CurrencyAmount">;

export function userId(raw: string): UserId {
    if (!/^u_[a-z0-9]{8}$/.test(raw)) throw new Error(`invalid user id: ${raw}`);
    return raw as UserId;
}

export function currency(amount: number): CurrencyAmount {
    if (!Number.isFinite(amount)) throw new Error("not finite");
    return Math.round(amount * 100) as CurrencyAmount;
}

export const sample = { id: userId("u_abc12345"), price: currency(19.99) };
