
export interface RuntimeProbe {
    structuredCloneSupported: boolean;
    aggregateErrorSupported: boolean;
}

export function probe(): RuntimeProbe {
    return {
        structuredCloneSupported: typeof structuredClone === "function",
        aggregateErrorSupported: typeof AggregateError === "function",
    };
}

export const probed = probe();
