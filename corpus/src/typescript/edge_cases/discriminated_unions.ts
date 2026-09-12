export type Event =
    | { kind: "login"; user: string; at: number }
    | { kind: "logout"; user: string; reason?: string }
    | { kind: "error"; code: number; message: string }
    | { kind: "metric"; name: string; value: number };

export function describe(event: Event): string {
    switch (event.kind) {
        case "login":
            return `login ${event.user} @ ${event.at}`;
        case "logout":
            return `logout ${event.user}${event.reason ? `(${event.reason})` : ""}`;
        case "error":
            return `error ${event.code}: ${event.message}`;
        case "metric":
            return `metric ${event.name}=${event.value}`;
        default: {
            const exhaust: never = event;
            return exhaust;
        }
    }
}

export function isError(e: Event): e is Extract<Event, { kind: "error" }> {
    return e.kind === "error";
}

export const samples = [
    describe({ kind: "login", user: "ada", at: 1 }),
    describe({ kind: "metric", name: "rps", value: 12.5 }),
];
