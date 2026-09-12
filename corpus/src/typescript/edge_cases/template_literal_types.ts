export type RouteMethod = "GET" | "POST" | "DELETE";
export type RoutePath = `/${string}`;
export type Route = `${RouteMethod} ${RoutePath}`;
export type Versioned<T extends string> = `v${1 | 2 | 3}/${T}`;

export type EventName<T extends string> = `on${Capitalize<T>}`;
export type Snake<T extends string> = T extends `${infer Head}${infer Tail}`
    ? Tail extends Uncapitalize<Tail>
        ? `${Lowercase<Head>}${Snake<Tail>}`
        : `${Lowercase<Head>}_${Snake<Tail>}`
    : T;

declare const route: Route;
declare const versionedRoute: Versioned<"users">;
declare const click: EventName<"click">;
declare const snakeCased: Snake<"helloWorldFromTS">;

export const proof = { route, versionedRoute, click, snakeCased };
