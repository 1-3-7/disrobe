type Palette = Record<"primary" | "secondary" | "tertiary", string | [number, number, number]>;

export const palette = {
    primary: "#0ea5e9",
    secondary: [255, 64, 128] as const,
    tertiary: "#facc15",
} satisfies Palette;

export const primaryUpper = palette.primary.toUpperCase();
export const secondaryFirst = palette.secondary[0];

type RouteShape = Record<string, { method: "GET" | "POST"; path: `/${string}` }>;

export const routes = {
    list: { method: "GET", path: "/items" },
    create: { method: "POST", path: "/items/new" },
} satisfies RouteShape;

export const listMethod = routes.list.method;
