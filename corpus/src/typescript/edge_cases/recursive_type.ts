export type LinkedList<T> = { value: T; next: LinkedList<T> | null };
export type Tree<T> = { value: T; children: ReadonlyArray<Tree<T>> };
export type JsonValue =
    | string
    | number
    | boolean
    | null
    | ReadonlyArray<JsonValue>
    | { readonly [key: string]: JsonValue };

export function fromArray<T>(items: ReadonlyArray<T>): LinkedList<T> | null {
    if (items.length === 0) return null;
    return { value: items[0]!, next: fromArray(items.slice(1)) };
}

export function leafCount<T>(node: Tree<T>): number {
    if (node.children.length === 0) return 1;
    return node.children.reduce((acc, child) => acc + leafCount(child), 0);
}

const sample: JsonValue = { id: 1, list: [true, null, "ok", { nested: [1, 2] }] };
export const head = fromArray([1, 2, 3]);
export const sampleStr = JSON.stringify(sample);
