function answer(kind: string): Promise<number> {
    return Promise.resolve(kind.charCodeAt(0));
}

async function route(kind: string): Promise<string> {
    let result = "";
    switch (kind) {
        case "a":
            result = "alpha " + (await answer(kind));
            break;
        case "b":
            result = "beta";
            break;
        default:
            result = "other " + (await answer(kind));
    }
    return result;
}

async function labelled(grid: number[][]): Promise<string> {
    const found: string[] = [];
    outer: for (let row = 0; row < grid.length; row++) {
        for (let col = 0; col < grid[row].length; col++) {
            const cell = await Promise.resolve(grid[row][col]);
            if (cell === 0) {
                continue outer;
            }
            if (cell < 0) {
                break outer;
            }
            found.push(row + "." + col + "=" + cell);
        }
    }
    return found.join(" ");
}

async function main(): Promise<void> {
    console.log(await route("a"));
    console.log(await route("b"));
    console.log(await route("z"));
    console.log(await labelled([[1, 2], [0, 3], [4, -1, 5], [6]]));
}

main();

export {};
