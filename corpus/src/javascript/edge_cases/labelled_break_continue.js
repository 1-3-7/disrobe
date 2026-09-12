function findPair(matrix, target) {
    outer: for (let i = 0; i < matrix.length; i++) {
        inner: for (let j = 0; j < matrix[i].length; j++) {
            if (matrix[i][j] === target) return { i, j };
            if (matrix[i][j] < 0) continue outer;
            if (matrix[i][j] > 100) break outer;
        }
    }
    return null;
}

const grid = [
    [1, 2, 3, -1, 50],
    [10, 20, 30, 40, 200],
    [5, 6, 7, 8, 9],
];

console.log({
    found3: findPair(grid, 3),
    found200: findPair(grid, 200),
    foundMissing: findPair(grid, 999),
});
