function add(a, b) {
    return a + b;
}

function subtract(a, b) {
    return a - b;
}

function multiply(a, b) {
    return a * b;
}

function divide(a, b) {
    if (b === 0) {
        throw new Error("divide by zero");
    }
    return a / b;
}

function calculate(op, x, y) {
    switch (op) {
        case "add":
            return add(x, y);
        case "sub":
            return subtract(x, y);
        case "mul":
            return multiply(x, y);
        case "div":
            return divide(x, y);
        default:
            throw new Error("unknown op: " + op);
    }
}

function greet(name) {
    const banner = "calculator ready";
    return banner + " :: hello, " + name;
}

function runSamples() {
    const cases = [
        ["add", 10, 5],
        ["sub", 10, 5],
        ["mul", 10, 5],
        ["div", 10, 5],
    ];
    const out = [];
    for (const [op, x, y] of cases) {
        out.push(op + "(" + x + "," + y + ") = " + calculate(op, x, y));
    }
    return out;
}

console.log(greet("disrobe"));
runSamples().forEach((line) => console.log(line));
