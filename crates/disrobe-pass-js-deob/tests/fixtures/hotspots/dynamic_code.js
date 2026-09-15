const userInput = globalThis.payload;

eval(userInput); // Noncompliant {{S1523}}
const built = new Function("a", "b", "return a + b"); // Noncompliant {{S1523}}
const made = Function("return 1")(); // Noncompliant {{S1523}}
setTimeout("doWork()", 100); // Noncompliant {{S1523}}
setInterval("tick()", 1000); // Noncompliant {{S1523}}
window.setTimeout("late()", 50); // Noncompliant {{S1523}}
setTimeout("run" + userInput, 10); // Noncompliant {{S1523}}

setTimeout(function () { doWork(); }, 100);
setInterval(() => tick(), 1000);
const parsed = JSON.parse(userInput);
const registry = { eval(value) { return value; } };
registry.eval(userInput);
const passthrough = () => userInput;
