const eventually = await Promise.resolve(42);
const fromTimer = await new Promise((resolve) => setTimeout(() => resolve("late"), 1));
console.log({ eventually, fromTimer });
