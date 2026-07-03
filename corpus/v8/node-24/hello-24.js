process.stdout.write("hello ");
function greet(name) {
  const msg = "hello " + name;
  process.stdout.write(msg);
  return msg.length;
}
const PI = 3.14159;
let total = 0;
for (let i = 0; i < 10; i++) { total = total + i; }
greet("world");