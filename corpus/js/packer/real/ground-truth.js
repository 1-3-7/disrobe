function greet(name) {
  var prefix = "Hello, ";
  var suffix = "! Welcome aboard.";
  return prefix + name + suffix;
}
function compute(values) {
  var total = 0;
  for (var i = 0; i < values.length; i++) {
    total = total + values[i] * 2;
  }
  return total;
}
var people = ["Alice", "Bob", "Carol"];
var numbers = [3, 7, 11, 13];
var message = greet(people[0]);
var sum = compute(numbers);
console.log(message);
console.log("Sum is " + sum);
