import std.stdio;

class Greeter {
    string name;
    this(string name) { this.name = name; }
    string greet() { return "hello, " ~ name ~ "!"; }
    long fib(long n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
}

void main() {
    auto g = new Greeter("disrobe");
    writeln(g.greet());
    writeln("fib(10) = ", g.fib(10));
}
