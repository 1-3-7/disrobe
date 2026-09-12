const std = @import("std");

fn fib(n: u64) u64 {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

fn greet(writer: anytype, name: []const u8) !void {
    try writer.print("hello, {s}!\n", .{name});
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try greet(stdout, "disrobe");
    try stdout.print("fib(10) = {d}\n", .{fib(10)});
}
