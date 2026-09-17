class Greeter
  def initialize(@name : String)
  end

  def greet : String
    "hello, #{@name}!"
  end

  def fib(n : Int64) : Int64
    n < 2 ? n : fib(n - 1) + fib(n - 2)
  end
end

g = Greeter.new("disrobe")
puts g.greet
puts "fib(10) = #{g.fib(10_i64)}"
