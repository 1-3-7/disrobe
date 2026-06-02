module Tiny
  class Greeter
    def initialize(who)
      @who = who
    end

    def greet
      "hello, #{@who}!"
    end
  end
end

puts Tiny::Greeter.new("world").greet
