module Shapes
  class Shape
    attr_reader :name

    def initialize(name)
      @name = name
    end

    def area
      0
    end

    def to_s
      format("%s(%.2f)", name, area)
    end
  end

  class Rect < Shape
    def initialize(w, h)
      super("rect")
      @w = w
      @h = h
    end

    def area
      @w * @h
    end
  end

  class Circle < Shape
    def initialize(r)
      super("circle")
      @r = r
    end

    def area
      3.14159 * @r**2
    end
  end
end

module Countable
  def count_up(limit)
    total = 0
    i = 0
    while i < limit
      i += 1
      next if i.even?
      total += i
    end
    total
  end
end

class Ledger
  include Countable
  include Comparable

  attr_accessor :entries

  def initialize(*entries, currency: "EUR", **meta)
    @entries = entries
    @currency = currency
    @meta = meta
  end

  def balance
    @entries.sum
  end

  def <=>(other)
    balance <=> other.balance
  end

  def describe
    tag = @meta[:tag] || "none"
    "#{@currency} #{balance} tag=#{tag} size=#{@entries.size}"
  end

  def each_entry
    return enum_for(:each_entry) unless block_given?

    @entries.each_with_index { |e, i| yield e, i }
  end
end

def classify(value)
  case value
  when Integer then value.negative? ? :negative : :integer
  when Float then :float
  when /\A\d+\z/ then :digits
  when String, Symbol then :text
  when nil then :nothing
  else :other
  end
end

def match_shape(data)
  case data
  in { type: :point, x: Integer => x, y: Integer => y } then "point #{x},#{y}"
  in [first, *rest] then "list #{first} +#{rest.size}"
  in String => s if s.length > 3 then "long #{s}"
  else "unmatched"
  end
end

def retrying(limit)
  attempts = 0
  begin
    attempts += 1
    raise ArgumentError, "try #{attempts}" if attempts < limit

    "ok after #{attempts}"
  rescue ArgumentError => e
    retry if attempts < limit
    "gave up: #{e.message}"
  ensure
    @last_attempts = attempts
  end
end

def divide(a, b)
  [a / b, a % b, a.fdiv(b).round(3), -a / b, a.divmod(-b)]
rescue ZeroDivisionError
  :division_by_zero
end

def fib(n, memo = {})
  return n if n < 2

  memo[n] ||= fib(n - 1, memo) + fib(n - 2, memo)
end

Point = Struct.new(:x, :y) do
  def +(other)
    Point.new(x + other.x, y + other.y)
  end
end

shapes = [Shapes::Rect.new(2, 3), Shapes::Circle.new(1.5)]
puts shapes.map(&:to_s).join(" | ")
puts shapes.sort_by(&:area).map(&:name).inspect

ledger = Ledger.new(10, -4, 7, currency: "USD", tag: "q3")
other = Ledger.new(1, 2)
puts ledger.describe
puts other.describe
puts [ledger > other, ledger.count_up(9), ledger.clamp(other, other) == other].inspect
ledger.each_entry { |e, i| print "#{i}:#{e} " }
puts
puts ledger.each_entry.map { |e, i| e * i }.inspect

puts [1, -2, 2.5, "42", "hi", :sym, nil, [1]].map { |v| classify(v) }.inspect
puts [{ type: :point, x: 1, y: 2 }, [9, 8, 7], "abcdef", "ab", 3].map { |d| match_shape(d) }.inspect
puts retrying(3)
puts retrying(1)
puts divide(7, 2).inspect
puts divide(-7, 2).inspect
puts divide(1, 0).inspect
puts fib(40)

a, (b, c), *d = 1, [2, 3], 4, 5
puts [a, b, c, d].inspect
x = nil
x ||= 5
x += 1
x <<= 2
puts x
counts = Hash.new(0)
"the quick brown the lazy the".split.each { |w| counts[w] += 1 }
puts counts.sort_by { |k, v| [-v, k] }.first(2).inspect
puts (1..10).step(3).to_a.inspect
puts (1...10).select(&:odd?).reduce(:*)
adder = ->(p, q = 10) { p + q }
twice = proc { |f, v| f.call(f.call(v)) }
puts [adder.(1), adder[1, 2], twice.call(->(v) { v * 3 }, 2)].inspect
puts (Point.new(1, 2) + Point.new(3, 4)).to_a.inspect
text = <<~TEXT
  line one
    indented #{1 + 1}
TEXT
puts text.lines.map(&:rstrip).inspect
puts "a-b_c d".tr("-_", "  ").split.map(&:capitalize).join
puts nil&.length.inspect
puts "done" unless ledger.entries.empty?
i = 0
i += 2 until i > 7
puts i
puts [3, 1, 2].sort.reverse.each_slice(2).to_a.inspect
puts({ a: 1, "b" => [2, { c: 3 }] }.to_a.flatten.inspect)
