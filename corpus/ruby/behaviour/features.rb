module Shout
  refine String do
    def shout = upcase + "!"
  end
end
using Shout

class Config
  def initialize = @values = {}
  def method_missing(name, *args)
    key = name.to_s
    if key.end_with?("=")
      @values[key.chomp("=").to_sym] = args.first
    elsif @values.key?(name)
      @values[name]
    else
      super
    end
  end
  def respond_to_missing?(name, include_private = false) = @values.key?(name.to_s.chomp("=").to_sym) || super
end

def pinned(value, expected)
  case value
  in ^expected then :same
  in Integer | Float => n if n > expected then :bigger
  else :other
  end
end

def retrying(limit)
  attempts = 0
  begin
    attempts += 1
    raise ArgumentError, "try #{attempts}" if attempts < limit
    "ok after #{attempts}"
  rescue ArgumentError
    retry if attempts < limit
    "gave up"
  ensure
    attempts += 100
  end
end

def safe_lengths(items) = items.map { it&.length }

def memo(h, key)
  h[key] ||= key.to_s * 2
  h[key] &&= h[key].upcase
  h
end

def lazy_evens = (1..Float::INFINITY).lazy.select(&:even?).map { _1 * 3 }.first(4)

def fiber_counts
  f = Fiber.new do
    3.times { |i| Fiber.yield i * 10 }
    :done
  end
  4.times.map { f.resume }
end

def chained(obj) = obj&.then { |o| o * 2 }

def nested_splat
  a, (b, *c), d = 1, [2, 3, 4], 5
  [a, b, c, d]
end

def each_with_redo
  out = []
  tries = 0
  [1, 2].each do |x|
    tries += 1
    out << [x, tries]
    redo if tries == 1
  end
  out
end

c = Config.new
c.name = "disrobe"
p "hi".shout, c.name, c.respond_to?(:name), (c.nope rescue :no_method)
p pinned(5, 5), pinned(7, 5), pinned("x", 5)
p retrying(3), retrying(1)
p safe_lengths(["ab", nil, "xyz"]), memo({}, :k), lazy_evens, fiber_counts
p chained(4), chained(nil), nested_splat, each_with_redo
p __method__.inspect, [3, 1, 2].sort.then { _1.sum }, 5.clamp(1, 3)
