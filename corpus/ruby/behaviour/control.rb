class ValidationError < StandardError
  def initialize(field)
    super("invalid #{field}")
    @field = field
  end

  attr_reader :field
end

class Counter
  @@instances = 0
  LIMIT = 3

  class << self
    def build(start = 0) = new(start)

    def instances = @@instances
  end

  attr_accessor :value

  def initialize(start)
    @@instances += 1
    @value = start
    @log = nil
  end

  def bump(by: 1)
    self.value += by
    (@log ||= []) << by
    self
  end

  def history = @log.to_a

  def method_missing(name, *args)
    if name.to_s.start_with?("times_")
      value * name.to_s.delete_prefix("times_").to_i
    else
      super
    end
  end

  def respond_to_missing?(name, include_private = false)
    name.to_s.start_with?("times_") || super
  end
end

class Base
  def greet(name, punct: "!")
    "hello #{name}#{punct}"
  end
end

class Child < Base
  def greet(name, punct: "?")
    super.upcase
  end
end

def collatz(n)
  steps = 0
  until n == 1
    n = n.even? ? n / 2 : 3 * n + 1
    steps += 1
  end
  steps
end

def first_square_over(limit)
  i = 0
  loop do
    i += 1
    break i * i if i * i > limit
  end
end

def evens_until(list, stop)
  out = []
  list.each do |x|
    next if x.odd?
    break if x == stop

    out << x
  end
  out
end

def find_pair(nums, target)
  catch(:found) do
    nums.each_with_index do |a, i|
      nums.each_with_index do |b, j|
        throw :found, [i, j] if i < j && a + b == target
      end
    end
    nil
  end
end

def safe_div(a, b)
  raise ValidationError, :b if b.zero?

  a / b
rescue ValidationError => e
  "#{e.class}: #{e.message} (#{e.field})"
else
  "ok"
ensure
  $audit = (($audit || 0) + 1)
end

def forward(*args, **opts, &blk) = collect(*args, **opts, &blk)

def collect(*args, **opts)
  block_given? ? yield(args, opts) : [args, opts]
end

def pairs(hash)
  hash.each_with_index.map { |(k, v), i| "#{i}#{k}#{v}" }.join(",")
end

def numbered(list) = list.map { _1 * 2 }.sum + list.map { it + 1 }.sum

def spread(first, *middle, last) = [first, middle, last]

c = Counter.build(5).bump.bump(by: 3)
puts [c.value, c.history, c.times_4, c.respond_to?(:times_9), Counter.instances, Counter::LIMIT].inspect
begin
  c.nope
rescue NoMethodError => e
  puts "missing: #{e.name}"
end
puts Child.new.greet("ann")
puts [collatz(27), first_square_over(50), evens_until([2, 3, 4, 6, 8, 10], 8)].inspect
puts find_pair([3, 9, 4, 7], 11).inspect
puts safe_div(10, 2).inspect
puts safe_div(1, 0)
puts $audit
puts forward(1, 2, k: 3) { |a, o| a.sum + o[:k] }
puts forward(:x).inspect
puts pairs({ a: 1, b: 2 })
puts numbered([1, 2, 3])
puts spread(1, 2, 3, 4).inspect
first, *rest = [9, 8, 7]
*init, tail = [1, 2, 3]
puts [first, rest, init, tail].inspect
total = 0
for i in 1..4
  total += i
end
puts total
n = 0
begin
  n += 1
end while n < 3
puts n
puts [1, 2, 3].sum { |x| x.odd? && x > 1 ? x : 0 }
puts defined?(zzz).inspect
puts defined?(puts)
puts [:a, "b", 3].map { |v| v.is_a?(Symbol) || v.is_a?(String) ? v.to_s : v }.inspect
puts %w[x y z].each_with_object({}) { |s, h| h[s] = s.ord }.inspect
puts [4, 5].method(:sum).call
puts [1, 2].map(&method(:Integer)).inspect
puts format("%05.1f|%-4s|%x", 3.14159, "ab", 255)
puts "a,b;c".split(/[,;]/).inspect
puts({ x: 1 }.merge(y: 2) { |_k, a, b| a + b }.inspect)
