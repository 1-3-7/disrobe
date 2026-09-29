require "time"

module Deep
  class K
    def self.go = 1
  end
end

def sieve(limit)
  flags = Array.new(limit, true)
  (2...limit).each do |i|
    next unless flags[i]
    (i * i...limit).step(i) { |j| flags[j] = false }
  end
  (2...limit).select { |i| flags[i] }
end

def fib(count)
  a = 0
  b = 1
  out = []
  count.times do
    out << a
    a, b = b, a + b
  end
  out
end

def with_value(x)
  yield(x) if block_given?
end

def parse_year(text)
  Time.parse(text).year if defined?(Time.parse)
rescue StandardError
  nil
end

def probe(o)
  defined?(o.nope) ? :yes : :no
end

s = "x"
p sieve(30), fib(8)
p with_value(3) { |v| v + 1 }, with_value(3)
p parse_year("2024-05-06T00:00:00Z"), parse_year("garbage"), probe(1)
p defined?(Deep::K.go), defined?(Deep::K.nope), defined?(Deep::Missing.go), defined?(String.new)
p defined?(s.upcase.downcase), defined?(s.upcase.nope), defined?(Deep::K), defined?(Deep::Nope), defined?(@x), defined?(puts)
stages = { double: ->(x) { x * 2 }, inc: ->(x) { x + 1 } }
p stages.reduce(3) { |acc, (_name, stage)| stage.call(acc) }
p [[1, [2, 3]], [4, [5, 6]]].map { |a, (b, c)| a + b * c }
p({ a: 1, b: 2 }.map { |(k, v)| "#{k}=#{v}" })
