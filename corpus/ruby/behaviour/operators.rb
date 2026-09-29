class Vec
  attr_reader :x, :y
  def initialize(x, y) = (@x, @y = x, y)
  def +(o) = Vec.new(x + o.x, y + o.y)
  def -@ = Vec.new(-x, -y)
  def [](i) = i.zero? ? x : y
  def []=(i, v)
    i.zero? ? @x = v : @y = v
  end
  def ==(o) = o.is_a?(Vec) && x == o.x && y == o.y
  def to_s = "(#{x}, #{y})"
  def to_proc = proc { |k| k * x + y }
  def coerce(n) = [Vec.new(n, n), self]
  protected def secret = x * 1000
  public
  def compare_secret(o) = secret <=> o.secret
  class << self
    def zero = new(0, 0)
    attr_accessor :made
  end
  alias_method :plus, :+
end

Point3 = Data.define(:a, :b, :c) do
  def sum = a + b + c
end

class Ladder
  include Enumerable
  def initialize(n) = @n = n
  def each
    i = 0
    yield i, i * i while (i += 1) <= @n
  end
end

def classify(n)
  case n
  when ..0 then :nonpositive
  when 1...10 then :small
  when 10, 20, 30 then :round
  else :big
  end
end

def unless_else(v)
  unless v.nil?
    "has #{v}"
  else
    "none"
  end
end

def countdown(n)
  out = []
  begin
    out << n
    n -= 1
  end until n.zero?
  out
end

def catcher = catch(:found) { [1, 2, 3].each { |v| throw :found, v * 7 if v == 2 }; :missing }

def block_locals
  y = :outer
  [1, 2].map { |v; y| y = v * 2; y } + [y]
end

def ensure_order
  log = []
  begin
    log << :body
    raise KeyError, "k"
  rescue KeyError => e
    log << e.message
  else
    log << :else
  ensure
    log << :ensure
  end
  log
end

v = Vec.new(1, 2)
v[1] = 5
Vec.made = :yes
p (v + Vec.new(3, 4)).to_s, (-v).to_s, v[0], v[1], v == Vec.new(1, 5), v.plus(v).to_s
p [1, 2].map(&v), v.compare_secret(Vec.new(2, 0)), Vec.zero.to_s, Vec.made
p Point3.new(a: 1, b: 2, c: 3).sum, Point3.new(1, 2, 3).with(c: 9).to_h
p Ladder.new(3).to_a, Ladder.new(4).select { |a, b| b.odd? }
p [-2, 0, 5, 20, 99].map { classify(_1) }, unless_else(nil), unless_else(3)
p countdown(3), catcher, block_locals, ensure_order
p v.send(:x), v.public_send(:y), v.frozen?, v.instance_variable_get(:@y), Integer === 3
