require "set"

class Money
  include Comparable
  attr_reader :cents, :currency

  def initialize(cents, currency = :usd)
    @cents = cents
    @currency = currency
  end

  def <=>(other)
    return nil unless other.is_a?(Money) && other.currency == @currency
    @cents <=> other.cents
  end

  def classify(other)
    return :missing if other.nil? || other.cents.zero?
    return :foreign unless other.currency == @currency || other.cents > 500
    return :bigger if (other <=> self) == 1
    :other
  end
end

class Pool
  def initialize(ids)
    @in_use = Set.new(ids)
    @available = []
  end

  def release(conn)
    return unless @in_use.delete?(conn)
    @available << conn
  end

  attr_reader :available
end

class Countdown
  include Enumerable

  def initialize(n) = @n = n

  def each
    return enum_for(:each) unless block_given?
    i = @n
    while i > 0
      yield i
      i -= 1
    end
    self
  end
end

def pick(x)
  return :negative if x < 0
  return if x == 0
  return x * 2 if x.even? && x > 10
  x
end

m = Money.new(300)
p m <=> Money.new(200), m <=> Money.new(200, :eur), m <=> 5
p [nil, Money.new(0), Money.new(10, :eur), Money.new(900, :eur), Money.new(400), Money.new(100)].map { |o| m.classify(o) }
pool = Pool.new([1, 2, 3])
[1, 9, 3, 1].each { |c| pool.release(c) }
p pool.available
p Countdown.new(4).to_a, Countdown.new(3).map { |v| v ** 2 }, Countdown.new(2).each.next
p [-4, 0, 12, 7, 14].map { |x| pick(x) }
p 2 ** 10, (-2) ** 3, 7 <=> 3, Integer === 4, "abc" =~ /c/, 6 ^ 3, 256 >> 4
