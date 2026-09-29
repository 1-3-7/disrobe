require "set"

class AppError < StandardError
  def initialize(msg = "app failed") = super
end
class RetryableError < AppError; end

def fetch(attempts)
  tries = 0
  begin
    tries += 1
    raise RetryableError if tries < attempts
    raise AppError, "fatal" if attempts > 5
    [:ok, tries]
  rescue RetryableError => e
    retry if tries < 3
    [:gave_up, e.message, tries]
  rescue AppError => e
    [:fatal, e.message]
  end
end

def one(fail)
  log = []
  result = begin
    log << :body
    raise "x" if fail
    :fine
  rescue => e
    log << e.message
    :rescued
  ensure
    log << :ensure
  end
  [result, log]
end
def two(v)
  @memo = begin
    Integer(v)
  rescue ArgumentError
    -1
  end
  @memo * 2
end

def external_iteration
  e = [1, 2, 3].each
  out = []
  loop { out << e.next * 2 }
  out << e.size
end

def generator
  Enumerator.new do |y|
    a, b = 0, 1
    loop do
      y << a
      a, b = b, a + b
    end
  end.take(8)
end

def set_ops
  s = Set[3, 1, 2]
  t = Set.new([2, 3, 4])
  [(s | t).sort, (s & t).sort, (s - t).to_a, s.subset?(Set[1, 2, 3, 4]), s.include?(2)]
end

def string_bits(text)
  [text.bytesize, text.length, text.reverse, text.encoding.to_s, text.unpack1("U*"),
   text.scan(/[aeiou]/).size, text.tr("a-y", "b-z"), text.center(11, "*"), text.succ, text.ord]
end

def throwing(n)
  catch(:done) do
    n.times do |i|
      n.times do |j|
        throw :done, [i, j] if i * j == 6
      end
    end
    :none
  end
end

def while_modifiers(n)
  total = 0
  total += n while (n -= 1) > 0
  steps = 0
  steps += 1 until steps * steps > 30
  [total, steps]
end

p fetch(2), fetch(9), fetch(6), one(true), one(false), two("21"), two("zz"), external_iteration, generator
p set_ops, string_bits("maze"), throwing(4), throwing(2), while_modifiers(5)
p [AppError.new.message, RetryableError.ancestors.take(3), (raise AppError rescue $!.class)]
