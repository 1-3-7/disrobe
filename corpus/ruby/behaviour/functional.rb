words = %w[apple banana cherry avocado blueberry cranberry]
syms = %i[a b c]
p words.group_by { _1[0] }, words.tally.size, words.each_slice(2).to_a, words.each_cons(2).count
p words.partition { it.length > 6 }, words.min_by(&:length), words.sort_by { -it.length }.first(2)
p words.each_with_object(Hash.new(0)) { |w, h| h[w[0]] += w.length }, [1, 2, 3].inject(:+), (1..4).sum { _1 * _1 }
p [1, 2].zip([3, 4], [5, 6]), [[1, 2], [3]].flat_map { |a| a.map { _1 * 10 } }, syms.map(&:to_s)

add = ->(a, b) { a + b }
inc = add.curry[1]
double = proc { |x| x * 2 }
pipeline = inc >> double
compose = double << inc
p inc.(4), pipeline.call(3), compose.call(3), add.lambda?, double.lambda?, add.arity, double.arity

def opts(a, b = a * 2, *rest, key: :k, **extra, &blk)
  [a, b, rest, key, extra, blk&.call(a)]
end
p opts(1), opts(1, 2, 3, 4, key: :z, w: 5) { _1 + 100 }, opts(*[7, 8], **{key: :q})

m = [3, 1, 2].method(:sort)
p m.call, m.to_proc.call, method(:opts).arity, [1, 2, 3].map(&method(:Integer))

s = +"abc"
s << "def"
t = s.dup.freeze
p s.frozen?, t.frozen?, s.tap { |x| x << "!" }, t, Array.new(3) { |i| i * i }
heredoc = <<~TEXT.lines.map(&:strip)
  first line
    indented #{1 + 1}
  last
TEXT
p heredoc, format("%05.2f|%-4s|%+d", 3.14159, "x", 7), "%s and %p" % ["a", :b]
