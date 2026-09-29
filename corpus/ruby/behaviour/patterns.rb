Point = Struct.new(:x, :y)

def shape(v)
  case v
  in {} | nil
    :empty
  in Integer | Float
    :number
  in Point[x, y] if x == y
    [:diagonal, x]
  in [*, 42, *]
    :holds_answer
  in [Integer => head, String, *rest]
    [:tagged, head, rest]
  in [0, nil, :s, 1..3]
    :literals
  in [[x, y], {k:}]
    [:nested, x, y, k]
  in [[[deep]], [first, *], {c: [inner]}]
    [:deeper, deep, first, inner]
  in [Integer, *] | [_, String]
    :mixed
  in {x: Integer} | {y: nil}
    :keyed
  in [a, *_]
    [:first, a]
  else
    :other
  end
end

samples = [
  nil, {}, 1, 2.5, [7, 42, 9], [1, "s", 2, 3], [0, nil, :s, 2],
  [[1, 2], {k: 3}], [[[4]], [5, 6], {c: [7]}], [8, :z], [:q, "t"],
  {x: 1}, {y: nil}, Point.new(3, 3), [:w], "text"
]
samples.each { |s| puts "#{s.inspect} -> #{shape(s).inspect}" }
