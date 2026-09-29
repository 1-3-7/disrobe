defmodule Operators do
  import Bitwise

  def strict(a, b), do: a === b
  def loose(a, b), do: a == b
  def strict_not(a, b), do: a !== b
  def masked(a, b), do: (a &&& b) + 1
  def shifted(a), do: (a <<< 2) + 1
  def mixed(a, b), do: bxor(a, b) * 2
  def quotient(a, b), do: {div(a, b), rem(a, b)}
  def left_minus(a, b, c), do: (a -- b) -- c
  def right_minus(a, b, c), do: a -- (b -- c)
  def negate(a), do: -(-a)
  def ordered(a, b), do: (a == b) < true

  def test do
    [
      strict(1, 1.0),
      loose(1, 1.0),
      strict_not(1, 1.0),
      masked(6, 3),
      shifted(3),
      mixed(6, 3),
      quotient(-7, 2),
      left_minus([1, 2, 3, 1], [1], [1]),
      right_minus([1, 2, 3, 1], [1, 2], [2]),
      negate(5),
      ordered(1, 2)
    ]
  end
end
