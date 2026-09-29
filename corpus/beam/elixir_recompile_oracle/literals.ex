defmodule Literals do
  def hash_brace, do: "a\#{b} #x"
  def charlist, do: ~c"c\#{d}"
  def atom, do: :"x\#{y}"
  def controls, do: "\e\0q\\"
  def quoted, do: "say \"hi\"\n"

  def test do
    [hash_brace(), charlist(), atom(), controls(), quoted()]
  end
end
