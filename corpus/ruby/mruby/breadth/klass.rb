class Counter
  def initialize(start)
    @value = start
  end

  def bump
    @value = @value + 1
  end

  def value
    @value
  end
end

c = Counter.new(10)
c.bump
c.bump
puts c.value
