module Loud
  def speak = super.upcase + "!"
end

module Polite
  def speak = "please, " + super
end

class Animal
  include Comparable

  attr_reader :name, :legs

  def initialize(name, legs) = (@name, @legs = name, legs)

  def speak = "#{name} makes a sound"

  def <=>(other) = [legs, name] <=> [other.legs, other.name]

  def ==(other) = other.is_a?(Animal) && name == other.name

  alias eql? ==

  def hash = name.hash

  def to_s = "#{self.class.name.downcase}:#{name}"

  protected

  def secret = legs * 7

  public

  def compare_secret(other) = secret <=> other.secret

  private

  def hidden = "hidden #{name}"
end

class Dog < Animal
  prepend Loud

  def speak = "#{name} barks"
end

class Cat < Animal
  include Polite

  def speak = "#{name} meows"
end

module Registry
  module_function

  def register(kind, &factory)
    (@factories ||= {})[kind] = factory
  end

  def build(kind, *args) = @factories.fetch(kind).call(*args)
end

class Animal
  define_method(:describe) { |prefix = "a"| "#{prefix} #{self}" }

  %i[walk run].each_with_index do |verb, i|
    define_method("#{verb}_speed") { legs * (i + 1) }
  end
end

Point3 = Struct.new(:x, :y, :z, keyword_init: true) do
  def norm1 = x.abs + y.abs + z.abs
end

Pair = Data.define(:left, :right) do
  def swap = with(left: right, right: left)
end

Registry.register(:dog) { |n| Dog.new(n, 4) }
Registry.register(:cat) { |n| Cat.new(n, 4) }
Registry.register(:bird) { |n| Animal.new(n, 2) }
zoo = [Registry.build(:dog, "rex"), Registry.build(:cat, "tom"), Registry.build(:bird, "tweety")]
puts zoo.map(&:speak).inspect
puts zoo.sort.map(&:to_s).inspect
puts zoo.minmax.map(&:name).inspect
puts [zoo[0] == Dog.new("rex", 3), zoo.uniq { |a| a.legs }.size, zoo.to_h { |a| [a.name, a.legs] }].inspect
puts [zoo[0].compare_secret(zoo[2]), zoo[1].send(:hidden), zoo[0].respond_to?(:hidden)].inspect
begin
  zoo[0].secret
rescue NoMethodError => e
  puts e.message[/protected method '\w+'/]
end
puts [zoo[2].describe, zoo[1].describe("the"), zoo[0].walk_speed, zoo[2].run_speed].inspect
puts Dog.ancestors.take(3).inspect
p3 = Point3.new(x: 1, y: -2, z: 3)
puts [p3.norm1, p3.to_h, p3 == Point3.new(x: 1, y: -2, z: 3)].inspect
pair = Pair.new(left: 1, right: 2)
puts [pair.swap.left, pair.frozen?, pair.to_h].inspect
counts = zoo.group_by(&:legs).transform_values(&:count)
puts counts.inspect
puts zoo.each_slice(2).map { |slice| slice.map(&:name).join("+") }.inspect
puts (1..10).each_cons(3).count { |a, b, c| a + b + c > 12 }
puts [3, 1, 2].tap { |a| a.push(a.sum) }.then { |a| a.max - a.min }
puts %w[a b c].zip([1, 2, 3], [true, false, nil]).map(&:compact).inspect
puts({ "k" => [1, 2], "j" => [3] }.sum { |_, v| v.size })
puts [[1, "a"], [2, "b"]].each_with_object(Hash.new { |h, k| h[k] = [] }) { |(n, s), acc| acc[n.odd?] << s }.inspect
obj = Object.new
def obj.greet(who = "you") = "hi #{who}"
puts [obj.greet, obj.greet("me"), obj.singleton_methods].inspect
s = +"mutable"
s << "!" unless s.frozen?
sym_result = (:sym.to_proc.call("x") rescue "err")
puts [s, "lit".frozen?, sym_result].inspect
puts __method__.inspect
