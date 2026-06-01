# frozen_string_literal: true
# encoding: utf-8
# warn_indent: false
# shareable_constant_value: literal

BEGIN {
  $loaded_at = Time.now.to_i
}

END {
  $finished_at = Time.now.to_i
}

require 'json'
require 'set'
require 'forwardable'
require 'singleton'
require 'observer'

module EdgeCases
  VERSION = '3.4.0'
  CONFIG = { timeout: 30, retries: 3, debug: false }
  PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31].freeze
  EMPTY = [].freeze
  GREETING = 'hello'.freeze

  module Comparable
  end

  module Inner
    INNER_CONST = :inner_value
    def self.echo(x); x; end
  end

  class Error < StandardError
    def initialize(msg = 'edge-case error', code: nil)
      super(msg)
      @code = code
    end
    attr_reader :code
  end

  class TimeoutError < Error; end
  class RetryError < Error; end

  class Greeter
    attr_accessor :name, :tone
    attr_reader :created_at

    def initialize(name = 'world', tone: :friendly, **extra)
      @name = name
      @tone = tone
      @extra = extra
      @created_at = Time.now
      freeze if extra[:freeze]
    end

    def greet(prefix = 'hello', suffix: '!', upcase: false)
      msg = "#{prefix}, #{@name}#{suffix}"
      upcase ? msg.upcase : msg
    end

    def greet_endless(prefix = 'hi') = "#{prefix}, #{@name}"

    def with_block
      yield(@name) if block_given?
    end

    def with_explicit_block(&blk)
      blk.call(@name) if blk
    end

    def variadic(*args, **kwargs, &blk)
      [args, kwargs, blk]
    end

    def forward_all(...)
      Inner.echo(...)
    end

    def self.factory(count, **opts)
      Array.new(count) { |i| new("guest_#{i}", **opts) }
    end

    def to_s = "<Greeter name=#{@name.inspect} tone=#{@tone.inspect}>"
    def inspect = to_s
    def ==(other) = other.is_a?(Greeter) && other.name == @name
    alias_method :eql?, :==
    def hash = @name.hash
  end

  class FancyGreeter < Greeter
    def initialize(name = 'world', flair: '*', **rest)
      super(name, **rest)
      @flair = flair
    end

    def greet(prefix = 'hello', **opts)
      base = super(prefix, **opts)
      "#{@flair}#{base}#{@flair}"
    end
  end

  module Mixin
    def shout(text)
      "#{text.upcase}!"
    end

    def whisper(text)
      "(#{text.downcase})"
    end
  end

  module Prepended
    def greet(*)
      "[prepended] #{super}"
    end
  end

  class MixedGreeter < Greeter
    include Mixin
    prepend Prepended

    def greet(*args, **opts)
      shout(super)
    end
  end

  Point = Struct.new(:x, :y) do
    def magnitude
      Math.hypot(x, y)
    end

    def +(other)
      Point.new(x + other.x, y + other.y)
    end

    def to_s = "(#{x},#{y})"
  end

  Color = Data.define(:r, :g, :b) do
    def to_hex
      format('#%02x%02x%02x', r, g, b)
    end

    def luma = 0.299 * r + 0.587 * g + 0.114 * b
  end

  class LazySeq
    include Enumerable

    def initialize(seed = 0)
      @seed = seed
    end

    def each
      return enum_for(:each) unless block_given?
      i = @seed
      loop do
        yield i
        i += 1
      end
    end
  end

  class Registry
    include Singleton

    def initialize
      @items = {}
    end

    def register(key, value)
      @items[key] = value
      self
    end

    def fetch(key, default = nil)
      @items.fetch(key, default)
    end

    def keys = @items.keys.sort
  end

  class EventBus
    include Observable

    def emit(payload)
      changed
      notify_observers(payload)
    end
  end

  class CommandBag
    extend Forwardable
    def_delegators :@store, :size, :empty?, :clear, :each

    def initialize
      @store = []
    end

    def <<(cmd)
      @store << cmd
      self
    end
  end

  class MetaThing
    def initialize
      @attrs = {}
    end

    def method_missing(name, *args, **kwargs, &blk)
      str = name.to_s
      if str.end_with?('=')
        @attrs[str.chomp('=').to_sym] = args.first
      elsif @attrs.key?(name)
        @attrs[name]
      else
        super
      end
    end

    def respond_to_missing?(name, include_private = false)
      true
    end

    class << self
      def define_accessor(sym)
        define_method(sym) { @attrs[sym] }
        define_method("#{sym}=") { |v| @attrs[sym] = v }
      end
    end

    define_accessor :pinned
  end

  module Refined
    refine String do
      def shout = "#{upcase}!"
      def emphasis(count = 1) = "#{self}#{'!' * count}"
    end

    refine Integer do
      def doubled = self * 2
      def triangle = (self * (self + 1)) / 2
    end
  end

  module Patterns
    module_function

    def classify(value)
      case value
      in Integer => n if n.negative?
        :negative_integer
      in 0
        :zero
      in Integer => n if n.positive?
        :positive_integer
      in Float => f if f.nan?
        :nan
      in Float
        :float
      in String => s if s.empty?
        :empty_string
      in String
        :string
      in []
        :empty_array
      in [first, *rest]
        [:array, first, rest.length]
      in {} | nil
        :empty_or_nil
      in { type: String => t, payload: }
        [:tagged, t, payload]
      in Symbol
        :symbol
      in ->(x) { x.respond_to?(:to_proc) }
        :proc_like
      else
        :unknown
      end
    end

    def deconstruct_point(pt)
      case pt
      in Point(x:, y:) if x == y
        :diagonal
      in Point(x: 0, y:)
        [:on_y, y]
      in Point(x:, y: 0)
        [:on_x, x]
      in Point => p
        [:generic, p.magnitude]
      end
    end

    def find_pattern(arr)
      case arr
      in [*, 42, *]
        :contains_42
      in [first, second, *_]
        [:pair, first, second]
      else
        :other
      end
    end
  end

  module Numerics
    module_function

    def doubled(arr)
      arr.map(&:to_i).map { |n| n * 2 }
    end

    def sum_via_each(arr)
      total = 0
      arr.each { |n| total += n }
      total
    end

    def sum_via_inject(arr)
      arr.inject(0, :+)
    end

    def lazy_squares(limit)
      (1..Float::INFINITY).lazy.map { |i| i * i }.first(limit)
    end

    def primes_under(limit)
      sieve = Array.new(limit, true)
      sieve[0] = sieve[1] = false
      (2...limit).each do |i|
        next unless sieve[i]
        (i*i...limit).step(i) { |j| sieve[j] = false }
      end
      (0...limit).select { |i| sieve[i] }
    end

    def safe_divide(a, b)
      a / b
    rescue ZeroDivisionError => e
      0
    end

    def chained_rescue(input)
      Integer(input)
    rescue ArgumentError, TypeError
      -1
    end

    def with_ensure(io)
      data = io.read
      data.length
    ensure
      io.close if io.respond_to?(:close)
    end

    def with_retry(max = 3)
      tries = 0
      begin
        tries += 1
        raise RetryError if tries < 2
        :ok
      rescue RetryError
        retry if tries < max
        :failed
      end
    end

    def fib(n) = n < 2 ? n : fib(n - 1) + fib(n - 2)

    def collatz_length(n)
      count = 0
      while n > 1
        n = n.even? ? n / 2 : 3 * n + 1
        count += 1
        break if count > 10_000
      end
      count
    end
  end

  module Strings
    module_function

    def interp(name, count)
      "name=#{name.inspect} count=#{count + 1} squared=#{count ** 2}"
    end

    def heredoc_plain
      <<~HEREDOC
        line one
        line two
        end of input
      HEREDOC
    end

    def heredoc_with_interp(name)
      <<~MSG
        hello,
        time=
      MSG
    end

    def multiline_string
      "first" \
      " second" \
      " third"
    end

    def percent_literals
      arr = %w[red green blue]
      sym = %i[a b c]
      cmd = %q(echo hi)
      reg = %r{^/api/v\d+/}
      [arr, sym, cmd, reg]
    end

    def gsub_block(text)
      text.gsub(/\w+/) { |w| w.capitalize }
    end

    def safe_navigation(obj)
      obj&.value&.to_s&.strip
    end

    def conditional_assign(h)
      h[:cache] ||= {}
      h[:nested] &&= h[:nested].dup
      h
    end
  end

  module Hashes
    module_function

    def short_syntax
      a = 1
      b = 2
      c = 3
      { a:, b:, c: }
    end

    def transform(h)
      h.transform_keys(&:to_sym).transform_values { |v| v.to_s }
    end

    def merge_with_block(a, b)
      a.merge(b) { |_key, v1, v2| v1 + v2 }
    end

    def deep_dig(h, *path)
      h.dig(*path)
    end

    def slice_and_except(h)
      [h.slice(:a, :b), h.except(:a)]
    end
  end

  module BlocksAndProcs
    module_function

    def map_with_symbol(arr)
      arr.map(&:to_s)
    end

    def map_with_proc(arr, fn)
      arr.map(&fn)
    end

    def returning_lambda
      ->(x, y) { x + y }
    end

    def returning_proc
      Proc.new { |x, y| x + y }
    end

    def curry_example
      add = ->(a, b, c) { a + b + c }
      add.curry[1][2][3]
    end

    def yielding(arr)
      arr.each_with_index do |item, idx|
        yield(item, idx) if block_given?
      end
    end

    def explicit_block(&blk)
      blk.call(1, 2)
    end

    def callable_returns
      [
        method(:map_with_symbol),
        method(:map_with_symbol).to_proc,
        method(:map_with_symbol).unbind
      ]
    end
  end

  module Splats
    module_function

    def explode(*args, **opts)
      [args, opts]
    end

    def forward(*args, **opts, &blk)
      explode(*args, **opts, &blk)
    end

    def deep_destructure((a, (b, c)), *rest)
      [a, b, c, rest]
    end

    def kwargs_passthrough(**opts)
      [:wrapped, opts]
    end

    def required_kw(name:, age: 0, **rest)
      [name, age, rest]
    end
  end

  module Ranges
    module_function

    def beginless = ..5
    def endless = 5..
    def both = 1..10

    def cover_check
      (1..10).cover?(5)
    end

    def step_range
      (1..20).step(3).to_a
    end

    def char_range
      ('a'..'e').to_a
    end
  end

  module Enumerables
    module_function

    def grouped(arr)
      arr.group_by { |x| x % 3 }
    end

    def partitioned(arr)
      arr.partition(&:even?)
    end

    def zipped(a, b)
      a.zip(b)
    end

    def chunk_while(arr)
      arr.chunk_while { |a, b| b - a == 1 }.to_a
    end

    def each_cons(arr)
      arr.each_cons(2).to_a
    end

    def flat_map(arr)
      arr.flat_map { |x| [x, x * 2] }
    end

    def filter_map(arr)
      arr.filter_map { |x| x * 2 if x.positive? }
    end

    def tally(arr)
      arr.tally
    end

    def reduce_with_initial(arr)
      arr.reduce(0) { |acc, n| acc + n }
    end
  end

  module Threading
    module_function

    def with_mutex
      mutex = Thread::Mutex.new
      counter = 0
      threads = Array.new(4) do
        Thread.new do
          mutex.synchronize { counter += 1 }
        end
      end
      threads.each(&:join)
      counter
    end

    def with_queue
      q = Thread::Queue.new
      producer = Thread.new do
        5.times { |i| q << i }
        q.close
      end
      consumed = []
      until q.closed? && q.empty?
        begin
          consumed << q.pop(timeout: 0.05)
        rescue ThreadError
          break
        end
      end
      producer.join
      consumed
    end

    def with_fiber
      fib = Fiber.new do
        a = 0
        b = 1
        loop do
          Fiber.yield(a)
          a, b = b, a + b
        end
      end
      Array.new(10) { fib.resume }
    end

    def scheduler_available?
      Fiber.respond_to?(:scheduler) && !Fiber.scheduler.nil?
    end
  end

  module Concurrency
    module_function

    def ractor_aware?
      defined?(Ractor) ? true : false
    end

    def run_ractor
      return :unavailable unless defined?(Ractor)
      r = Ractor.new do
        sum = 0
        10.times { |i| sum += i }
        sum
      end
      r.take
    end
  end

  module ObjectSpaceUse
    module_function

    def count_strings
      ObjectSpace.each_object(String).count
    end

    def gc_stats
      GC.stat.slice(:count, :heap_allocated_pages)
    end
  end

  module Reflection
    module_function

    def class_eval_method(klass, name, body)
      klass.class_eval do
        define_method(name) { body }
      end
    end

    def instance_eval_thing(obj)
      obj.instance_eval { @internal_state }
    end

    def singleton_methods_for(obj)
      obj.singleton_class.instance_methods(false)
    end

    def method_object
      m = Greeter.instance_method(:greet)
      g = Greeter.new('claude')
      bound = m.bind(g)
      bound.call
    end

    def constants_under
      EdgeCases.constants.sort
    end

    def ancestors_of
      FancyGreeter.ancestors.map(&:to_s)
    end
  end

  module Conversions
    module_function

    def to_int_safely(x)
      Integer(x, exception: false)
    end

    def to_float_safely(x)
      Float(x, exception: false)
    end

    def parse_json(text)
      JSON.parse(text, symbolize_names: true)
    rescue JSON::ParserError
      nil
    end

    def dump_json(obj)
      JSON.dump(obj)
    end
  end

  module Files
    module_function

    def with_tempfile(content)
      require 'tempfile'
      Tempfile.create('edge') do |f|
        f.write(content)
        f.flush
        File.read(f.path)
      end
    end

    def expand_paths
      [
        __FILE__,
        __dir__,
        File.expand_path('.'),
        File.join('a', 'b', 'c')
      ]
    end

    def glob_demo
      Dir.glob('*.rb').sort
    end
  end

  module Encoding
    module_function

    def unicode_demo
      str = "café \u{1F600} ÿ"
      [str.encoding.to_s, str.bytesize, str.length]
    end

    def force_encoding
      raw = "\xFF\xFE\x68\x00".dup
      raw.force_encoding('UTF-16LE').encode('UTF-8', invalid: :replace, undef: :replace)
    end
  end

  module Symbols
    module_function

    def symbol_proc
      [1, 2, 3].map(&:to_s).map(&:upcase)
    end

    def all_symbols
      [:foo, :bar, :"with spaces", :"with-dash", :+, :<<]
    end

    def comparison
      :a <=> :b
    end
  end

  module Operators
    module_function

    def spaceship(a, b) = a <=> b

    def safe_or(a, b)
      a || b
    end

    def safe_and(a, b)
      a && b
    end

    def double_bang(x)
      !!x
    end

    def bitops(a, b)
      [a & b, a | b, a ^ b, ~a, a << 1, a >> 1]
    end

    def power(a, b) = a ** b
  end

  module ControlFlow
    module_function

    def case_when(x)
      case x
      when Integer then :int
      when Float then :float
      when String then :str
      when /\Aregex/ then :rx
      when (1..10) then :small_range
      when ->(v) { v.respond_to?(:to_proc) } then :callable
      else :other
      end
    end

    def loop_with_break
      i = 0
      loop do
        i += 1
        break if i > 5
      end
      i
    end

    def until_loop(n)
      i = 0
      until i >= n
        i += 1
      end
      i
    end

    def while_modifier(arr)
      arr.pop while arr.size > 2
      arr
    end

    def if_modifier(x)
      :positive if x.positive?
    end

    def unless_modifier(x)
      :nonzero unless x.zero?
    end

    def ternary(x)
      x.positive? ? :pos : :nonpos
    end

    def next_redo
      sum = 0
      (1..10).each do |i|
        next if i.even?
        sum += i
      end
      sum
    end
  end

  class Comparable
    include ::Comparable

    attr_reader :value

    def initialize(value)
      @value = value
    end

    def <=>(other)
      @value <=> other.value
    end
  end

  class Enumer
    include Enumerable

    def initialize(items)
      @items = items
    end

    def each(&blk)
      @items.each(&blk)
    end
  end

  module ExceptionsPlus
    module_function

    def chain_cause
      raise Error, 'inner'
    rescue Error => e
      raise Error.new('outer'), cause: e
    rescue Error => e
      e.cause&.message
    end

    def raise_with_data
      raise Error.new('boom', code: 42)
    rescue Error => e
      [e.message, e.code]
    end

    def begin_rescue_else_ensure
      begin
        :tried
      rescue StandardError
        :rescued
      else
        :no_error
      ensure
        :always
      end
    end
  end

  module ConstantsDance
    A = 1
    B = 2
    FROZEN = [1, 2, 3].freeze
    NESTED = { inner: { value: 42 } }.freeze

    def self.lookup(sym)
      const_get(sym)
    end

    def self.list
      constants.sort
    end
  end

  module Visibility
    class Account
      def initialize(balance)
        @balance = balance
      end

      def deposit(amount)
        @balance += amount
      end

      def balance = @balance

      private

      def secret_audit
        :audited
      end

      protected

      def transfer_to(other, amount)
        other.send(:credit, amount)
        @balance -= amount
      end

      private

      def credit(amount)
        @balance += amount
      end
    end
  end

  module Frozen
    FROZEN_STR = 'immutable'.freeze
    NESTED = [[1, 2], [3, 4]].map(&:freeze).freeze

    def self.try_mutate
      FROZEN_STR.upcase!
    rescue FrozenError => e
      e.message
    end
  end

  def self.run_demo
    g = Greeter.new('claude', tone: :warm)
    fancy = FancyGreeter.new('opus', flair: '~')
    mixed = MixedGreeter.new('sonnet')
    [g.greet, fancy.greet, mixed.greet]
  end

  def self.summary
    {
      version: VERSION,
      primes: PRIMES,
      constants: ConstantsDance.list,
      ancestors: Reflection.ancestors_of,
      patterns: [
        Patterns.classify(0),
        Patterns.classify(3.14),
        Patterns.classify(''),
        Patterns.classify({}),
        Patterns.classify([1, 2, 3]),
        Patterns.classify(:foo)
      ]
    }
  end
end

module EdgeCases
  module DSL
    class Builder
      def initialize(&block)
        @items = []
        @meta = {}
        instance_eval(&block) if block_given?
      end

      def item(name, *tags, **opts, &blk)
        @items << { name: name, tags: tags, opts: opts, block: blk }
        self
      end

      def meta(key, value)
        @meta[key] = value
        self
      end

      def configure
        yield self if block_given?
        self
      end

      def to_h
        { items: @items.map { |it| it.except(:block) }, meta: @meta }
      end
    end

    def self.build(&block)
      Builder.new(&block)
    end
  end

  module ChainableQuery
    class Query
      def initialize(scope: [])
        @scope = scope.dup
      end

      def where(*conds)
        Query.new(scope: @scope + [[:where, conds]])
      end

      def order(field, dir = :asc)
        Query.new(scope: @scope + [[:order, field, dir]])
      end

      def limit(n)
        Query.new(scope: @scope + [[:limit, n]])
      end

      def each(&blk)
        result = simulate
        block_given? ? result.each(&blk) : result.each
      end

      def to_a
        simulate
      end

      private

      def simulate
        @scope.flat_map { |op| Array(op) }
      end
    end
  end

  module AbstractMachines
    class StateMachine
      def initialize(state = :idle)
        @state = state
        @transitions = {}
      end

      def transition(from:, to:, on:)
        (@transitions[on] ||= {})[from] = to
        self
      end

      def fire(event)
        next_state = @transitions.dig(event, @state)
        if next_state
          @state = next_state
          true
        else
          false
        end
      end

      attr_reader :state
    end

    class Pipeline
      def initialize
        @stages = []
      end

      def stage(name, &blk)
        @stages << [name, blk]
        self
      end

      def run(input)
        @stages.reduce(input) do |acc, (_name, stage)|
          stage.call(acc)
        end
      end
    end
  end

  module Numerics
    module_function

    def matrix_multiply(a, b)
      rows_a = a.length
      cols_a = a.first.length
      cols_b = b.first.length
      raise ArgumentError, 'mismatched dims' unless cols_a == b.length
      result = Array.new(rows_a) { Array.new(cols_b, 0) }
      (0...rows_a).each do |i|
        (0...cols_b).each do |j|
          (0...cols_a).each do |k|
            result[i][j] += a[i][k] * b[k][j]
          end
        end
      end
      result
    end

    def quicksort(arr)
      return arr if arr.length <= 1
      pivot = arr.sample
      less, equal, greater = arr.partition { |x| x < pivot }.then { |l, rest| [l, *rest.partition { |x| x == pivot }] }
      quicksort(less) + equal + quicksort(greater)
    end

    def merge_sort(arr)
      return arr if arr.length <= 1
      mid = arr.length / 2
      left = merge_sort(arr[0...mid])
      right = merge_sort(arr[mid..])
      merge(left, right)
    end

    def merge(left, right)
      result = []
      until left.empty? || right.empty?
        result << (left.first <= right.first ? left.shift : right.shift)
      end
      result + left + right
    end

    def binary_search(arr, target)
      low = 0
      high = arr.length - 1
      while low <= high
        mid = (low + high) / 2
        case arr[mid] <=> target
        when 0 then return mid
        when -1 then low = mid + 1
        when 1 then high = mid - 1
        end
      end
      nil
    end

    def gcd(a, b) = b.zero? ? a.abs : gcd(b, a % b)
    def lcm(a, b) = (a * b).abs / gcd(a, b)

    def is_prime?(n)
      return false if n < 2
      return true if n < 4
      return false if n.even?
      i = 3
      while i * i <= n
        return false if (n % i).zero?
        i += 2
      end
      true
    end
  end

  module GraphAlgorithms
    module_function

    def bfs(graph, start)
      visited = Set.new([start])
      queue = [start]
      order = []
      until queue.empty?
        node = queue.shift
        order << node
        graph.fetch(node, []).each do |n|
          unless visited.include?(n)
            visited << n
            queue << n
          end
        end
      end
      order
    end

    def dfs(graph, start, visited: Set.new, order: [])
      return order if visited.include?(start)
      visited << start
      order << start
      graph.fetch(start, []).each { |n| dfs(graph, n, visited:, order:) }
      order
    end

    def topo_sort(graph)
      indeg = Hash.new(0)
      graph.each do |from, tos|
        indeg[from] += 0
        tos.each { |t| indeg[t] += 1 }
      end
      queue = indeg.select { |_k, v| v.zero? }.keys
      order = []
      until queue.empty?
        node = queue.shift
        order << node
        graph.fetch(node, []).each do |n|
          indeg[n] -= 1
          queue << n if indeg[n].zero?
        end
      end
      order
    end
  end

  module Memoized
    def self.included(base)
      base.extend(ClassMethods)
    end

    module ClassMethods
      def memoize(method_name)
        original = instance_method(method_name)
        define_method(method_name) do |*args, **kwargs|
          @__cache ||= {}
          key = [method_name, args, kwargs]
          @__cache[key] ||= original.bind(self).call(*args, **kwargs)
        end
      end
    end
  end

  class Fibonacci
    include Memoized

    def calc(n)
      return n if n < 2
      calc(n - 1) + calc(n - 2)
    end

    memoize :calc
  end

  module Trees
    class Node
      attr_accessor :value, :left, :right

      def initialize(value)
        @value = value
        @left = nil
        @right = nil
      end

      def insert(v)
        if v < @value
          @left.nil? ? @left = Node.new(v) : @left.insert(v)
        else
          @right.nil? ? @right = Node.new(v) : @right.insert(v)
        end
      end

      def in_order(acc = [])
        @left&.in_order(acc)
        acc << @value
        @right&.in_order(acc)
        acc
      end

      def height
        l = @left ? @left.height : 0
        r = @right ? @right.height : 0
        1 + [l, r].max
      end

      def to_h
        h = { value: @value }
        h[:left] = @left.to_h if @left
        h[:right] = @right.to_h if @right
        h
      end
    end

    class BinarySearchTree
      def initialize
        @root = nil
      end

      def insert(v)
        if @root.nil?
          @root = Node.new(v)
        else
          @root.insert(v)
        end
        self
      end

      def to_a
        @root ? @root.in_order : []
      end

      def height = @root ? @root.height : 0
    end
  end

  module TextProcessing
    module_function

    def word_frequency(text)
      text.downcase.scan(/[a-z]+/).tally.sort_by { |_w, c| -c }
    end

    def palindrome?(s)
      clean = s.downcase.gsub(/[^a-z0-9]/, '')
      clean == clean.reverse
    end

    def anagrams?(a, b)
      a.downcase.chars.sort == b.downcase.chars.sort
    end

    def reverse_words(s)
      s.split(/\s+/).reverse.join(' ')
    end

    def caesar(text, shift = 3)
      text.tr('A-Za-z', "#{('A'.ord + shift).chr}-ZA-#{(('A'.ord + shift - 1)).chr}#{('a'.ord + shift).chr}-za-#{(('a'.ord + shift - 1)).chr}")
    end

    def vowel_count(text)
      text.scan(/[aeiouAEIOU]/).length
    end
  end

  module DateTimeStuff
    module_function

    def now_components
      now = Time.now
      {
        year: now.year,
        month: now.month,
        day: now.day,
        hour: now.hour,
        min: now.min,
        sec: now.sec,
        wday: now.wday,
        yday: now.yday,
        utc_offset: now.utc_offset
      }
    end

    def epoch_to_time(epoch)
      Time.at(epoch).utc
    end

    def parse_iso(text)
      Time.parse(text) if defined?(Time.parse)
    rescue StandardError
      nil
    end

    def days_between(a, b)
      ((a - b) / 86_400).to_i
    end
  end

  module Random
    module_function

    def shuffled(arr) = arr.shuffle
    def sample_n(arr, n) = arr.sample(n)
    def coin_flip = [true, false].sample
    def dice_roll(sides = 6) = rand(1..sides)
    def random_string(len = 12)
      chars = ('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a
      Array.new(len) { chars.sample }.join
    end
  end

  module RegexHeavy
    module_function

    def extract_emails(text)
      text.scan(/[\w.+-]+@[\w-]+\.[\w.-]+/)
    end

    def extract_urls(text)
      text.scan(%r{https?://[^\s<>"']+})
    end

    def named_captures(text)
      m = text.match(/(?<area>\d{3})-(?<line>\d{4})/)
      m ? m.named_captures : {}
    end

    def replace_dates(text)
      text.gsub(/\b(\d{4})-(\d{2})-(\d{2})\b/) { "#{$3}/#{$2}/#{$1}" }
    end

    def split_csv_naive(line)
      line.split(/,(?=(?:[^"]*"[^"]*")*[^"]*\z)/)
    end
  end

  module Caching
    class LRU
      def initialize(capacity = 64)
        @capacity = capacity
        @store = {}
      end

      def [](key)
        return nil unless @store.key?(key)
        value = @store.delete(key)
        @store[key] = value
        value
      end

      def []=(key, value)
        @store.delete(key) if @store.key?(key)
        @store[key] = value
        @store.shift while @store.size > @capacity
        value
      end

      def size = @store.size
      def keys = @store.keys.dup
    end
  end

  module Observers
    class EventLog
      def initialize
        @events = []
      end

      def update(event)
        @events << [Time.now.to_f, event]
      end

      def events = @events.dup
    end

    def self.demo
      bus = EventBus.new
      log = EventLog.new
      bus.add_observer(log)
      3.times { |i| bus.emit({ tick: i }) }
      log.events.length
    end
  end

  module SafeNav
    module_function

    def deep_chain(obj)
      obj&.foo&.bar&.baz&.length
    end

    def conditional_call(obj, method_name, *args)
      obj.respond_to?(method_name) ? obj.public_send(method_name, *args) : nil
    end
  end

  module CallableObjects
    class Greeting
      def call(name)
        "hello, #{name}"
      end

      def to_proc
        method(:call).to_proc
      end
    end

    def self.demo
      g = Greeting.new
      [g.call('claude'), [1, 2, 3].map(&g)]
    end
  end

  module IOPatterns
    module_function

    def stringio_round_trip(input)
      require 'stringio'
      io = StringIO.new
      io.write(input)
      io.rewind
      io.read
    end

    def each_line_demo(text)
      lines = []
      text.each_line { |l| lines << l.chomp }
      lines
    end

    def with_open(path)
      File.open(path, 'r') do |io|
        io.read(64)
      end
    end
  end

  module Marshalling
    module_function

    def round_trip(obj)
      Marshal.load(Marshal.dump(obj))
    end

    def json_round_trip(obj)
      JSON.parse(JSON.dump(obj))
    end
  end

  module Coercion
    class Money
      include ::Comparable

      attr_reader :cents

      def initialize(cents)
        @cents = cents.to_i
      end

      def +(other) = Money.new(@cents + coerce_cents(other))
      def -(other) = Money.new(@cents - coerce_cents(other))
      def *(scalar) = Money.new(@cents * scalar.to_i)
      def <=>(other) = @cents <=> coerce_cents(other)

      def coerce(other)
        [Money.new(other), self]
      end

      def to_s = format('$%.2f', @cents / 100.0)

      private

      def coerce_cents(other)
        other.is_a?(Money) ? other.cents : other.to_i
      end
    end
  end

  module BigStuff
    module_function

    def big_array(n = 1000) = (0...n).to_a
    def big_hash(n = 100) = (0...n).to_h { |i| [i.to_s.to_sym, i * i] }
    def deeply_nested(depth = 5)
      depth.times.reduce({ leaf: true }) { |acc, _| { nested: acc } }
    end
  end
end

module EdgeCases
  module FunctionalStyle
    module_function

    def compose(*fns)
      ->(x) { fns.reverse.reduce(x) { |acc, fn| fn.call(acc) } }
    end

    def pipe(*fns)
      ->(x) { fns.reduce(x) { |acc, fn| fn.call(acc) } }
    end

    def memoize_fn(fn)
      cache = {}
      ->(*args) { cache[args] ||= fn.call(*args) }
    end

    def partial(fn, *applied)
      ->(*rest) { fn.call(*applied, *rest) }
    end

    def fixed_point(fn, initial, eps: 1e-9, max: 1000)
      x = initial
      max.times do
        nx = fn.call(x)
        return nx if (nx - x).abs < eps
        x = nx
      end
      x
    end
  end

  module ProtocolDefinitions
    module Drawable
      def draw
        raise NotImplementedError
      end

      def area
        raise NotImplementedError
      end
    end

    class Circle
      include Drawable

      attr_reader :radius

      def initialize(radius)
        @radius = radius
      end

      def draw = "Circle(r=#{@radius})"
      def area = Math::PI * @radius ** 2
      def circumference = 2 * Math::PI * @radius
    end

    class Rectangle
      include Drawable

      def initialize(w, h)
        @w = w
        @h = h
      end

      def draw = "Rect(#{@w}x#{@h})"
      def area = @w * @h
      def perimeter = 2 * (@w + @h)
    end

    class Triangle
      include Drawable

      def initialize(a, b, c)
        @a = a
        @b = b
        @c = c
      end

      def draw = "Tri(#{@a},#{@b},#{@c})"

      def area
        s = perimeter / 2.0
        Math.sqrt(s * (s - @a) * (s - @b) * (s - @c))
      end

      def perimeter = @a + @b + @c
    end
  end

  module ValueObjects
    class Email
      attr_reader :local, :domain

      def initialize(value)
        local, domain = value.to_s.split('@', 2)
        raise ArgumentError, "invalid email: #{value.inspect}" unless local && domain && !domain.empty?
        @local = local
        @domain = domain
        freeze
      end

      def to_s = "#{@local}@#{@domain}"
      def ==(other) = other.is_a?(Email) && other.local == @local && other.domain == @domain
      alias_method :eql?, :==
      def hash = [@local, @domain].hash
    end

    class Money
      include ::Comparable

      ZERO = nil

      attr_reader :cents, :currency

      def initialize(cents, currency = 'USD')
        @cents = cents.to_i
        @currency = currency.to_s.upcase
        freeze
      end

      def +(other)
        ensure_same_currency!(other)
        Money.new(@cents + other.cents, @currency)
      end

      def -(other)
        ensure_same_currency!(other)
        Money.new(@cents - other.cents, @currency)
      end

      def *(scalar) = Money.new((@cents * scalar).to_i, @currency)
      def /(scalar) = Money.new((@cents / scalar).to_i, @currency)

      def <=>(other)
        return nil unless other.is_a?(Money) && other.currency == @currency
        @cents <=> other.cents
      end

      def to_s = format("%s %.2f", @currency, @cents / 100.0)

      def hash = [@cents, @currency].hash

      private

      def ensure_same_currency!(other)
        raise ArgumentError, "currency mismatch" unless other.currency == @currency
      end
    end

    Money.const_set(:ZERO, Money.new(0))
  end

  module SuiteOfMixins
    module Loggable
      def log(level, msg)
        puts "[#{level.upcase}] #{Time.now.iso8601}: #{msg}"
      end
    end

    module Auditable
      def audit_record
        {
          class: self.class.name,
          frozen: frozen?,
          object_id: object_id,
          timestamp: Time.now.to_f
        }
      end
    end

    module Persistable
      def to_storage
        instance_variables.to_h do |iv|
          [iv.to_s.delete_prefix('@').to_sym, instance_variable_get(iv)]
        end
      end

      def self.included(base)
        base.extend(ClassMethods)
      end

      module ClassMethods
        def from_storage(h)
          obj = allocate
          h.each { |k, v| obj.instance_variable_set("@#{k}", v) }
          obj
        end
      end
    end
  end

  module Validators
    class Result
      attr_reader :errors

      def initialize
        @errors = []
      end

      def add(field, message)
        @errors << { field: field, message: message }
        self
      end

      def valid? = @errors.empty?
      def to_h = { valid: valid?, errors: @errors }
    end

    module_function

    def validate_email(value)
      r = Result.new
      r.add(:email, 'missing') if value.nil? || value.to_s.empty?
      r.add(:email, 'invalid format') unless value.to_s.match?(/\A[\w.+-]+@[\w-]+\.[\w.-]+\z/)
      r
    end

    def validate_age(value)
      r = Result.new
      n = Integer(value, exception: false)
      r.add(:age, 'must be integer') if n.nil?
      r.add(:age, 'must be positive') if n && n.negative?
      r.add(:age, 'unrealistic') if n && n > 150
      r
    end

    def combine(*results)
      combined = Result.new
      results.each { |r| r.errors.each { |e| combined.add(e[:field], e[:message]) } }
      combined
    end
  end

  module HTTPLike
    Request = Struct.new(:method, :path, :headers, :body, keyword_init: true)
    Response = Struct.new(:status, :headers, :body, keyword_init: true)

    class Router
      def initialize
        @routes = {}
      end

      def get(path, &handler)
        register(:get, path, handler)
      end

      def post(path, &handler)
        register(:post, path, handler)
      end

      def put(path, &handler)
        register(:put, path, handler)
      end

      def delete(path, &handler)
        register(:delete, path, handler)
      end

      def dispatch(request)
        handler = @routes.dig(request.method, request.path)
        return Response.new(status: 404, headers: {}, body: 'not found') unless handler
        handler.call(request)
      rescue StandardError => e
        Response.new(status: 500, headers: {}, body: e.message)
      end

      private

      def register(method, path, handler)
        (@routes[method] ||= {})[path] = handler
        self
      end
    end

    class Middleware
      def initialize(app, &blk)
        @app = app
        @before = blk
      end

      def call(req)
        @before&.call(req)
        @app.call(req)
      end
    end
  end

  module SerializerKit
    class Json
      def initialize(pretty: false)
        @pretty = pretty
      end

      def dump(obj)
        @pretty ? JSON.pretty_generate(obj) : JSON.dump(obj)
      end

      def load(text)
        JSON.parse(text, symbolize_names: true)
      end
    end

    class Marshalled
      def dump(obj) = Marshal.dump(obj)
      def load(blob) = Marshal.load(blob)
    end

    class CSV
      def dump(rows)
        rows.map { |row| row.map { |c| escape(c) }.join(',') }.join("\n")
      end

      private

      def escape(value)
        text = value.to_s
        text.match?(/[,"\n]/) ? "\"#{text.gsub('"', '""')}\"" : text
      end
    end
  end

  module ScheduledJobs
    class Scheduler
      Job = Struct.new(:at, :payload, :id)

      def initialize
        @jobs = []
        @next_id = 0
      end

      def schedule(at:, payload:)
        @next_id += 1
        job = Job.new(at, payload, @next_id)
        @jobs << job
        @jobs.sort_by!(&:at)
        job.id
      end

      def cancel(id)
        before = @jobs.size
        @jobs.reject! { |j| j.id == id }
        before != @jobs.size
      end

      def due(now)
        @jobs.select { |j| j.at <= now }
      end

      def pop_due!(now)
        ready, future = @jobs.partition { |j| j.at <= now }
        @jobs = future
        ready
      end
    end
  end

  module SimpleORM
    class Model
      def initialize(attrs = {})
        @attrs = attrs.dup
      end

      def [](key) = @attrs[key]

      def []=(key, value)
        @attrs[key] = value
      end

      def update(**changes)
        @attrs.merge!(changes)
        self
      end

      def to_h = @attrs.dup

      def self.create(attrs = {})
        new(attrs).tap(&:after_create)
      end

      def after_create
        nil
      end
    end

    class User < Model
      def email = self[:email]
      def name = self[:name]
      def admin? = !!self[:admin]
      def to_s = "User(#{name})"
    end

    class Post < Model
      def title = self[:title]
      def body = self[:body]
      def published? = !!self[:published]
    end
  end

  module BinaryFormats
    module_function

    def pack_u32_le(values)
      values.pack('V*')
    end

    def unpack_u32_le(bytes)
      bytes.unpack('V*')
    end

    def pack_struct(magic, version, payload)
      [magic, version, payload.bytesize, payload].pack('a4 N N a*')
    end

    def hex_dump(bytes)
      bytes.unpack1('H*').scan(/.{2}/).each_slice(16).map { |row| row.join(' ') }
    end
  end

  module ResourcePools
    class ConnPool
      def initialize(size: 5, &factory)
        @size = size
        @factory = factory
        @available = Array.new(size) { factory.call }
        @in_use = Set.new
      end

      def acquire
        raise 'pool exhausted' if @available.empty?
        conn = @available.shift
        @in_use << conn
        conn
      end

      def release(conn)
        return unless @in_use.delete?(conn)
        @available << conn
      end

      def with
        c = acquire
        yield c
      ensure
        release(c) if c
      end

      def stats
        { size: @size, available: @available.size, in_use: @in_use.size }
      end
    end
  end

  module EventLoops
    class TimerWheel
      def initialize
        @timers = []
      end

      def after(seconds, &blk)
        @timers << { at: Time.now.to_f + seconds, fn: blk }
        self
      end

      def tick
        now = Time.now.to_f
        fired = []
        @timers.reject! do |t|
          if t[:at] <= now
            fired << t[:fn]
            true
          end
        end
        fired.each(&:call)
        fired.size
      end
    end
  end
end

puts EdgeCases.run_demo.inspect
puts EdgeCases.summary.inspect
