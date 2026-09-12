#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'

module Tiny
  class Greeter
    def initialize(who)
      @who = who
    end

    def greet
      "hello, #{@who}!"
    end
  end
end

puts Tiny::Greeter.new('world').greet
