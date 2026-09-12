# frozen_string_literal: true
# shareable_constant_value: literal

PRIMES = [2, 3, 5, 7].freeze
EMPTY = [].freeze
GREETING = "hello"
FLAGS = [true, false, nil]
CONFIG = { timeout: 30, retries: 3, debug: false }
SPAN = (1..10)
OPEN = (1...10)
BEGINLESS = (..5)
ENDLESS = (1..)

def first_prime = PRIMES.first
def biggest = [4, 8, 15, 16, 23, 42].max
def in_span?(n) = SPAN.cover?(n)
def flags_present = FLAGS.compact
