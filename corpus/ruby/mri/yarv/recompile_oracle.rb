# Non-circular YARV recompile-equivalence oracle.
#
# Usage: ruby recompile_oracle.rb <original.rb> <recovered.rb>
#
# Measures how faithfully disrobe recovered a `.rb` from its compiled `.yarvc`:
#   1. compile the fixture's OWN committed original `.rb` with the real ruby compiler,
#   2. compile the disrobe-recovered `.rb` with the real ruby compiler,
#   3. diff the opcode multiset of (2) against (1).
# The recovered source is recompiled by ruby itself -- never re-emitted through disrobe's own
# builder -- so the measurement is non-circular: it scores recovery, not encoder/decoder symmetry.
#
# Output (stdout): one line `mode=<whole|partial> matched=<n>/<total> pct=<rate>`.
# Exit status: 0 always (the caller decides pass/fail on the printed rate).

def opcodes(iseq)
  out = []
  walk = lambda do |i|
    i.disasm.each_line { |l| out << $1 if l =~ /^\d{4} (\S+)/ }
    i.each_child { |c| walk.call(c) }
  end
  walk.call(iseq)
  out
end

def multiset_match(want, have)
  hw = Hash.new(0); want.each { |x| hw[x] += 1 }
  hh = Hash.new(0); have.each { |x| hh[x] += 1 }
  inter = 0
  hw.each { |k, v| inter += [v, hh[k]].min }
  inter
end

original_path = ARGV.fetch(0)
recovered_path = ARGV.fetch(1)

original = RubyVM::InstructionSequence.compile(File.read(original_path))
want = opcodes(original)
total = want.size

# Strip the decompiler's annotation comments but PRESERVE Ruby magic comments
# (frozen_string_literal, encoding, etc) -- they are program semantics, not noise,
# and the recovered source legitimately carries them. Recompiling without them would
# wrongly turn recovered frozen literals back into chilled strings.
MAGIC_COMMENT = /\A#\s*(frozen_string_literal|encoding|warn_indent|shareable_constant_value)\s*[:=]/
recovered_source = File.read(recovered_path).lines.reject do |l|
  s = l.lstrip
  s.start_with?("#") && !(s =~ MAGIC_COMMENT)
end.join

begin
  recovered = RubyVM::InstructionSequence.compile(recovered_source)
  have = opcodes(recovered)
  matched = multiset_match(want, have)
  pct = total > 0 ? (100 * matched / total) : 0
  puts "mode=whole matched=#{matched}/#{total} pct=#{pct}"
rescue SyntaxError, StandardError
  # Recovered source did not parse as one unit: score each top-level def/class/module/statement
  # independently so a single unrecoverable construct does not zero the rest.
  units = []
  lines = recovered_source.lines
  i = 0
  while i < lines.size
    if lines[i] =~ /^(def |class |module )/
      block = [lines[i]]
      j = i + 1
      while j < lines.size
        block << lines[j]
        if lines[j] =~ /^end\b/
          i = j
          break
        end
        j += 1
      end
      units << block.join
      i = j + 1
    else
      units << lines[i]
      i += 1
    end
  end
  have = []
  units.each do |unit|
    begin
      have.concat(opcodes(RubyVM::InstructionSequence.compile(unit)))
    rescue SyntaxError, StandardError
      next
    end
  end
  matched = multiset_match(want, have)
  pct = total > 0 ? (100 * matched / total) : 0
  puts "mode=partial matched=#{matched}/#{total} pct=#{pct}"
end
