def opcodes(iseq)
  out = []
  walk = lambda do |i|
    i.disasm.each_line { |l| out << $1 if l =~ /^\d{4} (\S+)/ }
    i.each_child { |c| walk.call(c) }
  end
  walk.call(iseq)
  out
end

original_path = ARGV.fetch(0)
recovered_path = ARGV.fetch(1)

original = RubyVM::InstructionSequence.compile(File.read(original_path))
want = opcodes(original)

MAGIC_COMMENT = /\A#\s*(frozen_string_literal|encoding|warn_indent|shareable_constant_value)\s*[:=]/
recovered_source = File.read(recovered_path).lines.reject do |l|
  s = l.lstrip
  s.start_with?("#") && !(s =~ MAGIC_COMMENT)
end.join
recovered = RubyVM::InstructionSequence.compile(recovered_source)
have = opcodes(recovered)

hw = Hash.new(0); want.each { |x| hw[x] += 1 }
hh = Hash.new(0); have.each { |x| hh[x] += 1 }

keys = (hw.keys | hh.keys).sort
puts "OPCODE                          want  have  delta"
keys.each do |k|
  w = hw[k]; h = hh[k]
  d = h - w
  next if d == 0
  printf("%-30s %5d %5d %+5d\n", k, w, h, d)
end
