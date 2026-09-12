src_path = ARGV.fetch(0)
out_path = ARGV.fetch(1)
iseq = RubyVM::InstructionSequence.compile_file(src_path)
File.binwrite(out_path, iseq.to_binary)
