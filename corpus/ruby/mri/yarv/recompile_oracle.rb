require "digest"
require "json"
require "pathname"
require "rbconfig"

MAGIC_COMMENT = /\A#\s*(frozen_string_literal|encoding|warn_indent|shareable_constant_value)\s*[:=]/

def instruction_stream(iseq)
  disassemblies = []
  opcodes = []
  walk = lambda do |child|
    disassembly = child.disasm
    disassemblies << disassembly
    disassembly.each_line { |line| opcodes << Regexp.last_match(1) if line =~ /^\d{4} (\S+)/ }
    child.each_child { |nested| walk.call(nested) }
  end
  walk.call(iseq)
  [disassemblies.join("\n"), opcodes]
end

def partial_instruction_stream(source)
  units = []
  lines = source.lines
  index = 0
  while index < lines.size
    if lines[index] =~ /^(def |class |module )/
      block = [lines[index]]
      cursor = index + 1
      while cursor < lines.size
        block << lines[cursor]
        if lines[cursor] =~ /^end\b/
          index = cursor
          break
        end
        cursor += 1
      end
      units << block.join
      index = cursor + 1
    else
      units << lines[index]
      index += 1
    end
  end

  disassemblies = []
  opcodes = []
  units.each do |unit|
    begin
      disassembly, names = instruction_stream(RubyVM::InstructionSequence.compile(unit))
      disassemblies << disassembly
      opcodes.concat(names)
    rescue SyntaxError, StandardError
      next
    end
  end
  [disassemblies.join("\n"), opcodes]
end

def counts(stream)
  stream.each_with_object(Hash.new(0)) { |opcode, result| result[opcode] += 1 }
end

def artifact(path)
  {
    "path" => File.expand_path(path),
    "size_bytes" => File.size(path),
    "sha256" => Digest::SHA256.file(path).hexdigest
  }
end

def write_artifact(directory, name, contents)
  path = File.join(directory, name)
  File.binwrite(path, contents)
  artifact(path).merge("name" => name)
end

original_path = ARGV.fetch(0)
recovered_path = ARGV.fetch(1)
fixture_path = ARGV.fetch(2)
rust_harness_path = ARGV.fetch(3)
evidence_dir = Pathname.new(ARGV.fetch(4))
raise ArgumentError, "evidence directory must be absolute" unless evidence_dir.absolute?

Dir.mkdir(evidence_dir)

original_source = File.read(original_path)
recovered_source = File.read(recovered_path)
filtered_recovered_source = recovered_source.lines.reject do |line|
  stripped = line.lstrip
  stripped.start_with?("#") && !(stripped =~ MAGIC_COMMENT)
end.join

original_disassembly, original_opcodes = instruction_stream(
  RubyVM::InstructionSequence.compile(original_source, original_path)
)

begin
  recovered_disassembly, recovered_opcodes = instruction_stream(
    RubyVM::InstructionSequence.compile(filtered_recovered_source, recovered_path)
  )
  mode = "whole"
rescue SyntaxError, StandardError
  recovered_disassembly, recovered_opcodes = partial_instruction_stream(filtered_recovered_source)
  mode = "partial"
end

original_counts = counts(original_opcodes)
recovered_counts = counts(recovered_opcodes)
per_opcode = (original_counts.keys | recovered_counts.keys).sort.map do |opcode|
  original_count = original_counts[opcode]
  recovered_count = recovered_counts[opcode]
  matched_count = [original_count, recovered_count].min
  {
    "opcode" => opcode,
    "original" => original_count,
    "recovered" => recovered_count,
    "matched" => matched_count,
    "deficit" => original_count - matched_count,
    "excess" => recovered_count - matched_count
  }
end

original_total = original_opcodes.size
recovered_total = recovered_opcodes.size
matched_total = per_opcode.sum { |entry| entry.fetch("matched") }
deficit_total = per_opcode.sum { |entry| entry.fetch("deficit") }
excess_total = per_opcode.sum { |entry| entry.fetch("excess") }
pct = original_total.positive? ? (100 * matched_total / original_total) : 0

stored = {
  "original_source" => write_artifact(evidence_dir, "original.rb", original_source),
  "recovered_source" => write_artifact(evidence_dir, "recovered.rb", recovered_source),
  "compiled_recovered_source" => write_artifact(
    evidence_dir,
    "compiled_recovered.rb",
    filtered_recovered_source
  ),
  "original_disassembly" => write_artifact(
    evidence_dir,
    "original.disasm.txt",
    original_disassembly
  ),
  "recovered_disassembly" => write_artifact(
    evidence_dir,
    "recovered.disasm.txt",
    recovered_disassembly
  ),
  "original_opcode_stream" => write_artifact(
    evidence_dir,
    "original.opcodes.txt",
    original_opcodes.empty? ? "" : original_opcodes.join("\n") + "\n"
  ),
  "recovered_opcode_stream" => write_artifact(
    evidence_dir,
    "recovered.opcodes.txt",
    recovered_opcodes.empty? ? "" : recovered_opcodes.join("\n") + "\n"
  )
}

shared_library_name = RbConfig::CONFIG.fetch("LIBRUBY_SO")
shared_library_path = [RbConfig::CONFIG.fetch("bindir"), RbConfig::CONFIG.fetch("libdir")]
  .map { |directory| File.join(directory, shared_library_name) }
  .find { |candidate| File.file?(candidate) }
raise "Ruby shared runtime library #{shared_library_name} was not found" unless shared_library_path

report = {
  "schema" => "disrobe.yarv-opcode-name-multiset-recall.v1",
  "compile_only" => true,
  "metric" => "original opcode-name multiset recall after recompilation",
  "limitations" => [
    "instruction ordering is not compared",
    "instruction operands are not compared",
    "control flow is not compared",
    "extra recovered instructions do not reduce recall"
  ],
  "mode" => mode,
  "runtime" => {
    "version" => RUBY_DESCRIPTION,
    "executable" => artifact(File.realpath(RbConfig.ruby)),
    "shared_library" => artifact(File.realpath(shared_library_path))
  },
  "inputs" => {
    "fixture_source" => artifact(original_path),
    "fixture_ibf" => artifact(fixture_path),
    "ruby_harness" => artifact(File.realpath(__FILE__)),
    "rust_harness" => artifact(rust_harness_path)
  },
  "stored" => stored,
  "per_opcode" => per_opcode,
  "totals" => {
    "original" => original_total,
    "recovered" => recovered_total,
    "matched" => matched_total,
    "deficit" => deficit_total,
    "excess" => excess_total,
    "recall_pct_integer" => pct,
    "recall_pct" => original_total.positive? ? 100.0 * matched_total / original_total : 0.0
  }
}

report_path = File.join(evidence_dir, "report.json")
File.write(report_path, JSON.pretty_generate(report) + "\n")
puts "mode=#{mode} matched=#{matched_total}/#{original_total} pct=#{pct} " \
     "compile_only=true metric=opcode-name-multiset-recall evidence=#{report_path}"
