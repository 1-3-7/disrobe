WORDS = %w[apple Banana cherry date Elder fig].freeze
LOG = <<~LOG
  2026-09-01 INFO  started id=17
  2026-09-01 WARN  slow id=18 ms=250
  2026-09-02 ERROR failed id=19 code=E42
LOG

def title_case(text) = text.split(/[\s_-]+/).map(&:capitalize).join(" ")

def redact(text) = text.gsub(/\d{3,}/) { |digits| "#" * digits.size }

def levels(log)
  log.each_line.filter_map do |line|
    next unless line =~ /(\d{4})-(\d\d)-(\d\d) (\w+)\s+(\w+)(.*)$/

    day, level, verb, rest = $3.to_i, $4.downcase.to_sym, $5, Regexp.last_match(6)
    { day: day, level: level, verb: verb, fields: rest.scan(/(\w+)=(\w+)/).to_h }
  end
end

def histogram(text)
  text.downcase.each_char.reject { |c| c !~ /[a-z]/ }.tally.sort_by { |ch, n| [-n, ch] }.first(3)
end

def caesar(text, shift)
  text.tr("a-zA-Z", ("a".."z").to_a.rotate(shift).join + ("A".."Z").to_a.rotate(shift).join)
end

def wrap(text, width)
  text.split.each_with_object([+""]) do |word, lines|
    if lines.last.empty?
      lines.last << word
    elsif lines.last.size + 1 + word.size <= width
      lines.last << " " << word
    else
      lines << word.dup
    end
  end
end

puts title_case("hello_world-from ruby")
puts redact("call 5551234 or 12 then 0800")
levels(LOG).each { |entry| puts entry.inspect }
puts histogram("Mississippi River").inspect
puts caesar("Hello, World!", 3)
puts caesar(caesar("Round Trip", 5), -5)
puts wrap("the quick brown fox jumps over the lazy dog", 12).inspect
puts WORDS.sort_by(&:downcase).map { |w| w.center(8, ".") }.join("|")
puts WORDS.group_by(&:size).transform_values { |ws| ws.map { _1[0] }.join }.inspect
puts format("%-6s|%6.2f|%+d|%o|%e|%s", "ab", 3.14159, 7, 8, 12_345.678, nil.inspect)
puts "%s has %d items (%.1f%%)" % ["cart", 3, 42.5]
puts "abc".succ, "az".succ, "zz99".succ
puts [1, 2, 3].pack("C*").unpack1("H*"), "hi".unpack("C*").inspect
puts "tab\tsep\\slash \"q\" #{1 + 1} é".inspect
puts 'single #{no} \' quote'
puts :"odd symbol".inspect, :plain.to_proc.call("x") rescue puts "no plain method"
puts "CamelCaseString".gsub(/([a-z])([A-Z])/, '\1_\2').downcase
puts "a1b22c333".scan(/[a-z]\d+/).map { |s| s[1..].to_i }.sum
puts "x" * 3 + "-" + "yz".reverse * 2
puts "line1\nline2\r\nline3".lines(chomp: true).inspect
puts "  padded  ".strip.ljust(10, "*").rjust(12, "<")
puts "encoding: #{"café".encoding} #{"café".bytesize} #{"café".length}"
puts "a,b,,c".split(",", -1).inspect, "a b  c".split.inspect
puts "ruby" <=> "rubx", "Ruby".casecmp?("rUBY"), "abc".start_with?("ab", "x")
