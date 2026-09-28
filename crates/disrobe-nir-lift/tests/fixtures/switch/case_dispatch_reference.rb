def label_position(label)
  Integer(label.to_s.delete_prefix("label_"))
end

def child_iseq?(value)
  value.is_a?(Array) && value[0] == "YARVInstructionSequence/SimpleDataFormat"
end

def walk(iseq, rows)
  iseq[12].each do |entry|
    walk(entry[1], rows) if child_iseq?(entry[1])
  end
  position = 0
  iseq[13].each do |element|
    case element
    when Symbol
      if element.to_s.start_with?("label_") && label_position(element) != position
        raise "#{element} is not at slot #{position}"
      end
    when Array
      if element[0] == :opt_case_dispatch
        targets = element[1].each_slice(2).map { |_key, label| label_position(label) }
        targets << label_position(element[2])
        targets << position + element.length
        rows << [position, targets.uniq.sort]
      end
      element.each { |operand| walk(operand, rows) if child_iseq?(operand) }
      position += element.length
    end
  end
end

rows = []
walk(RubyVM::InstructionSequence.compile_file(ARGV.fetch(0)).to_a, rows)
rows.sort.each { |position, targets| puts "#{position}: #{targets.join(' ')}" }
