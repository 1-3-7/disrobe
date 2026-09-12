def classify(x)
  case x
  when Integer
    "int"
  else
    "other"
  end
end
