Dim depth, word
depth = 1 + 2
word = Replace("t-h-r-e-e", "-", "")
WScript.Echo "depth", depth, word
MsgBox String(3, "*") & Left(word, 2)
