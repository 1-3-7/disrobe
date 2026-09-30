Dim a, b
a = 6
b = a * 7
WScript.Echo "answer", b
MsgBox "quarter " & (b \ 4) & ", rest " & (b - (b \ 4) * 4)
