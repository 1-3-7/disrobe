Dim greeting, target
target = "World"
greeting = "Hello, " & target & Chr(33)
WScript.Echo greeting, Len(greeting)
MsgBox UCase(target) & " said ""hi"""
